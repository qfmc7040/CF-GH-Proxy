'use strict'

const CONFIG = {
    PREFIX: '/',
    CACHE_TTL: 604800,
    MAX_CACHE_SIZE: 250 * 1024 * 1024,
    RATE_LIMIT_WINDOW: 30,
    // 只统计回源请求（缓存命中不计数），约 10 req/s/IP。
    RATE_LIMIT_MAX: 300,
    IS_PRODUCTION: true,
    // 置为 false 即回源处理 Range 请求。
    RANGE_CACHE_ENABLED: true,
    // 起点过靠后要丢弃的前缀太多，超过此值改走回源。
    RANGE_CACHE_MAX_SKIP: 32 * 1024 * 1024,
    // 单次切片上限，避免把超大对象读进内存。
    RANGE_CACHE_MAX_BYTES: 64 * 1024 * 1024,
}

const GITHUB_PATTERNS = [
    /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:releases|archive|tags|info|git-)\/.*$/i,
    /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:blob|raw)\/.*$/i,
    /^(?:https?:\/\/)?raw\.(?:githubusercontent|github)\.com\/.+?\/.+?\/.+?\/.+$/i,
    /^(?:https?:\/\/)?gist\.(?:githubusercontent|github)\.com\/.+?\/.+?\/.+$/i,
    /^(?:https?:\/\/)?api\.github\.com\/.*$/i,
    /^(?:https?:\/\/)?codeload\.github\.com\/.+?\/.+?\/(?:tar\.gz|zip|legacy\..*)$/i,
    /^(?:https?:\/\/)?objects\.githubusercontent\.com\/.*$/i,
    /^(?:https?:\/\/)?github\.githubassets\.com\/.*$/i,
    /^(?:https?:\/\/)?(?:copilot|actions)\.githubusercontent\.com\/.*$/i,
    /^(?:https?:\/\/)?release-assets\.githubusercontent\.com\/.*$/i,
    /^(?:https?:\/\/)?github-releases\.githubusercontent\.com\/.*$/i,
]

const SAFE_REDIRECT_HOSTS = new Set([
    'objects.githubusercontent.com', 'github-releases.githubusercontent.com',
    'release-assets.githubusercontent.com', 'raw.githubusercontent.com',
    'gist.githubusercontent.com', 'codeload.github.com',
    'github.githubassets.com', 'copilot.githubusercontent.com',
    'actions.githubusercontent.com',
])

const AZURE_BLOB_SUFFIXES = ['.blob.core.windows.net', '.azureedge.net']

const ALLOWED_HOSTNAMES = [
    'github.com', 'raw.githubusercontent.com', 'raw.github.com',
    'gist.githubusercontent.com', 'gist.github.com', 'api.github.com',
    'codeload.github.com', 'objects.githubusercontent.com',
    'github.githubassets.com', 'copilot.githubusercontent.com',
    'actions.githubusercontent.com',
    'release-assets.githubusercontent.com', 'github-releases.githubusercontent.com',
]

const SECURITY_HEADERS = {
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'x-frame-options': 'DENY',
}

const CORS_HEADERS = {
    'access-control-allow-origin': '*',
    'access-control-expose-headers': '*',
}

const PREFLIGHT_RESP = new Response(null, {
    status: 204,
    headers: { 
        ...CORS_HEADERS, 
        ...SECURITY_HEADERS,
        'access-control-allow-methods': 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS',
        'access-control-allow-headers': 'Content-Type, Authorization, Accept, X-Requested-With, Range',
        'access-control-max-age': '1728000',
    },
})

const IGNORED_QUERY_PARAMS = new Set([
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'ga_source', 'ga_medium', 'ga_campaign',
    'ref',
])

function applyCommonHeaders(headersObj) {
    for (const [k, v] of Object.entries(CORS_HEADERS)) headersObj.set(k, v)
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) headersObj.set(k, v)
    return headersObj
}

function makeRes(body, status = 200, headers = {}) {
    const resHeaders = new Headers(headers)
    applyCommonHeaders(resHeaders)
    return new Response(body, { status, headers: resHeaders })
}

function makeErrorRes(err) {
    console.error('[Worker Error]', err)
    return makeRes(CONFIG.IS_PRODUCTION ? 'Internal Server Error' : (err.stack || err.message), CONFIG.IS_PRODUCTION ? 500 : 502)
}

function newUrl(urlStr) {
    try {
        if (!urlStr.startsWith('http')) urlStr = 'https://' + urlStr
        return new URL(urlStr)
    } catch { return null }
}

// 只解析单段 Range；多段或语法错误返回 null 由调用方回源，起点越界返回 unsatisfiable。
function parseRangeHeader(header, total) {
    if (!header || !Number.isFinite(total) || total <= 0) return null

    const match = /^\s*bytes\s*=\s*(\d*)\s*-\s*(\d*)\s*$/i.exec(header)
    if (!match) return null

    const rawStart = match[1]
    const rawEnd = match[2]
    if (!rawStart && !rawEnd) return null

    if (!rawStart) {
        const suffix = parseInt(rawEnd, 10)
        if (!Number.isFinite(suffix) || suffix <= 0) return null
        const start = Math.max(total - suffix, 0)
        return { start, end: total - 1, length: total - start }
    }

    const start = parseInt(rawStart, 10)
    if (!Number.isFinite(start) || start < 0) return null
    if (start >= total) return { unsatisfiable: true }

    let end = rawEnd ? parseInt(rawEnd, 10) : total - 1
    if (!Number.isFinite(end)) return null
    if (end >= total) end = total - 1
    if (end < start) return null

    return { start, end, length: end - start + 1 }
}

// 边读边丢弃前缀切出 [start, end]，峰值内存只与单个 chunk 相关。
function sliceCachedResponse(cached, range) {
    const reader = cached.body.getReader()
    let offset = 0
    let sent = 0

    return new ReadableStream({
        async pull(controller) {
            try {
                while (sent < range.length) {
                    const { done, value } = await reader.read()
                    if (done) {
                        controller.close()
                        return
                    }

                    const chunkStart = offset
                    offset += value.byteLength

                    if (offset <= range.start) continue

                    const from = Math.max(range.start - chunkStart, 0)
                    const to = Math.min(range.end + 1 - chunkStart, value.byteLength)
                    if (to <= from) continue

                    const piece = value.subarray(from, to)
                    sent += piece.byteLength
                    controller.enqueue(piece)

                    if (sent >= range.length) {
                        controller.close()
                        reader.cancel().catch(() => {})
                        return
                    }
                }
                controller.close()
            } catch (err) {
                controller.error(err)
            }
        },
        cancel(reason) {
            return reader.cancel(reason)
        },
    })
}

// 缓存命中且是完整对象时直接切出 206；返回 null 表示应回源。
function serveRangeFromCache(req, cached, dynamicCors) {
    // 301/302 也会被写进缓存，它们的 body 是空的，不能切片。
    if (cached.status !== 200 || !cached.body) return null
    // 压缩过的字节偏移和客户端语义不一致，宁可回源。
    if (cached.headers.get('content-encoding')) return null

    const totalRaw = cached.headers.get('content-length')
    if (!totalRaw || !/^\d+$/.test(totalRaw)) return null
    const total = parseInt(totalRaw, 10)
    if (!Number.isFinite(total) || total <= 0) return null

    const buildHitHeaders = () => {
        const headers = new Headers(cached.headers)
        headers.set('x-cache-status', 'HIT')
        applyCommonHeaders(headers)
        for (const [k, v] of Object.entries(dynamicCors)) headers.set(k, v)
        return headers
    }

    // If-Range 不匹配说明缓存版本已不是客户端要的，按 RFC 返回完整 200。
    const ifRange = req.headers.get('if-range')
    if (ifRange) {
        const cachedEtag = cached.headers.get('etag')
        const cachedLastModified = cached.headers.get('last-modified')
        const matched = (cachedEtag && ifRange === cachedEtag) ||
                        (cachedLastModified && ifRange === cachedLastModified)
        if (!matched) {
            const headers = buildHitHeaders()
            headers.set('x-cache-status', 'HIT-IF-RANGE-MISS')
            return new Response(cached.body, { status: 200, headers })
        }
    }

    const range = parseRangeHeader(req.headers.get('range'), total)
    if (!range) return null

    if (range.unsatisfiable) {
        const headers = buildHitHeaders()
        headers.set('x-cache-status', 'HIT-RANGE-416')
        headers.set('content-range', `bytes */${total}`)
        headers.delete('content-length')
        return new Response(null, { status: 416, headers })
    }

    // 起点太靠后（要丢弃大量前缀）或切片太长时回源，不占请求生命周期的 I/O。
    if (range.start > CONFIG.RANGE_CACHE_MAX_SKIP || range.length > CONFIG.RANGE_CACHE_MAX_BYTES) {
        return null
    }

    const headers = buildHitHeaders()
    headers.set('x-cache-status', 'HIT-RANGE')
    headers.set('accept-ranges', 'bytes')
    headers.set('content-range', `bytes ${range.start}-${range.end}/${total}`)
    headers.set('content-length', String(range.length))

    return new Response(sliceCachedResponse(cached, range), { status: 206, headers })
}

function isSafeAzureRedirect(hostname) {
    return AZURE_BLOB_SUFFIXES.some(suffix => hostname.endsWith(suffix))
}

async function checkRateLimit(req, event) {
    try {
        const ip = req.headers.get('cf-connecting-ip') || 'unknown'
        const now = Math.floor(Date.now() / 1000)
        const windowKey = `rl:${ip}:${Math.floor(now / CONFIG.RATE_LIMIT_WINDOW)}`
        const cacheKey = `https://cache.internal/rate-limit/${windowKey}`
        const cache = caches.default
        
        const cacheReq = new Request(cacheKey, { method: 'GET' })
        const cached = await cache.match(cacheReq)
        
        let currentCount = 0
        if (cached) {
            currentCount = parseInt(await cached.text(), 10) || 0
        }

        if (currentCount >= CONFIG.RATE_LIMIT_MAX) {
            const retryAfter = (Math.floor(now / CONFIG.RATE_LIMIT_WINDOW) + 1) * CONFIG.RATE_LIMIT_WINDOW - now
            return makeRes(JSON.stringify({ error: 'Rate limit exceeded', retry_after: retryAfter }), 429, {
                'content-type': 'application/json; charset=utf-8', 
                'retry-after': String(retryAfter),
            })
        }

        event.waitUntil(cache.put(cacheReq, new Response(String(currentCount + 1), {
            headers: { 'cache-control': `public, max-age=${CONFIG.RATE_LIMIT_WINDOW}` }
        })).catch(e => console.warn('Rate limit cache update failed:', e)))
        
        return null
    } catch (e) { 
        console.warn('Rate limit bypass due to error:', e)
        return null 
    }
}

addEventListener('fetch', e => {
    e.respondWith(fetchHandler(e).catch(makeErrorRes))
})

async function fetchHandler(e) {
    const req = e.request
    const urlObj = new URL(req.url)
    
    if (req.method === 'OPTIONS') return PREFLIGHT_RESP

    let path = urlObj.searchParams.get('q')
    
    if (path) {
        const normalizedPath = path.replace(/^\//, '').replace(/^https?:\/+/, 'https://')
        const patternMatch = GITHUB_PATTERNS.some(p => p.test(normalizedPath))
        let hostnameMatch = false
        try { 
            hostnameMatch = ALLOWED_HOSTNAMES.includes(new URL(normalizedPath).hostname.toLowerCase()) 
        } catch {}
        
        if (patternMatch && hostnameMatch) {
            return Response.redirect('https://' + urlObj.host + CONFIG.PREFIX + normalizedPath, 301)
        }
        return makeRes('Blocked: Invalid redirect target.', 403)
    }

    let rawPath = urlObj.pathname
    if (CONFIG.PREFIX !== '/' && rawPath.startsWith(CONFIG.PREFIX)) {
        rawPath = rawPath.slice(CONFIG.PREFIX.length)
    }
    path = rawPath.replace(/^\//, '').replace(/^https?:\/+/, 'https://')

    if (!path) return serveIndex()
    
    if (GITHUB_PATTERNS.some(p => p.test(path))) {
        return proxyRequest(e, req, path)
    }

    return makeRes(JSON.stringify({ error: 'Not Found', message: 'Only GitHub URLs are supported.' }), 404, {
        'content-type': 'application/json; charset=utf-8'
    })
}

async function proxyRequest(e, req, pathname) {
    try {
        // 用完整 href 还原目标 URL：避免 pathname 解码签名参数中的斜杠，query 原样转发。
        const requestUrl = new URL(req.url)
        const targetPath = requestUrl.href.slice(requestUrl.origin.length + CONFIG.PREFIX.length)
        const targetUrl = targetPath.startsWith('http') ? targetPath : `https://${targetPath}`
        const urlObj = newUrl(targetUrl)
        if (!urlObj) return makeRes('Invalid target URL', 400)

        const isApiTarget = urlObj.hostname.toLowerCase() === 'api.github.com'
        const cacheable = !isApiTarget

        const cache = caches.default
        const cacheKey = buildCacheKey(pathname)
        const dynamicCors = getDynamicCorsHeaders(req, pathname)

        const isRangeRequest = !!req.headers.get('range')
        const rangeCacheEnabled = CONFIG.RANGE_CACHE_ENABLED !== false

        if (cacheable && req.method === 'GET' && (!isRangeRequest || rangeCacheEnabled)) {
            const cached = await cache.match(cacheKey)
            if (cached) {
                if (isRangeRequest) {
                    const rangeHit = serveRangeFromCache(req, cached, dynamicCors)
                    if (rangeHit) return rangeHit
                } else {
                    const clientEtag = req.headers.get('if-none-match')
                    const cachedEtag = cached.headers.get('etag')

                    if (clientEtag && clientEtag === cachedEtag) {
                        const headers = new Headers({ ...dynamicCors, ...SECURITY_HEADERS, 'etag': cachedEtag, 'x-cache-status': 'HIT-304' })
                        return new Response(null, { status: 304, headers })
                    }

                    const hitHeaders = new Headers(cached.headers)
                    hitHeaders.set('x-cache-status', 'HIT')
                    applyCommonHeaders(hitHeaders)
                    for (const [k, v] of Object.entries(dynamicCors)) hitHeaders.set(k, v)

                    return new Response(cached.body, { status: cached.status, headers: hitHeaders })
                }
            }
        }

        // 限流放在缓存查询之后：命中缓存不计额度，也省掉两次 Cache API 往返。
        const rateLimited = await checkRateLimit(req, e)
        if (rateLimited) return rateLimited

        const reqHdrNew = new Headers(req.headers)
        reqHdrNew.delete('cookie')
        reqHdrNew.delete('host')

        if (!isApiTarget) {
            reqHdrNew.delete('authorization')
        }
        const rangeHeader = req.headers.get('range')
        if (rangeHeader) {
            reqHdrNew.set('range', rangeHeader)
        }

        const response = await handleProxyFetch(urlObj, {
            method: req.method, 
            headers: reqHdrNew, 
            redirect: 'manual',
            body: req.body,
            cf: { 
                cacheEverything: false,
                cacheTtlByStatus: { "200-299": CONFIG.CACHE_TTL } 
            }
        }, 0)

        if ([301, 302, 303, 307, 308].includes(response.status)) {
             const location = response.headers.get('location')
             if (location) {
                 const nextUrl = new URL(location, urlObj.href)
                 const isSafe = SAFE_REDIRECT_HOSTS.has(nextUrl.hostname) || 
                                GITHUB_PATTERNS.some(p => p.test(nextUrl.href)) || 
                                isSafeAzureRedirect(nextUrl.hostname)
                 
                 if (isSafe) {
                     const redirHeaders = new Headers(response.headers)
                     applyCommonHeaders(redirHeaders)
                     for (const [k, v] of Object.entries(dynamicCors)) redirHeaders.set(k, v)

                     if (cacheable) {
                         e.waitUntil(cache.put(cacheKey, new Response(null, {
                             status: response.status,
                             headers: redirHeaders
                         })).catch(err => console.warn('Cache redirect failed', err)))
                     }

                     return new Response(null, { status: response.status, headers: redirHeaders })
                 }
             }
        }

        if (isApiTarget) {
            const apiHeaders = new Headers(response.headers)
            apiHeaders.set('x-cache-status', 'BYPASS-API')
            apiHeaders.set('cache-control', 'no-store')
            apiHeaders.delete('set-cookie')
            applyCommonHeaders(apiHeaders)
            for (const [k, v] of Object.entries(dynamicCors)) apiHeaders.set(k, v)
            return new Response(response.body, { status: response.status, headers: apiHeaders })
        }

        if (!response.ok && response.status !== 304 && response.status !== 206) {
            const errHeaders = new Headers(response.headers)
            applyCommonHeaders(errHeaders)
            for (const [k, v] of Object.entries(dynamicCors)) errHeaders.set(k, v)
            return new Response(response.body, { status: response.status, headers: errHeaders })
        }

        if (req.method === 'GET' && (response.status === 200 || response.status === 206)) {
            const contentLength = parseInt(response.headers.get('content-length') || '0', 10)
            
            const finalHeaders = new Headers(response.headers)
            applyCommonHeaders(finalHeaders)
            for (const [k, v] of Object.entries(dynamicCors)) finalHeaders.set(k, v)

            if (response.status === 206) {
                finalHeaders.set('x-cache-status', 'RANGE-BYPASS')
                return new Response(response.body, { status: 206, headers: finalHeaders })
            }

            const shouldCache = contentLength > 0 && contentLength <= CONFIG.MAX_CACHE_SIZE
            if (shouldCache && response.body) {
                finalHeaders.set('Cache-Control', `public, max-age=${CONFIG.CACHE_TTL}`)
                finalHeaders.set('x-cache-status', 'MISS')
                
                try {
                    const [forClient, forCache] = response.body.tee()
                    
                    e.waitUntil(cache.put(cacheKey, new Response(forCache, { 
                        status: response.status, 
                        headers: finalHeaders 
                    })))
                    
                    return new Response(forClient, { status: response.status, headers: finalHeaders })
                } catch (teeErr) {
                    console.error('Tee failed:', teeErr)
                    finalHeaders.set('x-cache-status', 'BYPASS-TEE-ERROR')
                    return new Response(response.body, { status: response.status, headers: finalHeaders })
                }
            } else {
                finalHeaders.set('x-cache-status', contentLength > CONFIG.MAX_CACHE_SIZE ? 'STREAM-LARGE' : 'STREAM')
                finalHeaders.delete('set-cookie')
                return new Response(response.body, { status: response.status, headers: finalHeaders })
            }
        }

        const missHeaders = new Headers(response.headers)
        missHeaders.set('x-cache-status', 'BYPASS')
        applyCommonHeaders(missHeaders)
        for (const [k, v] of Object.entries(dynamicCors)) missHeaders.set(k, v)
        
        return new Response(response.body, { status: response.status, headers: missHeaders })

    } catch (err) {
        console.error('Proxy Error:', err)
        return makeErrorRes(err)
    }
}

function buildCacheKey(pathname) {
    try {
        const url = newUrl(pathname)
        if (!url) throw new Error('Invalid URL')
        
        const STATIC_HOSTS = [
            'raw.githubusercontent.com',
            'raw.github.com',
            'codeload.github.com',
            'objects.githubusercontent.com',
            'github-releases.githubusercontent.com',
            'release-assets.githubusercontent.com',
            'github.githubassets.com'
        ]
        
        const isStaticAsset = STATIC_HOSTS.includes(url.hostname) || 
                              /\/releases\/download\//.test(url.pathname) ||
                              /\/archive\//.test(url.pathname) ||
                              /\/blobs\//.test(url.pathname)

        if (isStaticAsset) {
            const cleanUrl = new URL(url.href)
            cleanUrl.search = '' 
            cleanUrl.hash = ''
            cleanUrl.hostname = cleanUrl.hostname.toLowerCase()
            return new Request(cleanUrl.href, { method: 'GET' })
        }

        const NO_SIMPLIFY = [
            /^api\.github\.com$/, 
            /^gist\.(?:githubusercontent|github)\.com$/, 
        ]
        
        const isNoSimplify = NO_SIMPLIFY.some(p => p.test(url.hostname) || p.test(url.pathname))
        
        if (isNoSimplify) {
            const cleanUrl = new URL(url.href)
            cleanUrl.hostname = cleanUrl.hostname.toLowerCase()
            return new Request(cleanUrl.href, { method: 'GET' })
        }

        const cleanUrl = new URL(url.href)
        cleanUrl.hash = ''
        cleanUrl.hostname = cleanUrl.hostname.toLowerCase()
        
        const params = new URLSearchParams(cleanUrl.search)
        const newParams = new URLSearchParams()
        
        const keys = Array.from(params.keys()).sort()
        
        for (const key of keys) {
            if (IGNORED_QUERY_PARAMS.has(key)) continue
            
            const values = params.getAll(key)
            for (const val of values) {
                newParams.append(key, val)
            }
        }
        
        cleanUrl.search = newParams.toString()
        
        return new Request(cleanUrl.href, { method: 'GET' })
    } catch { 
        return new Request(`https://fallback.invalid/${pathname}`, { method: 'GET' }) 
    }
}

function getDynamicCorsHeaders(req, targetUrl) {
    try {
        const url = newUrl(targetUrl)
        if (url && (url.hostname === 'api.github.com' || url.searchParams.has('token'))) {
            const origin = req.headers.get('origin')
            if (origin) {
                return { 
                    'access-control-allow-origin': origin, 
                    'access-control-expose-headers': '*', 
                    'vary': 'Origin' 
                }
            }
            return { 'access-control-expose-headers': '*' }
        }
    } catch {}
    return { ...CORS_HEADERS }
}

async function handleProxyFetch(urlObj, init, redirectCount) {
    if (redirectCount > 5) return makeRes('Too many redirects', 508)
    
    try {
        const res = await fetch(urlObj.href, init)
        
        if ([301, 302, 303, 307, 308].includes(res.status)) {
            const location = res.headers.get('location')
            if (!location) return res
            
            const nextUrl = new URL(location, urlObj.href)
            
            const isSafe = SAFE_REDIRECT_HOSTS.has(nextUrl.hostname) || 
                           GITHUB_PATTERNS.some(p => p.test(nextUrl.href)) || 
                           isSafeAzureRedirect(nextUrl.hostname)
            
            if (isSafe) {
                return handleProxyFetch(nextUrl, init, redirectCount + 1)
            }
            
            const safeHeaders = new Headers(res.headers)
            safeHeaders.delete('set-cookie')
            applyCommonHeaders(safeHeaders)
            return new Response(null, { status: res.status, headers: safeHeaders })
        }
        
        const resHdrNew = new Headers(res.headers)
        resHdrNew.delete('content-security-policy')
        resHdrNew.delete('clear-site-data')
        resHdrNew.delete('x-frame-options')
        resHdrNew.delete('set-cookie')
        
        return new Response(res.body, { status: res.status, headers: resHdrNew })
    } catch (err) { 
        return makeRes('Proxy Error: ' + err.message, 502) 
    }
}

const ICON_SUN = `<svg class="icon-sun" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32l1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" stroke-linecap="round"/></svg>`
const ICON_MOON = `<svg class="icon-moon" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z" stroke-linecap="round" stroke-linejoin="round"/></svg>`
const ICON_GITHUB = `<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.4 7.4 0 012-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>`
const ICON_GLOBE = `<svg fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.5 3.8 5.6 3.8 9S14.5 18.5 12 21c-2.5-2.5-3.8-5.6-3.8-9S9.5 5.5 12 3z"/></svg>`
const ICON_CLOCK = `<svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" stroke-linecap="round" stroke-linejoin="round"/></svg>`
const ICON_ARROW = `<svg fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24" aria-hidden="true"><path d="M13 5l7 7-7 7M5 5l7 7-7 7" stroke-linecap="round" stroke-linejoin="round"/></svg>`

const THEME_BOOT_JS = "(function(){var k='gh_proxy_theme';var t='dark';try{var p=localStorage.getItem(k);var h=new Date(Date.now()+8*3600*1000).getUTCHours();t=(p==='light'||p==='dark')?p:((h>=7&&h<18)?'light':'dark');}catch(e){}document.documentElement.setAttribute('data-theme',t);})();"

const THEME_TOGGLE_JS = "(function(){var k='gh_proxy_theme';var btn=document.getElementById('themeToggle');if(!btn)return;function cur(){return document.documentElement.getAttribute('data-theme')==='light'?'light':'dark';}function auto(){var h=new Date(Date.now()+8*3600*1000).getUTCHours();return (h>=7&&h<18)?'light':'dark';}btn.addEventListener('click',function(){var n=cur()==='light'?'dark':'light';document.documentElement.setAttribute('data-theme',n);try{localStorage.setItem(k,n);}catch(e){}});btn.addEventListener('dblclick',function(){try{localStorage.removeItem(k);}catch(e){}document.documentElement.setAttribute('data-theme',auto());});setInterval(function(){var p=null;try{p=localStorage.getItem(k);}catch(e){}if(p!=='light'&&p!=='dark'){var a=auto();if(a!==cur())document.documentElement.setAttribute('data-theme',a);}},60000);})();"

const PAGE_BASE_CSS = `
:root {
    --radius-lg: 18px;
    --radius-md: 12px;
    --radius-sm: 8px;
    --font-sans: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Noto Sans SC", "Source Han Sans SC", "Microsoft YaHei", sans-serif;
    --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
    --bg: #0d1117;
    --surface: rgba(22, 27, 34, 0.72);
    --surface-2: rgba(255, 255, 255, 0.04);
    --surface-3: rgba(255, 255, 255, 0.08);
    --border: rgba(48, 54, 61, 0.75);
    --border-strong: rgba(88, 166, 255, 0.45);
    --text: #c9d1d9;
    --text-dim: #8b949e;
    --text-faint: rgba(139, 148, 158, 0.75);
    --accent: #58a6ff;
    --accent-soft: rgba(88, 166, 255, 0.14);
    --accent-glow: rgba(88, 166, 255, 0.32);
    --danger: #f85149;
    --danger-soft: rgba(248, 81, 73, 0.12);
    --ok: #3fb950;
    --input-bg: rgba(13, 17, 23, 0.65);
    --shadow-card: 0 18px 40px rgba(0, 0, 0, 0.35);
    --scrollbar-track: transparent;
    --scrollbar-thumb: rgba(48, 54, 61, 0.9);
    --scrollbar-thumb-hover: rgba(88, 166, 255, 0.55);
    --title-grad-start: #ffffff;
    --title-grad-end: #a5d6ff;
    --bg-image:
        radial-gradient(900px 520px at 8% -12%, rgba(88, 166, 255, 0.20), transparent 62%),
        radial-gradient(760px 460px at 92% -8%, rgba(130, 80, 223, 0.20), transparent 64%),
        radial-gradient(900px 620px at 50% 108%, rgba(63, 185, 80, 0.10), transparent 66%);
    --grid-line: rgba(255, 255, 255, 0.045);
    --hero-glow: rgba(88, 166, 255, 0.22);
    color-scheme: dark;
}

html[data-theme="light"] {
    --bg: #eef2f7;
    --surface: rgba(255, 255, 255, 0.78);
    --surface-2: rgba(31, 35, 40, 0.04);
    --surface-3: rgba(31, 35, 40, 0.08);
    --border: rgba(208, 215, 222, 0.9);
    --border-strong: rgba(9, 105, 218, 0.4);
    --text: #1f2328;
    --text-dim: #57606a;
    --text-faint: rgba(87, 96, 106, 0.8);
    --accent: #0969da;
    --accent-soft: rgba(9, 105, 218, 0.1);
    --accent-glow: rgba(9, 105, 218, 0.22);
    --danger: #cf222e;
    --danger-soft: rgba(207, 34, 46, 0.1);
    --ok: #1a7f37;
    --input-bg: rgba(255, 255, 255, 0.82);
    --shadow-card: 0 18px 40px rgba(140, 152, 175, 0.22);
    --scrollbar-track: transparent;
    --scrollbar-thumb: rgba(175, 184, 193, 0.9);
    --scrollbar-thumb-hover: rgba(9, 105, 218, 0.5);
    --title-grad-start: #1f2328;
    --title-grad-end: #0969da;
    --bg-image:
        radial-gradient(900px 520px at 8% -12%, rgba(9, 105, 218, 0.14), transparent 62%),
        radial-gradient(760px 460px at 92% -8%, rgba(130, 80, 223, 0.13), transparent 64%),
        radial-gradient(900px 620px at 50% 108%, rgba(26, 127, 55, 0.08), transparent 66%);
    --grid-line: rgba(31, 35, 40, 0.055);
    --hero-glow: rgba(9, 105, 218, 0.18);
    color-scheme: light;
}

*, *::before, *::after { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
    margin: 0;
    min-height: 100vh;
    min-height: 100dvh;
    padding-bottom: env(safe-area-inset-bottom, 0px);
    font-family: var(--font-sans);
    font-size: 16px;
    line-height: 1.6;
    color: var(--text);
    background-color: var(--bg);
    -webkit-font-smoothing: antialiased;
}
body::before,
body::after {
    content: "";
    position: fixed;
    inset: 0;
    z-index: 0;
    pointer-events: none;
}
body::before {
    background-image: var(--bg-image);
    background-repeat: no-repeat;
    background-size: cover;
}
body::after {
    background-image:
        linear-gradient(to right, var(--grid-line) 1px, transparent 1px),
        linear-gradient(to bottom, var(--grid-line) 1px, transparent 1px);
    background-size: 52px 52px;
    -webkit-mask-image: radial-gradient(ellipse 100% 70% at 50% 0%, #000 20%, transparent 78%);
    mask-image: radial-gradient(ellipse 100% 70% at 50% 0%, #000 20%, transparent 78%);
}
@supports not ((-webkit-mask-image: none) or (mask-image: none)) {
    body::after { background-image: none; }
}
h1, h2, h3, p, dl, dd, ul { margin: 0; }
ul { padding: 0; list-style: none; }
a { color: var(--accent); text-decoration: none; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
::selection { background: var(--accent-soft); }

.card {
    position: relative;
    background: var(--surface);
    backdrop-filter: blur(16px) saturate(1.25);
    -webkit-backdrop-filter: blur(16px) saturate(1.25);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-card), inset 0 1px 0 rgba(255, 255, 255, 0.06);
    transition: background 0.3s ease, border-color 0.3s ease, box-shadow 0.3s ease;
}
html[data-theme="light"] .card { box-shadow: var(--shadow-card), inset 0 1px 0 rgba(255, 255, 255, 0.9); }

.btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    height: 40px;
    padding: 0 16px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-2);
    color: var(--text);
    font: inherit;
    font-size: 0.88rem;
    font-weight: 600;
    line-height: 1;
    cursor: pointer;
    transition: background 0.18s ease, border-color 0.18s ease, color 0.18s ease, filter 0.18s ease;
}
.btn:hover { background: var(--surface-3); border-color: var(--border-strong); }
.btn:active { transform: translateY(1px); }
.btn:disabled { opacity: 0.55; cursor: not-allowed; }
.btn-primary {
    background: linear-gradient(135deg, var(--accent), #8250df);
    border-color: transparent;
    color: #fff;
    box-shadow: 0 6px 16px var(--accent-glow);
}
.btn-primary:hover {
    background: linear-gradient(135deg, var(--accent), #8250df);
    border-color: transparent;
    filter: brightness(1.08);
    box-shadow: 0 10px 22px var(--accent-glow);
}
.btn-primary:active { transform: translateY(1px); box-shadow: 0 4px 12px var(--accent-glow); }

.field {
    width: 100%;
    height: 44px;
    padding: 0 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--input-bg);
    color: var(--text);
    font: inherit;
    font-size: 0.92rem;
    transition: border-color 0.18s ease, box-shadow 0.18s ease, background 0.18s ease;
}
.field::placeholder { color: var(--text-faint); }
.field:hover { border-color: var(--border-strong); }
.field:focus {
    border-color: var(--accent);
    background: var(--surface);
    box-shadow: 0 0 0 3px var(--accent-soft), 0 6px 18px rgba(0, 0, 0, 0.12);
}

.code-inline {
    padding: 2px 6px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--surface-2);
    color: var(--accent);
    font-family: var(--font-mono);
    font-size: 0.85em;
    word-break: break-all;
}
.code-block {
    margin: 0;
    padding: 12px 14px;
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: var(--radius-md);
    background: rgba(0, 0, 0, 0.22);
    color: var(--text);
    font-family: var(--font-mono);
    font-size: 0.82rem;
    line-height: 1.6;
    white-space: pre-wrap;
    word-break: break-all;
    overflow-x: auto;
}
html[data-theme="light"] .code-block { background: rgba(31, 35, 40, 0.05); }

.theme-toggle {
    position: fixed;
    top: max(16px, env(safe-area-inset-top, 0px));
    right: max(16px, env(safe-area-inset-right, 0px));
    width: 42px;
    height: 42px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: 1px solid var(--border);
    border-radius: 50%;
    background: var(--surface);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    color: var(--text);
    cursor: pointer;
    z-index: 50;
    box-shadow: 0 6px 18px var(--shadow-card);
    transition: transform 0.18s ease, border-color 0.18s ease, color 0.18s ease;
}
.theme-toggle:hover { transform: scale(1.06) rotate(8deg); border-color: var(--border-strong); color: var(--accent); }
.theme-toggle svg { position: absolute; width: 18px; height: 18px; transition: opacity 0.22s ease, transform 0.22s ease; }
.theme-toggle .icon-sun { opacity: 1; transform: rotate(0deg) scale(1); }
.theme-toggle .icon-moon { opacity: 0; transform: rotate(-90deg) scale(0.5); }
html[data-theme="light"] .theme-toggle .icon-sun { opacity: 0; transform: rotate(90deg) scale(0.5); }
html[data-theme="light"] .theme-toggle .icon-moon { opacity: 1; transform: rotate(0deg) scale(1); }
`

const HOME_CSS = `
.page-home { display: flex; }
.shell {
    position: relative;
    z-index: 1;
    display: grid;
    grid-template-columns: minmax(0, 1fr) 336px;
    gap: 22px;
    align-items: start;
    width: 100%;
    max-width: 1040px;
    margin: auto;
    padding: 84px 20px 44px;
}
.hero {
    padding: 40px 36px 34px;
    overflow: hidden;
    isolation: isolate;
}
.hero::before {
    content: "";
    position: absolute;
    z-index: -1;
    top: -140px;
    left: 50%;
    width: 460px;
    height: 320px;
    transform: translateX(-50%);
    background: radial-gradient(closest-side, var(--hero-glow), transparent 78%);
    pointer-events: none;
}
.hero::after {
    content: "";
    position: absolute;
    z-index: -1;
    inset: 0;
    border-radius: inherit;
    background: linear-gradient(180deg, rgba(255, 255, 255, 0.05), transparent 42%);
    pointer-events: none;
}
html[data-theme="light"] .hero::after { background: linear-gradient(180deg, rgba(255, 255, 255, 0.6), transparent 46%); }
.brand {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 66px;
    height: 66px;
    margin: 0 auto 20px;
    border-radius: 20px;
    background: linear-gradient(140deg, #6cb6ff, var(--accent) 42%, #8250df);
    box-shadow: 0 14px 30px var(--accent-glow), inset 0 1px 0 rgba(255, 255, 255, 0.45);
    animation: brandFloat 6s ease-in-out infinite;
}
.brand::after {
    content: "";
    position: absolute;
    inset: 1px;
    border-radius: inherit;
    background: linear-gradient(180deg, rgba(255, 255, 255, 0.28), transparent 55%);
    pointer-events: none;
}
.brand svg { position: relative; width: 32px; height: 32px; fill: #fff; }
@keyframes brandFloat {
    0%, 100% { transform: translateY(0); }
    50% { transform: translateY(-4px); }
}
.title {
    margin: 0;
    text-align: center;
    font-size: 2.05rem;
    font-weight: 700;
    letter-spacing: -0.025em;
    background: linear-gradient(120deg, var(--title-grad-start), var(--title-grad-end));
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
}
@supports not ((-webkit-background-clip: text) or (background-clip: text)) {
    .title { color: var(--text); background: none; }
}
.subtitle {
    max-width: 34ch;
    margin: 12px auto 0;
    text-align: center;
    color: var(--text-dim);
    font-size: 0.9rem;
    line-height: 1.7;
}
.search-form {
    display: flex;
    gap: 8px;
    margin-top: 28px;
    padding: 6px;
    border: 1px solid var(--border);
    border-radius: 16px;
    background: var(--surface-2);
    transition: border-color 0.18s ease, box-shadow 0.18s ease, background 0.18s ease;
}
.search-form:focus-within {
    border-color: var(--border-strong);
    background: var(--surface);
    box-shadow: 0 0 0 4px var(--accent-soft);
}
.search-form .field {
    flex: 1 1 auto;
    height: 46px;
    border-color: transparent;
    background: transparent;
    box-shadow: none;
}
.search-form .field:hover { border-color: transparent; }
.search-form .field:focus { border-color: transparent; background: transparent; box-shadow: none; }
.search-form .btn { flex: none; height: 46px; padding: 0 20px; border-radius: 11px; }
.search-form .btn svg { width: 15px; height: 15px; }
.links {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 10px;
    margin-top: 22px;
}
.link-chip {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    height: 38px;
    padding: 0 15px;
    border: 1px solid var(--border);
    border-radius: 999px;
    background: var(--surface-2);
    color: var(--text-dim);
    font-size: 0.84rem;
    font-weight: 500;
    transition: background 0.18s ease, border-color 0.18s ease, color 0.18s ease, transform 0.18s ease, box-shadow 0.18s ease;
}
.link-chip:hover {
    background: var(--surface-3);
    border-color: var(--border-strong);
    color: var(--text);
    transform: translateY(-1px);
    box-shadow: 0 6px 16px rgba(0, 0, 0, 0.16);
}
.link-chip svg { width: 15px; height: 15px; flex: none; }
.foot {
    margin-top: 30px;
    padding-top: 16px;
    border-top: 1px solid var(--border);
    text-align: center;
    color: var(--text-dim);
    font-size: 0.77rem;
    letter-spacing: 0.01em;
    line-height: 1.6;
}
.foot b { color: var(--text-dim); font-weight: 600; }
.history-card { display: flex; flex-direction: column; padding: 20px 18px; }
.panel-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 0 2px 12px;
    border-bottom: 1px solid var(--border);
}
.panel-title { display: flex; align-items: center; gap: 8px; color: var(--text); font-size: 0.92rem; font-weight: 600; letter-spacing: 0.01em; }
.panel-title svg { width: 17px; height: 17px; flex: none; color: var(--accent); }
.count-badge {
    margin-left: 2px;
    padding: 1px 7px;
    border-radius: 999px;
    background: var(--accent-soft);
    color: var(--accent);
    font-size: 0.7rem;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
}
.count-badge:empty { display: none; }
.clear-btn {
    padding: 4px 10px;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-dim);
    font: inherit;
    font-size: 0.8rem;
    cursor: pointer;
    transition: color 0.18s ease, background 0.18s ease;
}
.clear-btn:hover { color: var(--danger); background: var(--danger-soft); }
.history-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
    max-height: min(58vh, 520px);
    margin: 8px -8px 0;
    padding: 0 8px;
    overflow-y: auto;
    overscroll-behavior: contain;
    scrollbar-width: thin;
    scrollbar-color: var(--scrollbar-thumb) var(--scrollbar-track);
}
.history-list::-webkit-scrollbar { width: 8px; }
.history-list::-webkit-scrollbar-track { background: var(--scrollbar-track); }
.history-list::-webkit-scrollbar-thumb { background: var(--scrollbar-thumb); border-radius: 999px; }
.history-list::-webkit-scrollbar-thumb:hover { background: var(--scrollbar-thumb-hover); }
.history-item {
    padding: 10px 12px;
    border: 1px solid transparent;
    border-radius: 10px;
    cursor: pointer;
    transition: background 0.18s ease, border-color 0.18s ease, transform 0.18s ease;
}
.history-item:hover, .history-item:focus-visible {
    background: var(--surface-2);
    border-color: var(--border);
    transform: translateX(2px);
}
.history-item:hover .history-arrow { color: var(--accent); transform: translate(2px, -2px); }
.history-item-top { display: flex; align-items: center; gap: 8px; }
.history-name {
    flex: 1 1 auto;
    min-width: 0;
    color: var(--text);
    font-size: 0.85rem;
    font-weight: 600;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.history-arrow {
    flex: none;
    color: var(--text-faint);
    font-size: 0.85rem;
    line-height: 1;
    transition: color 0.18s ease, transform 0.18s ease;
}
.history-url {
    margin-top: 4px;
    color: var(--text-faint);
    font-family: var(--font-mono);
    font-size: 0.72rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.history-time { margin-top: 5px; color: var(--text-dim); font-size: 0.72rem; }
.history-empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
    padding: 30px 12px;
    border: 1px dashed var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-2);
    text-align: center;
    color: var(--text-faint);
    font-size: 0.82rem;
}
.history-empty::before {
    content: "📭";
    font-size: 20px;
    opacity: 0.85;
}
.history-empty small { display: block; color: var(--text-faint); font-size: 0.74rem; }
@media (max-width: 900px) {
    .shell {
        grid-template-columns: minmax(0, 1fr);
        max-width: 620px;
        padding: 76px 16px 32px;
    }
    .hero { padding: 32px 24px 28px; }
    .title { font-size: 1.7rem; }
    .hero::before { top: -120px; width: 380px; height: 260px; }
}
@media (max-width: 520px) {
    .shell { padding: 68px 14px 28px; gap: 16px; }
    .hero { padding: 26px 18px 22px; }
    .title { font-size: 1.5rem; }
    .brand { width: 58px; height: 58px; border-radius: 17px; }
    .brand svg { width: 28px; height: 28px; }
    .search-form { flex-direction: column; padding: 8px; }
    .search-form .btn { width: 100%; }
    .history-card { padding: 16px 14px; }
}
@media (prefers-reduced-motion: reduce) {
    .brand { animation: none; }
    .theme-toggle,
    .btn,
    .history-item,
    .link-chip {
        transition: none;
    }
    .theme-toggle:hover,
    .btn:active,
    .btn-primary:active,
    .history-item:hover,
    .history-item:focus-visible {
        transform: none;
    }
}
`

function serveIndex() {
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>GitHub 加速代理</title>
<script>${THEME_BOOT_JS}</script>
<style>${PAGE_BASE_CSS}${HOME_CSS}</style>
</head>
<body class="page-home">
<button id="themeToggle" class="theme-toggle" type="button" title="切换白天/夜间模式（双击恢复按时间自动切换）" aria-label="切换白天/夜间模式">${ICON_SUN}${ICON_MOON}</button>

<main class="shell">
    <section class="card hero">
        <div class="brand" aria-hidden="true">${ICON_GITHUB}</div>
        <h1 class="title">GitHub 加速代理</h1>

        <form id="searchForm" class="search-form" autocomplete="off">
            <input id="searchInput" class="field" type="text" name="q" placeholder="粘贴 GitHub 链接" required spellcheck="false" aria-label="GitHub 链接">
            <button class="btn btn-primary" type="submit">Go${ICON_ARROW}</button>
        </form>

        <div class="links">
            <a class="link-chip" href="https://github.com/qfmc7040/CF-GH-Proxy/" target="_blank" rel="noopener">${ICON_GITHUB}项目源码</a>
            <a class="link-chip" href="https://github.akams.cn/" target="_blank" rel="noopener">${ICON_GLOBE}代理聚合</a>
        </div>

        <div class="foot">Powered by <b>Cloudflare Workers</b> · © QFMC</div>
    </section>

    <aside class="card history-card">
        <div class="panel-head">
            <div class="panel-title">${ICON_CLOCK}最近访问<span id="historyCount" class="count-badge"></span></div>
            <button id="clearHistory" class="clear-btn" type="button">清空</button>
        </div>
        <ul id="historyList" class="history-list"></ul>
    </aside>
</main>

<script>
(function () {
    var STORAGE_KEY = 'gh_proxy_history_v2';
    var MAX_HISTORY = 50;
    var list = document.getElementById('historyList');
    var form = document.getElementById('searchForm');
    var input = document.getElementById('searchInput');

    function loadHistory() {
        try {
            var raw = localStorage.getItem(STORAGE_KEY);
            var data = raw ? JSON.parse(raw) : [];
            return Array.isArray(data) ? data : [];
        } catch (e) { return []; }
    }

    function extractFilename(url) {
        try {
            var obj = new URL(url);
            var parts = obj.pathname.split('/').filter(Boolean);
            if (!parts.length) return obj.hostname;
            var last = parts[parts.length - 1];
            if (last.indexOf('.') !== -1) return last;
            if (parts.length > 1) return parts[parts.length - 2] + '/' + last;
            return obj.hostname;
        } catch (e) { return url; }
    }

    function timeAgo(ts) {
        var seconds = Math.floor((Date.now() - ts) / 1000);
        if (seconds < 60) return '刚刚';
        var minutes = Math.floor(seconds / 60);
        if (minutes < 60) return minutes + ' 分钟前';
        var hours = Math.floor(minutes / 60);
        if (hours < 24) return hours + ' 小时前';
        return Math.floor(hours / 24) + ' 天前';
    }

    function targetUrl(url) {
        return location.origin + '/' + String(url).replace(/^https?:\\/\\//, '');
    }

    function renderHistory() {
        if (!list) return;
        var history = loadHistory();
        list.textContent = '';
        var badge = document.getElementById('historyCount');
        if (badge) badge.textContent = history.length ? String(history.length) : '';
        if (!history.length) {
            var empty = document.createElement('li');
            empty.className = 'history-empty';
            empty.textContent = '暂无访问记录';
            var tip = document.createElement('small');
            tip.textContent = '转发一次 GitHub 链接后会出现在这里';
            empty.appendChild(tip);
            list.appendChild(empty);
            return;
        }
        history.forEach(function (item) {
            var li = document.createElement('li');
            li.className = 'history-item';
            li.tabIndex = 0;
            li.setAttribute('role', 'link');

            var top = document.createElement('div');
            top.className = 'history-item-top';
            var name = document.createElement('span');
            name.className = 'history-name';
            name.textContent = item.filename || extractFilename(item.url);
            name.title = name.textContent;
            var arrow = document.createElement('span');
            arrow.className = 'history-arrow';
            arrow.textContent = '↗';
            arrow.setAttribute('aria-hidden', 'true');
            top.appendChild(name);
            top.appendChild(arrow);

            var url = document.createElement('div');
            url.className = 'history-url';
            url.textContent = item.url;
            url.title = item.url;

            var time = document.createElement('div');
            time.className = 'history-time';
            time.textContent = timeAgo(item.time);

            li.appendChild(top);
            li.appendChild(url);
            li.appendChild(time);

            function open() { window.location.href = targetUrl(item.url); }
            li.addEventListener('click', open);
            li.addEventListener('keydown', function (e) {
                if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); }
            });

            list.appendChild(li);
        });
    }

    function saveHistory(url) {
        var history = loadHistory().filter(function (item) { return item.url !== url; });
        history.unshift({ url: url, filename: extractFilename(url), time: Date.now() });
        if (history.length > MAX_HISTORY) history = history.slice(0, MAX_HISTORY);
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(history)); } catch (e) {}
        renderHistory();
    }

    var clearBtn = document.getElementById('clearHistory');
    if (clearBtn) {
        clearBtn.addEventListener('click', function () {
            try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
            renderHistory();
        });
    }

    if (form && input) {
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            var val = input.value.trim();
            if (!val) return;
            if (!/^https?:\\/\\//i.test(val)) val = 'https://' + val;
            saveHistory(val);
            window.location.href = targetUrl(val);
        });
    }

    renderHistory();
})();
</script>
<script>${THEME_TOGGLE_JS}</script>
</body>
</html>`
    return new Response(html, {
        status: 200,
        headers: {
            'content-type': 'text/html; charset=utf-8',
            ...CORS_HEADERS,
            ...SECURITY_HEADERS
        }
    })
}
