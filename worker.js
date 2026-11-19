// @ts-nocheck
// 单文件 Cloudflare Worker：caches.default、FetchEvent、GITHUB_TOKEN 等运行时全局
// 没有随包类型声明，开 checkJs 会产生大量与运行行为无关的报错，故整文件跳过类型检查。
'use strict'

const CONFIG = {
    PREFIX: '/',
    CACHE_TTL: 604800,
    // 超过此大小不写边缘缓存。响应体 tee 的两支共享背压，写缓存那一支慢会
    // 拖住发给客户端的那一支，大文件下载会因此被限速（实测尤以 Release 资产明显）。
    CACHE_MAX_SIZE: 32 * 1024 * 1024,
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
    // 首页 HTML 允许浏览器强缓存：命中时请求不再发到 Worker，也不占用每日请求额度。
    // 改了首页样式后，老访客最长要等这么久才能看到新版本，改版期间可临时调成 0。
    INDEX_TTL: 3600,
    // api.github.com 只对 Release 列表做短缓存，量级取 GitHub 自己响应头里的 60 秒。
    API_CACHE_TTL: 60,
    // 超过 CACHE_MAX_SIZE 的大文件不写边缘缓存，但让浏览器自己存一份。
    LARGE_CACHE_TTL: 86400,
    // Actions Artifacts 下载：部署方 PAT 具备 Actions: read 时才真正可用。
    // 策略是"仅公开仓库"——私有仓库的构建产物绝不经由本代理外泄。
    ARTIFACT_DOWNLOAD_ENABLED: true,
    // 公开性判定的边缘缓存时长。仓库由公开转私有后，最长要等这么久才失效。
    ARTIFACT_REPO_TTL: 86400,
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

// 部署方可在 Worker 里配置 GITHUB_TOKEN 变量/Secret，用它替代匿名额度。
// Service Worker 格式下绑定挂在全局作用域；typeof 对未声明的标识符不会抛错。
function serverGithubToken() {
    try {
        if (typeof GITHUB_TOKEN === 'string' && GITHUB_TOKEN.trim()) return GITHUB_TOKEN.trim()
    } catch (e) { /* 未配置 */ }
    try {
        if (typeof env === 'object' && env && typeof env.GITHUB_TOKEN === 'string' && env.GITHUB_TOKEN.trim()) {
            return env.GITHUB_TOKEN.trim()
        }
    } catch (e) { /* 未配置 */ }
    return ''
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
        
        // 网页版 artifact 地址不能直接下载，先换成 API zip 再做正常代理跳转。
        const artifactZip = artifactPageDownloadUrl(normalizedPath)
        if (artifactZip) {
            return Response.redirect('https://' + urlObj.host + CONFIG.PREFIX + artifactZip, 302)
        }

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

    // 网页版 artifact 地址（GITHUB_PATTERNS 不认这种形状），302 到对应的 API zip。
    const artifactZipTarget = artifactPageDownloadUrl(path)
    if (artifactZipTarget) {
        return Response.redirect('https://' + urlObj.host + CONFIG.PREFIX + artifactZipTarget, 302)
    }

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
        // 调用方自带 Authorization 时不读也不写 API 缓存：同一个 URL 对不同身份
        // 可能返回不同数据，缓存里只放用部署方 Token 取到的结果。
        const apiCacheable = isApiTarget && req.method === 'GET' &&
            !req.headers.get('authorization') && isCacheableApiPath(urlObj)

        const cache = caches.default
        // 必须用完整目标 URL（含 query）：buildCacheKey 收到的若只是 pathname，
        // api.github.com/repos/o/r/releases?per_page=10 与 ?per_page=100 会撞成同一个键，
        // 后到的请求直接拿到别人的分页结果。静态资产的 search 由 buildCacheKey 内部清空，
        // 签名参数不会因此产生垃圾条目。
        const cacheKey = buildCacheKey(urlObj.href)
        // 同理，getDynamicCorsHeaders 靠 query 里的 token 判断私有资源，也要完整 URL。
        const dynamicCors = getDynamicCorsHeaders(req, urlObj.href)

        const isRangeRequest = !!req.headers.get('range')
        const rangeCacheEnabled = CONFIG.RANGE_CACHE_ENABLED !== false

        if ((cacheable || apiCacheable) && req.method === 'GET' && (!isRangeRequest || rangeCacheEnabled)) {
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
                    // API 命中时用当前配置重写缓存时长，不信任条目里存的 Cache-Control：
                    // 旧版本部署（或误判分支）写进去的长 max-age 会把这个键锁死很久，
                    // 与 API_CACHE_TTL 的 60 秒语义冲突。
                    if (isApiTarget) hitHeaders.set('cache-control', `public, max-age=${CONFIG.API_CACHE_TTL}`)
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

        // 调用方自带的 Authorization 始终优先，也不借用部署方 Token。
        const callerToken = reqHdrNew.get('authorization')

        // Actions Artifacts 下载：用了部署方 Token 时只放行公开仓库。
        // 调用方自带 Token 时由调用方自己的权限决定，不做拦截。
        const artifactTarget = artifactDownloadTarget(urlObj)
        if (artifactTarget && !callerToken && CONFIG.ARTIFACT_DOWNLOAD_ENABLED !== false) {
            if (!(await isPublicRepo(artifactTarget.owner, artifactTarget.repo, e))) {
                return makeRes(JSON.stringify({
                    error: 'Forbidden',
                    message: 'Only public repositories can be downloaded through this proxy.',
                }), 403, { 'content-type': 'application/json; charset=utf-8' })
            }
        }

        if (isApiTarget) {
            // 没有调用方 Token 时用部署方配置的 Token，避免 Cloudflare 共享出口 IP
            // 把匿名的 60 次/小时用光。
            const serverToken = serverGithubToken()
            if (!callerToken && serverToken) reqHdrNew.set('authorization', 'Bearer ' + serverToken)
        } else {
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

        // handleProxyFetch 内部已递归跟随安全重定向（见 handleProxyFetch），
        // 只有非安全目标才会以 3xx 返回，因此这里不再重复处理重定向。
        if (isApiTarget) {
            const apiHeaders = new Headers(response.headers)
            apiHeaders.delete('set-cookie')

            if (apiCacheable && response.ok && response.body) {
                // 只缓存部署方 Token 取到的公开数据；命中分支会用当前请求的 Origin
                // 重写 CORS 头，所以存进去的副本去掉 allow-origin 与 vary。
                const cacheHeaders = new Headers(apiHeaders)
                cacheHeaders.delete('access-control-allow-origin')
                cacheHeaders.delete('vary')
                cacheHeaders.set('cache-control', `public, max-age=${CONFIG.API_CACHE_TTL}`)

                applyCommonHeaders(apiHeaders)
                for (const [k, v] of Object.entries(dynamicCors)) apiHeaders.set(k, v)
                apiHeaders.set('cache-control', `public, max-age=${CONFIG.API_CACHE_TTL}`)
                apiHeaders.set('x-cache-status', 'MISS-API')

                try {
                    const [forClient, forCache] = response.body.tee()
                    e.waitUntil(cache.put(cacheKey, new Response(forCache, {
                        status: response.status,
                        headers: cacheHeaders
                    })).catch(err => console.warn('Cache API response failed', err)))
                    return new Response(forClient, { status: response.status, headers: apiHeaders })
                } catch (teeErr) {
                    console.warn('API tee failed:', teeErr)
                }
            }

            apiHeaders.set('x-cache-status', 'BYPASS-API')
            apiHeaders.set('cache-control', 'no-store')
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

            const shouldCache = contentLength > 0 && contentLength <= CONFIG.CACHE_MAX_SIZE
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
            } else if (contentLength > CONFIG.CACHE_MAX_SIZE) {
                // 大文件不写边缘缓存（tee 会拖慢下载），但让浏览器自己存一份：
                // 重复下载直接命中本地缓存，不再经过 Worker。GitHub 的下载源本身
                // 不发 Cache-Control，没有这一行浏览器每次都会重新拉。
                finalHeaders.set('cache-control', `public, max-age=${CONFIG.LARGE_CACHE_TTL}`)
                finalHeaders.set('x-cache-status', 'STREAM-LARGE')
                finalHeaders.delete('set-cookie')
                return new Response(response.body, { status: response.status, headers: finalHeaders })
            } else {
                finalHeaders.set('x-cache-status', 'STREAM')
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

// 只给 API 里"列表型、可容忍几十秒延迟"的路径开短缓存。
// Release 列表每次打开页面都会打一次 api.github.com，匿名额度只有 60 次/小时。
function isCacheableApiPath(urlObj) {
    try {
        return /^\/repos\/[^/]+\/[^/]+\/releases\/?$/i.test(urlObj.pathname)
    } catch { return false }
}

// Actions Runs 页面里的 artifact 链接：
// github.com/{owner}/{repo}/actions/runs/{run_id}/artifacts/{artifact_id}
// 网页上的下载按钮是 JS 调 API，地址本身不能直接下载。这里换成对应的 API zip
// 路径并 302 过去，粘贴网页地址也能直接下载。
function artifactPageDownloadUrl(path) {
    try {
        const m = /^(?:https?:\/\/)?(?:www\.)?github\.com\/([^/]+)\/([^/]+)\/actions\/runs\/\d+\/artifacts\/(\d+)\/?$/i.exec(path)
        if (!m) return null
        const owner = encodeURIComponent(decodeURIComponent(m[1]))
        const repo = encodeURIComponent(decodeURIComponent(m[2]))
        return `https://api.github.com/repos/${owner}/${repo}/actions/artifacts/${m[3]}/zip`
    } catch {
        return null
    }
}

// Actions Artifacts 下载路径：/repos/{owner}/{repo}/actions/artifacts/{id}/zip
// 只有这个形状的请求才需要做"是否公开仓库"的判定，其余 API 路径不受影响。
function artifactDownloadTarget(urlObj) {
    try {
        if (urlObj.hostname.toLowerCase() !== 'api.github.com') return null
        const m = /^\/repos\/([^/]+)\/([^/]+)\/actions\/artifacts\/[^/]+\/zip\/?$/i.exec(urlObj.pathname)
        if (!m) return null
        return { owner: decodeURIComponent(m[1]), repo: decodeURIComponent(m[2]) }
    } catch {
        return null
    }
}

// 仅公开仓库：部署方 PAT 一旦带 Actions 读权限，私有仓库的 artifact 会变成
// 任何访客都能下载的公开链接，所以下载前先确认仓库是公开的。
// 判定结果按 TTL 缓存；查不到（404 / 额度耗尽 / 网络错误）一律按不可用处理。
async function isPublicRepo(owner, repo, event) {
    const cache = caches.default
    const cacheKey = new Request(
        `https://cache.internal/repo-visibility/${owner.toLowerCase()}/${repo.toLowerCase()}`,
        { method: 'GET' }
    )
    try {
        const cached = await cache.match(cacheKey)
        if (cached) return (await cached.text()) === 'public'
    } catch (e) { /* 缓存读失败就回源 */ }

    try {
        const apiUrl = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`
        const headers = new Headers({
            'accept': 'application/vnd.github+json',
            'user-agent': 'CF-GH-Proxy',
        })
        const serverToken = serverGithubToken()
        if (serverToken) headers.set('authorization', 'Bearer ' + serverToken)

        const res = await fetch(apiUrl, { headers })
        if (!res.ok) return false

        const data = await res.json()
        const isPublic = !!data && data.private === false

        event.waitUntil(cache.put(cacheKey, new Response(isPublic ? 'public' : 'private', {
            headers: { 'cache-control': `public, max-age=${CONFIG.ARTIFACT_REPO_TTL}` },
        })).catch(err => console.warn('Repo visibility cache failed:', err)))

        return isPublic
    } catch (err) {
        console.warn('Repo visibility check failed:', err)
        return false
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

// Authorization 只允许发给 api.github.com：跟随 302 到 Azure Blob 等下载域时
// 必须重新算一次，否则部署方 PAT 会被一起发出去，也会和 SAS 鉴权打架。
function headersForTarget(urlObj, init) {
    const headers = new Headers(init.headers || {})
    if (urlObj.hostname.toLowerCase() !== 'api.github.com') headers.delete('authorization')
    return { ...init, headers }
}

async function handleProxyFetch(urlObj, init, redirectCount) {
    if (redirectCount > 5) return makeRes('Too many redirects', 508)
    
    try {
        const res = await fetch(urlObj.href, headersForTarget(urlObj, init))
        
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

// Release 列表模式的前端脚本。以源码形式注入页面（toString），避免在模板字符串里转义正则。
function releaseModeClient() {
    var LS_KEY = 'gh_proxy_release_mode';
    var PER_PAGE = 20;

    var toggle = document.getElementById('releaseModeToggle');
    var submitLabel = document.getElementById('submitLabel');
    var input = document.getElementById('searchInput');
    var hint = document.getElementById('formHint');
    var modal = document.getElementById('releaseModal');
    var modalBody = document.getElementById('releaseBody');
    var modalTitle = document.getElementById('releaseTitle');
    var modalSub = document.getElementById('releaseSub');
    var closeBtn = document.getElementById('releaseClose');

    var state = { enabled: false, repo: null, page: 1, loading: false, items: [], lastFocus: null };

    function readEnabled() {
        try { return localStorage.getItem(LS_KEY) === '1'; } catch (e) { return false; }
    }
    function saveEnabled(on) {
        try { localStorage.setItem(LS_KEY, on ? '1' : '0'); } catch (e) {}
    }
    function setEnabled(on) {
        state.enabled = !!on;
        if (toggle) toggle.checked = state.enabled;
        if (submitLabel) submitLabel.textContent = state.enabled ? '获取列表' : 'Go';
        if (input) input.placeholder = state.enabled ? '粘贴 GitHub 仓库链接' : '粘贴 GitHub 链接';
        if (!state.enabled) clearHint();
    }
    function showHint(msg, isError) {
        if (!hint) return;
        hint.textContent = msg;
        hint.hidden = !msg;
        hint.classList.toggle('is-error', !!isError && !!msg);
    }
    function clearHint() { showHint(''); }

    function stripHost(value) {
        var s = String(value == null ? '' : value).trim();
        if (!s) return '';
        s = s.replace(/^https?:\/\//i, '');
        var host = location.host;
        if (host && s.toLowerCase().indexOf(host.toLowerCase() + '/') === 0) {
            s = s.slice(host.length + 1);
        }
        return s.replace(/^https?:\/\//i, '');
    }

    // 明确指向具体文件/下载的链接不改走列表，直接按原逻辑下载或预览。
    function isDirectFile(value) {
        var s = stripHost(value).toLowerCase();
        if (!s) return false;
        return /^(?:raw|gist|codeload)\.githubusercontent\.com\//.test(s) ||
            /^codeload\.github\.com\//.test(s) ||
            /^raw\.github\.com\//.test(s) ||
            /\/(?:releases\/download|archive|blob|raw|tags|info|git-)\//.test(s) ||
            /\.(?:zip|tar\.gz|tgz|exe|msi|dmg|apk|deb|rpm|jar|whl)$/.test(s);
    }

    function parseRepo(value) {
        var s = stripHost(value);
        if (!s) return null;
        var m = /^(?:www\.)?github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)/i.exec(s);
        if (m) return { owner: m[1], repo: m[2].replace(/\.git$/i, '') };
        var short = /^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/.exec(s);
        if (short) return { owner: short[1], repo: short[2] };
        return null;
    }

    function proxyUrl(u) {
        if (!u) return '#';
        return location.origin + '/' + String(u).replace(/^https?:\/\//i, '');
    }

    function pad(n) { return n < 10 ? '0' + n : String(n); }

    function formatSize(bytes) {
        var n = Number(bytes);
        if (!isFinite(n) || n <= 0) return '';
        var units = ['B', 'KB', 'MB', 'GB'];
        var i = 0;
        while (n >= 1024 && i < units.length - 1) { n = n / 1024; i++; }
        return (i === 0 ? String(n) : n.toFixed(1)) + ' ' + units[i];
    }

    function formatDate(iso) {
        if (!iso) return '';
        var d = new Date(iso);
        if (isNaN(d.getTime())) return '';
        var diff = Math.floor((Date.now() - d.getTime()) / 1000);
        var abs = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
        if (diff < 60) return '刚刚';
        if (diff < 3600) return Math.floor(diff / 60) + ' 分钟前';
        if (diff < 86400) return Math.floor(diff / 3600) + ' 小时前';
        if (diff < 86400 * 30) return Math.floor(diff / 86400) + ' 天前';
        return abs;
    }

    function el(tag, cls, text) {
        var node = document.createElement(tag);
        if (cls) node.className = cls;
        if (text != null) node.textContent = text;
        return node;
    }

    function openModal() {
        if (!modal) return;
        state.lastFocus = document.activeElement;
        modal.hidden = false;
        document.body.classList.add('modal-open');
        if (closeBtn) closeBtn.focus();
    }
    function closeModal() {
        if (!modal || modal.hidden) return;
        modal.hidden = true;
        document.body.classList.remove('modal-open');
        if (state.lastFocus && state.lastFocus.focus) state.lastFocus.focus();
        state.lastFocus = null;
    }
    function isOpen() { return !!modal && !modal.hidden; }

    function setState(text, isError) {
        if (!modalBody) return null;
        modalBody.textContent = '';
        var box = el('div', 'modal-state' + (isError ? ' error' : ''), text);
        modalBody.appendChild(box);
        return box;
    }

    function renderItem(item, isLatest) {
        var wrap = el('div', 'release-item');

        var top = el('div', 'release-top');
        var tag = el('a', 'release-tag', item.tag_name || '(未命名)');
        tag.href = proxyUrl(item.html_url || '');
        tag.target = '_blank';
        tag.rel = 'noopener';
        top.appendChild(tag);

        if (item.name && item.name !== item.tag_name) {
            top.appendChild(el('span', 'release-name', item.name));
        }
        if (isLatest) top.appendChild(el('span', 'badge badge-latest', '最新'));
        if (item.prerelease) top.appendChild(el('span', 'badge badge-pre', '预发布'));
        wrap.appendChild(top);

        var metaParts = [];
        var when = item.published_at || item.created_at;
        if (when) metaParts.push(formatDate(when));
        var author = item.author && item.author.login;
        if (author) metaParts.push('@' + author);
        var assets = Array.isArray(item.assets) ? item.assets : [];
        if (assets.length) metaParts.push(assets.length + ' 个文件');
        if (metaParts.length) wrap.appendChild(el('div', 'release-meta', metaParts.join(' · ')));

        var bodyText = String(item.body || '').trim();
        if (bodyText) {
            var body = el('div', 'release-body clamped', bodyText);
            wrap.appendChild(body);
            if (bodyText.length > 400) {
                var actions = el('div', 'release-actions');
                var expand = el('button', 'release-toggle', '展开全部');
                expand.type = 'button';
                expand.addEventListener('click', function () {
                    var clamped = body.classList.toggle('clamped');
                    expand.textContent = clamped ? '展开全部' : '收起';
                });
                actions.appendChild(expand);
                wrap.appendChild(actions);
            }
        }

        if (assets.length) {
            var list = el('div', 'release-assets');
            assets.forEach(function (asset) {
                if (!asset || !asset.name) return;
                var chip = el('a', 'asset-chip');
                chip.href = proxyUrl(asset.browser_download_url || '');
                chip.title = asset.name;
                chip.appendChild(el('span', '', asset.name));
                var size = formatSize(asset.size);
                if (size) chip.appendChild(el('em', 'asset-size', size));
                list.appendChild(chip);
            });
            wrap.appendChild(list);
        }
        return wrap;
    }

    function renderItems(items, append) {
        if (!modalBody) return;
        if (!append) modalBody.textContent = '';
        var existingMore = modalBody.querySelector('.modal-foot');
        if (existingMore) existingMore.parentNode.removeChild(existingMore);

        var latestIndex = -1;
        if (state.page === 1 && !append) {
            for (var i = 0; i < items.length; i++) {
                if (!items[i].prerelease && !items[i].draft) { latestIndex = i; break; }
            }
        }
        items.forEach(function (item, i) {
            modalBody.appendChild(renderItem(item, i === latestIndex));
        });

        if (items.length >= PER_PAGE) {
            var foot = el('div', 'modal-foot');
            var more = el('button', 'btn', '加载更多');
            more.type = 'button';
            more.addEventListener('click', function () {
                more.disabled = true;
                more.textContent = '加载中…';
                loadPage(state.page + 1, true);
            });
            foot.appendChild(more);
            modalBody.appendChild(foot);
        }
    }

    function headerOf(res, name) {
        try { return res && res.headers ? res.headers.get(name) : null; } catch (e) { return null; }
    }

    function clockOf(seconds) {
        var d = new Date(seconds * 1000);
        return pad(d.getHours()) + ':' + pad(d.getMinutes());
    }

    // 只有 x-ratelimit-remaining 归零才是额度用尽；其余 403 另有原因。
    // 非限流的 403 通常不带 x-ratelimit-* 头，因此不能用 "有 reset 头" 当作判断依据。
    function isQuotaExhausted(res) {
        return headerOf(res, 'x-ratelimit-remaining') === '0';
    }

    function quotaText(res) {
        var tail = '';
        var ts = parseInt(headerOf(res, 'x-ratelimit-reset'), 10);
        if (isFinite(ts) && ts > 0) tail = '，约 ' + clockOf(ts) + ' 后恢复';
        return 'GitHub API 额度已用尽' + tail + '。' +
            '未配置 Token 时每个出口 IP 每小时只能请求 60 次；' +
            '在 Worker 里配置 GITHUB_TOKEN 变量可提升到每小时 5000 次。';
    }

    function throttledText(res) {
        var tail = '';
        var retry = parseInt(headerOf(res, 'retry-after'), 10);
        if (isFinite(retry) && retry > 0) tail = '，约 ' + retry + ' 秒后再试';
        return '本站代理请求过于频繁' + tail + '。';
    }

    function deniedText() {
        return 'GitHub 拒绝了这次请求（HTTP 403）。' +
            '常见原因：触发了二级限流、仓库已被禁用，或该仓库不允许匿名访问。';
    }

    function errorTextFor(status, res, bodyText) {
        if (status === 404) return '仓库不存在，或该仓库没有 Release。';
        if (status === 429) {
            // 本站代理自己的限流返回 JSON {error:"Rate limit exceeded"}。
            if (bodyText && bodyText.indexOf('Rate limit exceeded') !== -1) return throttledText(res);
            return isQuotaExhausted(res) ? quotaText(res) : 'GitHub API 限流（HTTP 429）。请稍后再试。';
        }
        if (status === 403) return isQuotaExhausted(res) ? quotaText(res) : deniedText();
        return '获取 Release 失败（HTTP ' + status + '）。';
    }

    // 翻页失败时只在页脚提示，保留已经渲染出的列表。
    function showFootError(foot, msg, retryPage) {
        if (!foot) return;
        foot.textContent = '';
        foot.appendChild(el('div', 'modal-state error', msg));
        var retry = el('button', 'btn', '重试');
        retry.type = 'button';
        retry.addEventListener('click', function () {
            retry.disabled = true;
            retry.textContent = '加载中…';
            loadPage(retryPage, true);
        });
        foot.appendChild(retry);
    }

    function loadPage(page, append) {
        if (!state.repo || state.loading) return;
        state.loading = true;
        var placeholder = null;
        var foot = modalBody ? modalBody.querySelector('.modal-foot') : null;
        if (!append) placeholder = setState('加载中…', false);
        else if (foot) foot.textContent = '加载中…';

        var api = location.origin + '/api.github.com/repos/' +
            encodeURIComponent(state.repo.owner) + '/' + encodeURIComponent(state.repo.repo) +
            '/releases?per_page=' + PER_PAGE + '&page=' + page;

        fetch(api, { headers: { 'Accept': 'application/vnd.github+json' } })
            .then(function (res) {
                if (res.ok) return res.json().then(function (data) { return { ok: true, data: data }; });
                return res.text().then(function (t) { return { ok: false, status: res.status, res: res, body: t }; });
            })
            .then(function (r) {
                state.loading = false;
                if (!r.ok) {
                    var msg = errorTextFor(r.status, r.res, r.body);
                    if (append) showFootError(foot, msg, state.page + 1);
                    else setState(msg, true);
                    return;
                }
                var list = Array.isArray(r.data) ? r.data : [];
                if (!append && !list.length) {
                    setState('该仓库还没有发布 Release', false);
                    return;
                }
                if (append && !list.length) {
                    if (foot) foot.textContent = '没有更多了';
                    return;
                }
                if (placeholder && placeholder.parentNode) placeholder.parentNode.removeChild(placeholder);
                state.page = page;
                state.items = append ? state.items.concat(list) : list;
                renderItems(list, append);
            })
            .catch(function (err) {
                state.loading = false;
                var msg = '网络请求失败：' + (err && err.message ? err.message : '未知错误');
                if (append) showFootError(foot, msg, state.page + 1);
                else setState(msg, true);
            });
    }

    // 返回值：true = 已接管（打开浮窗或给出提示），false = 交回原有下载逻辑。
    function openReleaseList(raw) {
        if (isDirectFile(raw)) {
            clearHint();
            return false;
        }
        var repo = parseRepo(raw);
        if (!repo) {
            clearHint();
            return false;
        }
        clearHint();
        state.repo = repo;
        state.page = 1;
        state.items = [];
        state.loading = false;
        if (modalTitle) modalTitle.textContent = repo.owner + '/' + repo.repo;
        if (modalSub) modalSub.textContent = 'Releases · 数据来自 GitHub API';
        openModal();
        loadPage(1, false);
        return true;
    }

    setEnabled(readEnabled());
    if (toggle) {
        toggle.addEventListener('change', function () {
            setEnabled(toggle.checked);
            saveEnabled(state.enabled);
            if (!state.enabled) { clearHint(); closeModal(); }
        });
    }

    if (modal) {
        modal.addEventListener('click', function (e) {
            var t = e.target;
            if (t && t.getAttribute && t.getAttribute('data-close-modal') !== null) closeModal();
        });
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && isOpen()) closeModal();
        });
    }

    window.GHReleaseMode = {
        enabled: function () { return state.enabled; },
        open: function (value) { return openReleaseList(value); },
        close: closeModal
    };
}

const THEME_BOOT_JS = "(function(){var k='gh_proxy_theme',r=document.documentElement,t='dark';try{var p=localStorage.getItem(k);if(p==='light'||p==='dark'){t=p}else{var q=window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)');if(q){t=q.matches?'dark':'light'}else{var h=new Date(Date.now()+8*3600*1000).getUTCHours();t=(h>=7&&h<18)?'light':'dark'}}}catch(e){}r.setAttribute('data-theme',t)})();"

const THEME_TOGGLE_JS = "(function(){var k='gh_proxy_theme';var btn=document.getElementById('themeToggle');if(!btn)return;function cur(){return document.documentElement.getAttribute('data-theme')==='light'?'light':'dark';}function auto(){var q=window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)');if(q){return q.matches?'dark':'light';}var h=new Date(Date.now()+8*3600*1000).getUTCHours();return (h>=7&&h<18)?'light':'dark';}btn.addEventListener('click',function(){var n=cur()==='light'?'dark':'light';document.documentElement.setAttribute('data-theme',n);try{localStorage.setItem(k,n);}catch(e){}});btn.addEventListener('dblclick',function(){try{localStorage.removeItem(k);}catch(e){}document.documentElement.setAttribute('data-theme',auto());});setInterval(function(){var p=null;try{p=localStorage.getItem(k);}catch(e){}if(p!=='light'&&p!=='dark'){var a=auto();if(a!==cur())document.documentElement.setAttribute('data-theme',a);}},60000);})();"

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
        radial-gradient(900px 620px at 50% 108%, rgba(63, 185, 80, 0.06), transparent 66%);
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
html {
    -webkit-text-size-adjust: 100%;
    text-size-adjust: 100%;
    scrollbar-gutter: stable;
}
body {
    margin: 0;
    display: flex;
    isolation: isolate;
    min-height: 100vh;
    min-height: 100svh;
    padding-bottom: env(safe-area-inset-bottom, 0px);
    padding-left: env(safe-area-inset-left, 0px);
    padding-right: env(safe-area-inset-right, 0px);
    overflow-x: clip;
    font-family: var(--font-sans);
    font-size: 16px;
    line-height: 1.6;
    color: var(--text);
    background-color: var(--bg);
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}
@supports not (overflow: clip) {
    body { overflow-x: hidden; }
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
    background-size: auto;
}
body::after {
    background-image:
        linear-gradient(to right, var(--grid-line) 1px, transparent 1px),
        linear-gradient(to bottom, var(--grid-line) 1px, transparent 1px);
    background-size: 52px 52px;
    opacity: 0.75;
    -webkit-mask-image: linear-gradient(to bottom, #000 0%, rgba(0, 0, 0, 0.55) 24%, transparent 70%);
    mask-image: linear-gradient(to bottom, #000 0%, rgba(0, 0, 0, 0.55) 24%, transparent 70%);
}
@supports not ((-webkit-mask-image: none) or (mask-image: none)) {
    body::after { opacity: 0.55; }
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
    transition: background 0.3s ease, border-color 0.3s ease;
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
.search-form .btn { flex: none; height: 46px; padding: 0 20px; border-radius: 11px; white-space: nowrap; }
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

.form-hint {
    margin: 10px 2px 0;
    color: var(--text-dim);
    font-size: 0.78rem;
    line-height: 1.55;
    text-align: center;
}
.form-hint.is-error { color: var(--danger); }
.switch-row {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 9px;
    margin-top: 14px;
    color: var(--text-dim);
    font-size: 0.82rem;
    cursor: pointer;
    user-select: none;
    -webkit-user-select: none;
}
.switch-row input {
    position: absolute;
    width: 1px;
    height: 1px;
    opacity: 0;
    pointer-events: none;
}
.switch {
    position: relative;
    flex: none;
    width: 38px;
    height: 22px;
    border: 1px solid var(--border);
    border-radius: 999px;
    background: var(--surface-2);
    transition: background 0.2s ease, border-color 0.2s ease;
}
.switch::after {
    content: "";
    position: absolute;
    top: 2px;
    left: 2px;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: var(--text-faint);
    transition: transform 0.2s ease, background 0.2s ease;
}
.switch-row:hover .switch { border-color: var(--border-strong); }
.switch-row input:checked + .switch { background: var(--accent-soft); border-color: var(--accent); }
.switch-row input:checked + .switch::after { transform: translateX(16px); background: var(--accent); }
.switch-row input:focus-visible + .switch { outline: 2px solid var(--accent); outline-offset: 2px; }

.modal {
    position: fixed;
    inset: 0;
    z-index: 80;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px 16px;
}
.modal[hidden] { display: none; }
.modal-backdrop {
    position: absolute;
    inset: 0;
    background: rgba(1, 4, 9, 0.62);
    backdrop-filter: blur(3px);
    -webkit-backdrop-filter: blur(3px);
}
html[data-theme="light"] .modal-backdrop { background: rgba(31, 35, 40, 0.38); }
.modal-panel {
    position: relative;
    display: flex;
    flex-direction: column;
    width: min(720px, 100%);
    max-height: min(82vh, 760px);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg);
    box-shadow: 0 28px 70px rgba(0, 0, 0, 0.5);
    overflow: hidden;
    animation: modalIn 0.18s ease;
}
html[data-theme="light"] .modal-panel { background: #fff; }
@keyframes modalIn {
    from { opacity: 0; transform: translateY(10px) scale(0.99); }
    to { opacity: 1; transform: none; }
}
.modal-head {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 16px 18px;
    border-bottom: 1px solid var(--border);
}
.modal-title-wrap { flex: 1 1 auto; min-width: 0; }
.modal-title {
    color: var(--text);
    font-size: 0.98rem;
    font-weight: 700;
    line-height: 1.45;
    word-break: break-all;
}
.modal-sub {
    margin-top: 3px;
    color: var(--text-faint);
    font-family: var(--font-mono);
    font-size: 0.74rem;
    word-break: break-all;
}
.modal-close {
    flex: none;
    width: 32px;
    height: 32px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: 1px solid var(--border);
    border-radius: 50%;
    background: var(--surface-2);
    color: var(--text-dim);
    font-size: 18px;
    line-height: 1;
    cursor: pointer;
    transition: color 0.15s ease, border-color 0.15s ease, background 0.15s ease;
}
.modal-close:hover { color: var(--text); border-color: var(--border-strong); background: var(--surface-3); }
.modal-body {
    padding: 4px 18px 18px;
    overflow-y: auto;
    overscroll-behavior: contain;
    scrollbar-width: thin;
    scrollbar-color: var(--scrollbar-thumb) var(--scrollbar-track);
}
.modal-body::-webkit-scrollbar { width: 8px; }
.modal-body::-webkit-scrollbar-track { background: var(--scrollbar-track); }
.modal-body::-webkit-scrollbar-thumb { background: var(--scrollbar-thumb); border-radius: 999px; }
.modal-state { padding: 36px 12px; text-align: center; color: var(--text-dim); font-size: 0.85rem; }
.modal-state.error { color: var(--danger); }
.release-item { padding: 14px 0; border-bottom: 1px solid var(--border); }
.release-item:last-of-type { border-bottom: none; }
.release-top { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.release-tag {
    color: var(--accent);
    font-family: var(--font-mono);
    font-size: 0.84rem;
    font-weight: 700;
}
.release-name { color: var(--text); font-size: 0.88rem; font-weight: 600; }
.badge {
    padding: 1px 8px;
    border-radius: 999px;
    font-size: 0.68rem;
    font-weight: 700;
    line-height: 1.7;
}
.badge-latest { background: var(--accent-soft); color: var(--accent); }
.badge-pre { background: rgba(210, 153, 34, 0.16); color: #d29922; }
html[data-theme="light"] .badge-pre { color: #9a6700; }
.release-meta { margin-top: 5px; color: var(--text-faint); font-size: 0.74rem; }
.release-body {
    margin-top: 8px;
    color: var(--text-dim);
    font-size: 0.8rem;
    line-height: 1.7;
    white-space: pre-wrap;
    word-break: break-word;
    overflow-wrap: anywhere;
}
.release-body.clamped { max-height: 7.5em; overflow: hidden; }
.release-actions { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 8px; }
.release-toggle {
    padding: 0;
    border: none;
    background: none;
    color: var(--accent);
    font: inherit;
    font-size: 0.76rem;
    cursor: pointer;
}
.release-assets { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
.asset-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    max-width: 100%;
    padding: 4px 10px;
    border: 1px solid var(--border);
    border-radius: 999px;
    background: var(--surface-2);
    color: var(--text-dim);
    font-size: 0.74rem;
    transition: color 0.15s ease, border-color 0.15s ease, background 0.15s ease;
}
.asset-chip:hover { color: var(--text); border-color: var(--border-strong); background: var(--surface-3); }
.asset-chip span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.asset-size { flex: none; color: var(--text-faint); font-size: 0.7rem; font-style: normal; }
.modal-foot {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: center;
    gap: 10px;
    padding: 16px 0 4px;
}
.modal-foot .modal-state { padding: 0; }
body.modal-open { overflow: hidden; }
@media (max-width: 520px) {
    .search-form .btn { padding: 0 14px; font-size: 0.84rem; }
    .modal { padding: 10px 8px; }
    .modal-panel { max-height: 90vh; }
    .modal-head { padding: 14px; }
    .modal-body { padding: 2px 14px 14px; }
}
@media (max-width: 520px), (prefers-reduced-transparency: reduce) {
    .card,
    .theme-toggle {
        -webkit-backdrop-filter: none;
        backdrop-filter: none;
    }
    .card { background: var(--bg); }
    html[data-theme="light"] .card { background: #fff; }
    .theme-toggle { background: var(--bg); }
}

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
    .field { height: 48px; font-size: 16px; }
}
@media (prefers-reduced-motion: reduce) {
    .brand { animation: none; }
    .modal-panel { animation: none; }
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
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#0d1117" media="(prefers-color-scheme: dark)">
<meta name="theme-color" content="#eef2f7" media="(prefers-color-scheme: light)">
<title>GitHub 加速代理</title>
<script>${THEME_BOOT_JS}</script>
<style>${PAGE_BASE_CSS}${HOME_CSS}</style>
</head>
<body>
<button id="themeToggle" class="theme-toggle" type="button" title="切换白天/夜间模式（双击恢复自动切换）" aria-label="切换白天/夜间模式">${ICON_SUN}${ICON_MOON}</button>

<main class="shell">
    <section class="card hero">
        <div class="brand" aria-hidden="true">${ICON_GITHUB}</div>
        <h1 class="title">GitHub 加速代理</h1>

        <form id="searchForm" class="search-form" autocomplete="off">
            <input id="searchInput" class="field" type="text" name="q" placeholder="粘贴 GitHub 链接" required spellcheck="false" aria-label="GitHub 链接">
            <button id="submitBtn" class="btn btn-primary" type="submit"><span id="submitLabel">Go</span>${ICON_ARROW}</button>
        </form>
        <p id="formHint" class="form-hint" role="status" aria-live="polite" hidden></p>

        <label class="switch-row" for="releaseModeToggle" title="开启后，粘贴 GitHub 仓库链接点「获取列表」会列出 Release；Release 文件直链仍直接下载">
            <input id="releaseModeToggle" type="checkbox" role="switch" aria-label="Release 列表模式">
            <span class="switch" aria-hidden="true"></span>
            <span>Release 列表模式</span>
        </label>

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

<div id="releaseModal" class="modal" hidden>
    <div class="modal-backdrop" data-close-modal></div>
    <div class="modal-panel" role="dialog" aria-modal="true" aria-labelledby="releaseTitle">
        <div class="modal-head">
            <div class="modal-title-wrap">
                <div id="releaseTitle" class="modal-title">Release 列表</div>
                <div id="releaseSub" class="modal-sub"></div>
            </div>
            <button id="releaseClose" class="modal-close" type="button" data-close-modal aria-label="关闭">×</button>
        </div>
        <div id="releaseBody" class="modal-body"></div>
    </div>
</div>

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
            // Release 列表模式：能识别为仓库链接时打开浮窗，否则继续按原逻辑跳转。
            if (window.GHReleaseMode && window.GHReleaseMode.enabled() &&
                window.GHReleaseMode.open(val) === true) {
                return;
            }
            if (!/^https?:\\/\\//i.test(val)) val = 'https://' + val;
            saveHistory(val);
            window.location.href = targetUrl(val);
        });
    }

    renderHistory();
})();
</script>
<script>(${releaseModeClient})();</script>
<script>${THEME_TOGGLE_JS}</script>
</body>
</html>`
    return new Response(html, {
        status: 200,
        headers: {
            'content-type': 'text/html; charset=utf-8',
            // 首页是纯静态模板，浏览器强缓存后刷新不再产生 Worker 请求，直接省每日额度。
            'cache-control': `public, max-age=${CONFIG.INDEX_TTL}`,
            ...CORS_HEADERS,
            ...SECURITY_HEADERS
        }
    })
}
