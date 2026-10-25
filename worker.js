'use strict'

const CONFIG = {
    PREFIX: '/',
    CACHE_TTL: 604800,
    MAX_CACHE_SIZE: 250 * 1024 * 1024,
    RATE_LIMIT_WINDOW: 30,
    RATE_LIMIT_MAX: 50,
    IS_PRODUCTION: true,
    ARTIFACT_META_TTL_ANON: 300,
    ARTIFACT_META_TTL_AUTH: 60,
}

const GITHUB_PATTERNS = [
    /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:releases|archive|tags|info|git-)\/.*$/i,
    /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:blob|raw)\/.*$/i,
    /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/actions\/runs\/\d+\/artifacts\/\d+(?:\/.*)?$/i,
    /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/suites\/\d+\/artifacts\/\d+(?:\/.*)?$/i,
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

function parseArtifactPath(pathname) {
    let url
    try {
        url = new URL(pathname.startsWith('http') ? pathname : `https://${pathname}`)
    } catch { return null }

    const host = url.hostname.toLowerCase()
    const path = url.pathname
    let match

    if (host === 'github.com') {
        match = path.match(/^\/([^/]+)\/([^/]+)\/(?:actions\/runs|suites)\/[^/]+\/artifacts\/(\d+)(?:\/.*)?$/)
        if (match) {
            return { owner: match[1], repo: match[2], artifactId: match[3], source: 'web' }
        }
        return null
    }

    if (host === 'api.github.com') {
        match = path.match(/^\/repos\/([^/]+)\/([^/]+)\/actions\/artifacts\/(\d+)(?:\/zip)?\/?$/)
        if (match) {
            return { owner: match[1], repo: match[2], artifactId: match[3], source: 'api' }
        }
    }

    return null
}

function readServerToken() {
    try {
        if (typeof GITHUB_TOKEN !== 'undefined' && GITHUB_TOKEN) return String(GITHUB_TOKEN).trim()
    } catch {}
    try {
        const token = globalThis.GITHUB_TOKEN
        if (token) return String(token).trim()
    } catch {}
    return ''
}

function getArtifactToken(req) {
    const authHeader = req.headers.get('authorization')
    if (authHeader && authHeader.trim()) {
        const match = authHeader.match(/^(?:Bearer|token)\s+(.+)$/i)
        return (match ? match[1] : authHeader).trim()
    }

    const altHeader = req.headers.get('x-github-token')
    if (altHeader && altHeader.trim()) return altHeader.trim()

    const reqUrlObj = new URL(req.url)
    const fromQuery = reqUrlObj.searchParams.get('token')
    if (fromQuery && fromQuery.trim()) return fromQuery.trim()

    return readServerToken()
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

    const rateLimited = await checkRateLimit(req, e)
    if (rateLimited) return rateLimited

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
        const artifact = parseArtifactPath(pathname)

        if (artifact) {
            return handleArtifactRequest(req, artifact)
        }

        const targetUrl = pathname.startsWith('http') ? pathname : `https://${pathname}`
        const urlObj = newUrl(targetUrl)
        if (!urlObj) return makeRes('Invalid target URL', 400)

        const isApiTarget = urlObj.hostname.toLowerCase() === 'api.github.com'
        const cacheable = !isApiTarget

        const cache = caches.default
        const cacheKey = buildCacheKey(pathname)
        const dynamicCors = getDynamicCorsHeaders(req, pathname)

        const isRangeRequest = !!req.headers.get('range')

        if (cacheable && req.method === 'GET' && !isRangeRequest) {
            const cached = await cache.match(cacheKey)
            if (cached) {
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
            /\/actions\/runs\/\d+\/artifacts\//
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

function escapeHtml(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, ch => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[ch]))
}

function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes < 0) return '未知'
    if (bytes < 1024) return `${bytes} B`
    const units = ['KB', 'MB', 'GB', 'TB']
    let value = bytes / 1024
    let index = 0
    while (value >= 1024 && index < units.length - 1) {
        value /= 1024
        index++
    }
    return `${value >= 100 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`
}

function artifactContentDisposition(filename) {
    const name = String(filename || 'artifact.zip')
    const safeName = name
        .replace(/[\\\r\n"]/g, '_')
        .replace(/[^\x20-\x7E]/g, '_')
    const encoded = encodeURIComponent(name)
        .replace(/['()!*]/g, ch => '%' + ch.charCodeAt(0).toString(16).toUpperCase())
    return `attachment; filename="${safeName}"; filename*=UTF-8''${encoded}`
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
    --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, "PingFang SC", "Microsoft YaHei", sans-serif;
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
    --bg-grad-1: hsla(253, 16%, 7%, 1);
    --bg-grad-2: hsla(225, 39%, 30%, 1);
    --bg-grad-3: hsla(339, 49%, 30%, 1);
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
    --bg-grad-1: hsla(210, 100%, 94%, 1);
    --bg-grad-2: hsla(212, 95%, 84%, 1);
    --bg-grad-3: hsla(330, 85%, 90%, 1);
    color-scheme: light;
}

*, *::before, *::after { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
    margin: 0;
    min-height: 100vh;
    font-family: var(--font-sans);
    color: var(--text);
    background-color: var(--bg);
    background-image:
        radial-gradient(at 0% 0%, var(--bg-grad-1) 0, transparent 50%),
        radial-gradient(at 50% 0%, var(--bg-grad-2) 0, transparent 50%),
        radial-gradient(at 100% 0%, var(--bg-grad-3) 0, transparent 50%);
    background-size: 200% 200%;
    animation: bgShift 18s ease infinite;
    -webkit-font-smoothing: antialiased;
    transition: color 0.3s ease, background-color 0.3s ease;
}
@keyframes bgShift {
    0% { background-position: 0% 50%; }
    50% { background-position: 100% 50%; }
    100% { background-position: 0% 50%; }
}
@media (prefers-reduced-motion: reduce) {
    body { animation: none; }
}
h1, h2, h3, p, dl, dd, ul { margin: 0; }
ul { padding: 0; list-style: none; }
a { color: var(--accent); text-decoration: none; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
::selection { background: var(--accent-soft); }

.card {
    background: var(--surface);
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-card);
    transition: background 0.3s ease, border-color 0.3s ease, box-shadow 0.3s ease;
}

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
.btn:disabled { opacity: 0.55; cursor: not-allowed; }
.btn-primary { background: var(--accent); border-color: transparent; color: #fff; }
.btn-primary:hover { background: var(--accent); border-color: transparent; filter: brightness(1.08); }

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
.field:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-soft);
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
    top: 16px;
    right: 16px;
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
.theme-toggle:hover { transform: scale(1.06); border-color: var(--border-strong); color: var(--accent); }
.theme-toggle svg { position: absolute; width: 18px; height: 18px; transition: opacity 0.22s ease, transform 0.22s ease; }
.theme-toggle .icon-sun { opacity: 1; transform: rotate(0deg) scale(1); }
.theme-toggle .icon-moon { opacity: 0; transform: rotate(-90deg) scale(0.5); }
html[data-theme="light"] .theme-toggle .icon-sun { opacity: 0; transform: rotate(90deg) scale(0.5); }
html[data-theme="light"] .theme-toggle .icon-moon { opacity: 1; transform: rotate(0deg) scale(1); }
`

const ARTIFACT_CSS = `
.page-artifact { display: flex; padding: 72px 20px 40px; }
.artifact-wrap { width: 100%; max-width: 640px; margin: auto; }
.artifact-card { padding: 32px; }
.artifact-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 48px;
    height: 48px;
    margin: 0 auto 16px;
    border-radius: 14px;
    background: var(--accent-soft);
    font-size: 22px;
    line-height: 1;
}
.artifact-card h1 { font-size: 1.25rem; line-height: 1.4; text-align: center; color: var(--text); }
.artifact-lead { max-width: 48ch; margin: 10px auto 20px; text-align: center; color: var(--text-dim); font-size: 0.9rem; line-height: 1.7; }
.meta-grid {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    gap: 8px 16px;
    padding: 14px 16px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-2);
    font-size: 0.85rem;
}
.meta-grid dt { color: var(--text-dim); white-space: nowrap; }
.meta-grid dd { color: var(--text); font-weight: 600; word-break: break-all; }
.section {
    display: flex;
    flex-direction: column;
    gap: 10px;
    margin-top: 16px;
    padding: 16px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--surface-2);
}
.section-title { display: flex; align-items: center; gap: 8px; color: var(--text); font-size: 0.88rem; font-weight: 600; }
.step-num {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: none;
    width: 20px;
    height: 20px;
    border-radius: 50%;
    background: var(--accent-soft);
    color: var(--accent);
    font-size: 0.72rem;
    font-weight: 700;
}
.row { display: flex; flex-wrap: wrap; gap: 10px; }
.row .field { flex: 1 1 200px; min-width: 0; height: 42px; }
.hint { color: var(--text-dim); font-size: 0.8rem; line-height: 1.65; }
.status { min-height: 1.2em; color: var(--accent); font-size: 0.82rem; line-height: 1.5; }
.status.is-error { color: var(--danger); }
.artifact-actions { display: flex; justify-content: center; margin-top: 20px; }
@media (max-width: 600px) {
    .page-artifact { padding: 72px 16px 32px; }
    .artifact-card { padding: 24px 18px; }
}
`

function artifactPageShell(title, content) {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${escapeHtml(title)} · GitHub 加速代理</title>
<script>${THEME_BOOT_JS}</script>
<style>${PAGE_BASE_CSS}${ARTIFACT_CSS}</style>
</head>
<body class="page-artifact">
<button id="themeToggle" class="theme-toggle" type="button" title="切换白天/夜间模式（双击恢复按时间自动切换）" aria-label="切换白天/夜间模式">${ICON_SUN}${ICON_MOON}</button>
<main class="artifact-wrap">
    <div class="card artifact-card">
        ${content}
    </div>
</main>
<script>${THEME_TOGGLE_JS}</script>
</body>
</html>`
}

function buildArtifactHelpHTML(info) {
    const name = escapeHtml(info.name)
    const runUrl = info.runId
        ? `https://github.com/${info.owner}/${info.repo}/actions/runs/${info.runId}/artifacts/${info.artifactId}`
        : `https://github.com/${info.owner}/${info.repo}/actions`
    const ghCommand = info.runId
        ? `gh run download ${info.runId} -R ${info.owner}/${info.repo} -n "${info.name}"`
        : `gh run download -R ${info.owner}/${info.repo} -n "${info.name}"`

    const content = `
<div class="artifact-icon" aria-hidden="true">🔐</div>
<h1>Artifact 需要 GitHub 认证</h1>
<p class="artifact-lead">GitHub 对 Actions Artifact 的下载强制要求认证。代理无法读取你浏览器里的 GitHub 登录状态，因此需要提供一个 Token。</p>

<dl class="meta-grid">
    <dt>文件</dt><dd>${name}</dd>
    <dt>大小</dt><dd>${formatBytes(info.size)}</dd>
    <dt>Artifact ID</dt><dd>${escapeHtml(info.artifactId)}</dd>
</dl>

<div class="section">
    <div class="section-title"><span class="step-num">1</span>输入 GitHub Token 直接下载</div>
    <div class="row">
        <input id="gh-token" class="field" type="password" placeholder="ghp_... 或 github_pat_..." autocomplete="off" spellcheck="false" aria-label="GitHub Token">
        <button id="gh-download" class="btn btn-primary" type="button">下载</button>
    </div>
    <p id="gh-status" class="status" role="status" aria-live="polite"></p>
    <p class="hint">Token 只发送给本代理并转发到 api.github.com，不会写入 URL。建议使用 fine-grained Token，仅勾选 Actions: Read，用完即撤销。</p>
</div>

<div class="section">
    <div class="section-title"><span class="step-num">2</span>本地使用 GitHub CLI</div>
    <pre class="code-block">${escapeHtml(ghCommand)}</pre>
</div>

<div class="section">
    <div class="section-title"><span class="step-num">3</span>站点管理员配置服务端 Token</div>
    <p class="hint">在 Cloudflare Worker 添加 Secret <code class="code-inline">GITHUB_TOKEN</code>（fine-grained，仅 Actions: Read）后，公开仓库的 Artifact 可直接下载，用户无需输入。</p>
</div>

<div class="artifact-actions">
    <a class="btn" href="${escapeHtml(runUrl)}" target="_blank" rel="noopener">在 GitHub 打开</a>
</div>
<script>
(function () {
    var input = document.getElementById('gh-token');
    var button = document.getElementById('gh-download');
    var status = document.getElementById('gh-status');
    if (!input || !button || !status) return;

    function setStatus(text, isError) {
        status.textContent = text;
        status.classList.toggle('is-error', !!isError);
    }

    function start() {
        var token = (input.value || '').trim();
        if (!token) { setStatus('请先填写 GitHub Token', true); input.focus(); return; }
        button.disabled = true;
        setStatus('正在向 GitHub 请求…', false);
        fetch(location.href, { headers: { 'Authorization': 'Bearer ' + token } })
            .then(function (res) {
                if (!res.ok) {
                    return res.text().then(function (text) {
                        var msg = text;
                        try { var data = JSON.parse(text); msg = data.detail || data.error || text; } catch (e) {}
                        setStatus('下载失败（' + res.status + '）：' + String(msg).slice(0, 200), true);
                    });
                }
                setStatus('正在接收文件…', false);
                return res.blob().then(function (blob) {
                    var filename = res.headers.get('x-artifact-name') || 'artifact.zip';
                    try { filename = decodeURIComponent(filename); } catch (e) {}
                    var url = URL.createObjectURL(blob);
                    var link = document.createElement('a');
                    link.href = url;
                    link.download = filename;
                    document.body.appendChild(link);
                    link.click();
                    link.remove();
                    setTimeout(function () { URL.revokeObjectURL(url); }, 20000);
                    setStatus('已开始下载：' + filename, false);
                });
            })
            .catch(function (err) { setStatus('下载失败：' + (err && err.message ? err.message : err), true); })
            .then(function () { button.disabled = false; });
    }

    button.addEventListener('click', start);
    input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); start(); }
    });
})();
</script>`

    return artifactPageShell('Artifact 需要 GitHub 认证', content)
}

function buildArtifactErrorHTML(info, status, title, detail) {
    const content = `
<div class="artifact-icon" aria-hidden="true">⚠️</div>
<h1>${escapeHtml(title)}</h1>
<p class="artifact-lead">${escapeHtml(detail || '')}</p>

<dl class="meta-grid">
    <dt>状态码</dt><dd>${escapeHtml(status)}</dd>
    <dt>文件</dt><dd>${escapeHtml(info.name)}</dd>
    <dt>Artifact ID</dt><dd>${escapeHtml(info.artifactId)}</dd>
</dl>

<div class="artifact-actions">
    <a class="btn" href="https://github.com/${escapeHtml(info.owner)}/${escapeHtml(info.repo)}/actions" target="_blank" rel="noopener">打开仓库 Actions</a>
</div>`

    return artifactPageShell(title, content)
}

function wantsHtml(req) {
    const accept = (req.headers.get('accept') || '').toLowerCase()
    return accept.includes('text/html')
}

function artifactErrorResponse(req, status, title, detail, info) {
    if (!wantsHtml(req)) {
        const payload = {
            error: title,
            detail,
            status,
            artifact: info ? {
                id: info.artifactId,
                name: info.name,
                size_in_bytes: info.size,
                digest: info.digest || undefined,
                expired: !!info.expired,
            } : undefined,
        }
        return makeRes(JSON.stringify(payload), status, {
            'content-type': 'application/json; charset=utf-8',
            'cache-control': 'no-store',
        })
    }

    return new Response(buildArtifactErrorHTML(info || { name: '', artifactId: '', owner: '', repo: '' }, status, title, detail), {
        status,
        headers: {
            'content-type': 'text/html; charset=utf-8',
            ...CORS_HEADERS,
            ...SECURITY_HEADERS,
            'cache-control': 'no-store',
        },
    })
}

function artifactHelpResponse(req, info) {
    if (!wantsHtml(req)) {
        return makeRes(JSON.stringify({
            error: 'authentication_required',
            message: 'GitHub Actions artifacts require authentication. Configure the GITHUB_TOKEN secret on this worker, or send "Authorization: Bearer <token>" / "?token=<token>".',
            artifact: info ? {
                id: info.artifactId,
                name: info.name,
                size_in_bytes: info.size,
                digest: info.digest || undefined,
                expired: !!info.expired,
            } : undefined,
        }), 401, {
            'content-type': 'application/json; charset=utf-8',
            'cache-control': 'no-store',
            'www-authenticate': 'Bearer',
        })
    }

    return new Response(buildArtifactHelpHTML(info || { name: '', artifactId: '', owner: '', repo: '' }), {
        status: 200,
        headers: {
            'content-type': 'text/html; charset=utf-8',
            ...CORS_HEADERS,
            ...SECURITY_HEADERS,
            'cache-control': 'no-store',
        },
    })
}

async function fetchArtifactMetadata(owner, repo, artifactId, token) {
    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/actions/artifacts/${artifactId}`
    const headers = {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'CF-GH-Proxy',
    }
    if (token) headers['Authorization'] = `Bearer ${token}`

    // 匿名与带 token 的元数据必须分开缓存：私有仓库用 token 才能看到，
    // 若共用键会把私有仓库的 artifact 名字/大小泄露给匿名请求。
    const cache = caches.default
    const metaKey = new Request(
        `https://cf-gh-proxy.internal/artifact-meta/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${artifactId}?auth=${token ? '1' : '0'}`,
        { method: 'GET' }
    )
    const ttl = token ? CONFIG.ARTIFACT_META_TTL_AUTH : CONFIG.ARTIFACT_META_TTL_ANON

    try {
        const cached = await cache.match(metaKey)
        if (cached) {
            const data = await cached.json().catch(() => null)
            const status = parseInt(cached.headers.get('x-meta-status') || '200', 10)
            return {
                res: {
                    ok: status >= 200 && status < 300,
                    status,
                    headers: new Headers(),
                },
                data,
                cached: true,
            }
        }
    } catch (err) {
        console.warn('Artifact metadata cache read failed:', err)
    }

    try {
        const res = await fetch(apiUrl, { method: 'GET', headers, redirect: 'follow' })
        let data = null
        try { data = await res.json() } catch {}

        // 只缓存确定性的结果：成功，或 404（仓库/artifact 不存在）。
        // 401/403 往往和 token 本身相关，且 403 可能是限流，缓存会放大问题。
        if (res.ok || res.status === 404) {
            const storeHeaders = new Headers({
                'content-type': 'application/json; charset=utf-8',
                'cache-control': `public, max-age=${ttl}`,
                'x-meta-status': String(res.status),
            })
            const body = JSON.stringify(data)
            try {
                await cache.put(metaKey, new Response(body, { status: 200, headers: storeHeaders }))
            } catch (err) {
                console.warn('Artifact metadata cache write failed:', err)
            }
        }

        return { res, data, cached: false }
    } catch (err) {
        console.error('Artifact metadata fetch failed:', err)
        return { res: null, data: null, error: err }
    }
}

function isRateLimitedResponse(res, data) {
    if (!res) return false
    const remaining = res.headers ? res.headers.get('x-ratelimit-remaining') : null
    if (remaining !== null && remaining !== undefined && String(remaining).trim() === '0') return true
    const message = data && typeof data === 'object' ? String(data.message || '') : ''
    return /rate limit|secondary rate/i.test(message)
}

function rateLimitResetHint(res) {
    try {
        const reset = res && res.headers ? res.headers.get('x-ratelimit-reset') : null
        if (!reset || !/^\d+$/.test(String(reset).trim())) return ''
        const resetAt = new Date(Number(reset) * 1000)
        if (Number.isNaN(resetAt.getTime())) return ''
        return `额度预计在 ${resetAt.toISOString().replace('T', ' ').slice(0, 16)} UTC 重置。`
    } catch {
        return ''
    }
}

async function fetchArtifactZip(downloadUrl, token) {
    let url = downloadUrl
    let headers = {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'CF-GH-Proxy',
    }
    if (token) headers['Authorization'] = `Bearer ${token}`

    for (let i = 0; i < 5; i++) {
        const res = await fetch(url, { method: 'GET', headers, redirect: 'manual' })

        if (![301, 302, 303, 307, 308].includes(res.status)) return res

        const location = res.headers.get('location')
        if (!location) return res

        let nextUrl
        try { nextUrl = new URL(location, url) } catch { return res }

        const nextHost = nextUrl.hostname.toLowerCase()
        const isSafe = SAFE_REDIRECT_HOSTS.has(nextHost) ||
            isSafeAzureRedirect(nextHost) ||
            GITHUB_PATTERNS.some(p => p.test(nextUrl.href))

        if (!isSafe) return res

        if (nextHost !== 'api.github.com' && headers['Authorization']) {
            headers = { ...headers }
            delete headers['Authorization']
        }

        url = nextUrl.href
    }

    return makeRes('Too many redirects while fetching artifact', 508)
}

function artifactMetadataError(req, metaRes, meta, info) {
    if (metaRes.status === 403) {
        if (isRateLimitedResponse(metaRes, meta)) {
            const resetAt = rateLimitResetHint(metaRes)
            return artifactErrorResponse(req, 403, 'GitHub API 限流',
                `GitHub 未认证 API 每小时只有 60 次额度，且与同一出口 IP 的其他请求共享。请稍后重试，或在 Worker 上配置 GITHUB_TOKEN 提高额度。${resetAt}`, info)
        }
        return artifactErrorResponse(req, 403, 'GitHub Token 无权限',
            'Token 有效但缺少该仓库的 Actions 读取权限（fine-grained 需要 Actions: Read）。', info)
    }

    if (metaRes.status === 401) {
        return artifactErrorResponse(req, 401, 'GitHub Token 无效',
            '请确认 Token 未过期或未被撤销。', info)
    }

    return artifactErrorResponse(req, 404, 'Artifact 不存在',
        '可能是仓库或 Artifact ID 错误，或当前 Token 无权访问该仓库。', info)
}

async function handleArtifactRequest(req, artifact) {
    const { owner, repo, artifactId } = artifact
    const token = getArtifactToken(req)

    const { res: metaRes, data: meta } = await fetchArtifactMetadata(owner, repo, artifactId, token)
    const metaOk = !!(metaRes && metaRes.ok && meta && typeof meta === 'object')

    const info = {
        owner,
        repo,
        artifactId,
        name: (metaOk && meta.name) ? String(meta.name) : `${repo}-artifact-${artifactId}.zip`,
        size: (metaOk && Number.isFinite(meta.size_in_bytes)) ? meta.size_in_bytes : null,
        digest: (metaOk && meta.digest) ? String(meta.digest) : '',
        expired: !!(metaOk && meta.expired === true),
        runId: (metaOk && meta.workflow_run && meta.workflow_run.id) ? meta.workflow_run.id : null,
    }

    if (info.expired) {
        return artifactErrorResponse(req, 410, 'Artifact 已过期',
            '该 Actions Artifact 已超过 GitHub 的保留期并被删除，无法再下载。', info)
    }

    if (req.method === 'HEAD' && !token) {
        const headHeaders = new Headers({ 'cache-control': 'no-store', 'www-authenticate': 'Bearer' })
        applyCommonHeaders(headHeaders)
        return new Response(null, { status: 401, headers: headHeaders })
    }

    if (metaRes && (metaRes.status === 401 || metaRes.status === 403 || metaRes.status === 404)) {
        return artifactMetadataError(req, metaRes, meta, info)
    }

    if (!token) {
        return artifactHelpResponse(req, info)
    }

    const headers = new Headers({
        'content-type': 'application/zip',
        'content-disposition': artifactContentDisposition(info.name),
        'cache-control': 'no-store',
        'x-cache-status': 'ARTIFACT',
        'x-artifact-name': encodeURIComponent(info.name),
        'accept-ranges': 'none',
    })
    if (info.size !== null) headers.set('content-length', String(info.size))
    if (info.digest) headers.set('x-artifact-digest', info.digest)
    applyCommonHeaders(headers)

    if (req.method === 'HEAD') {
        return new Response(null, { status: 200, headers })
    }

    const downloadUrl = (metaOk && meta.archive_download_url)
        ? String(meta.archive_download_url)
        : `https://api.github.com/repos/${owner}/${repo}/actions/artifacts/${artifactId}/zip`

    let zipRes
    try {
        zipRes = await fetchArtifactZip(downloadUrl, token)
    } catch (err) {
        console.error('Artifact download failed:', err)
        return artifactErrorResponse(req, 502, '下载失败', String((err && err.message) || err), info)
    }

    if (!zipRes) {
        return artifactErrorResponse(req, 502, '下载失败', '上游没有返回响应。', info)
    }

    if ([301, 302, 303, 307, 308].includes(zipRes.status)) {
        return artifactErrorResponse(req, 401, '需要 GitHub 认证',
            '上游返回了登录跳转，Token 可能已失效或没有 Actions 读取权限。', info)
    }

    if (!zipRes.ok) {
        let detail = ''
        try { detail = (await zipRes.text()).slice(0, 500) } catch {}
        return artifactErrorResponse(req, zipRes.status, `GitHub API 返回 ${zipRes.status}`, detail, info)
    }

    const finalHeaders = new Headers(zipRes.headers)
    finalHeaders.delete('content-security-policy')
    finalHeaders.delete('clear-site-data')
    finalHeaders.delete('set-cookie')
    finalHeaders.delete('x-frame-options')
    finalHeaders.set('content-disposition', artifactContentDisposition(info.name))
    finalHeaders.set('cache-control', 'no-store')
    finalHeaders.set('x-cache-status', 'ARTIFACT')
    finalHeaders.set('x-artifact-name', encodeURIComponent(info.name))
    const upstreamLength = zipRes.headers.get('content-length')
    if (upstreamLength && /^\d+$/.test(upstreamLength)) {
        finalHeaders.set('content-length', upstreamLength)
    } else if (info.size !== null) {
        finalHeaders.set('content-length', String(info.size))
    }
    if (info.digest) finalHeaders.set('x-artifact-digest', info.digest)
    applyCommonHeaders(finalHeaders)

    return new Response(zipRes.body, { status: zipRes.status, headers: finalHeaders })
}

const HOME_CSS = `
.page-home { display: flex; }
.shell {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 340px;
    gap: 20px;
    align-items: start;
    width: 100%;
    max-width: 1000px;
    margin: auto;
    padding: 72px 20px 40px;
}
.hero { padding: 36px 32px; }
.brand {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 64px;
    height: 64px;
    margin: 0 auto 18px;
    border-radius: 16px;
    background: linear-gradient(135deg, var(--accent), #8250df);
    box-shadow: 0 10px 24px var(--accent-glow);
}
.brand svg { width: 32px; height: 32px; fill: #fff; }
.title {
    margin: 0;
    text-align: center;
    font-size: 2rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    background: linear-gradient(120deg, var(--title-grad-start), var(--title-grad-end));
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
}
@supports not ((-webkit-background-clip: text) or (background-clip: text)) {
    .title { color: var(--text); background: none; }
}
.subtitle {
    margin: 10px 0 0;
    text-align: center;
    color: var(--text-dim);
    font-size: 0.9rem;
    line-height: 1.6;
}
.search-form { display: flex; gap: 10px; margin-top: 26px; }
.search-form .field { flex: 1 1 auto; height: 48px; }
.search-form .btn { flex: none; height: 48px; padding: 0 20px; }
.search-form .btn svg { width: 16px; height: 16px; }
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
    padding: 0 14px;
    border: 1px solid var(--border);
    border-radius: 999px;
    background: var(--surface-2);
    color: var(--text-dim);
    font-size: 0.85rem;
    transition: background 0.18s ease, border-color 0.18s ease, color 0.18s ease;
}
.link-chip:hover { background: var(--surface-3); border-color: var(--border-strong); color: var(--text); }
.link-chip svg { width: 16px; height: 16px; flex: none; }
.foot {
    margin-top: 28px;
    padding-top: 16px;
    border-top: 1px solid var(--border);
    text-align: center;
    color: var(--text-faint);
    font-size: 0.78rem;
    line-height: 1.6;
}
.history-card { display: flex; flex-direction: column; padding: 20px; }
.panel-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border);
}
.panel-title { display: flex; align-items: center; gap: 8px; color: var(--text); font-size: 0.95rem; font-weight: 600; }
.panel-title svg { width: 18px; height: 18px; flex: none; color: var(--accent); }
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
    border-radius: var(--radius-sm);
    cursor: pointer;
    transition: background 0.18s ease, border-color 0.18s ease;
}
.history-item:hover, .history-item:focus-visible { background: var(--surface-2); border-color: var(--border); }
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
.history-arrow { flex: none; color: var(--text-faint); font-size: 0.85rem; line-height: 1; }
.history-url {
    margin-top: 4px;
    color: var(--text-faint);
    font-family: var(--font-mono);
    font-size: 0.72rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.history-time { margin-top: 5px; color: var(--text-faint); font-size: 0.72rem; }
.history-empty {
    padding: 28px 12px;
    border: 1px dashed var(--border);
    border-radius: var(--radius-md);
    text-align: center;
    color: var(--text-faint);
    font-size: 0.82rem;
}
@media (max-width: 900px) {
    .shell { grid-template-columns: minmax(0, 1fr); max-width: 620px; padding: 72px 16px 32px; }
    .hero { padding: 28px 22px; }
    .title { font-size: 1.65rem; }
}
@media (max-width: 520px) {
    .search-form { flex-direction: column; }
    .search-form .btn { width: 100%; }
}
`

function serveIndex() {
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
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
        <p class="subtitle">加速访问 Releases、Raw 文件、Actions Artifact 及 API 接口</p>

        <form id="searchForm" class="search-form" autocomplete="off">
            <input id="searchInput" class="field" type="text" name="q" placeholder="粘贴 GitHub 链接，例如 https://github.com/user/repo/releases/download/..." required spellcheck="false" aria-label="GitHub 链接">
            <button class="btn btn-primary" type="submit">加速访问${ICON_ARROW}</button>
        </form>

        <div class="links">
            <a class="link-chip" href="https://github.com/qfmc7040/CF-GH-Proxy/" target="_blank" rel="noopener">${ICON_GITHUB}项目源码</a>
            <a class="link-chip" href="https://github.akams.cn/" target="_blank" rel="noopener">${ICON_GLOBE}代理聚合</a>
        </div>

        <div class="foot">Powered by Cloudflare Workers · © QFMC</div>
    </section>

    <aside class="card history-card">
        <div class="panel-head">
            <div class="panel-title">${ICON_CLOCK}最近访问</div>
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
        if (!history.length) {
            var empty = document.createElement('li');
            empty.className = 'history-empty';
            empty.textContent = '暂无访问记录';
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
