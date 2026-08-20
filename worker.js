'use strict'

const CONFIG = {
    PREFIX: '/',
    CACHE_TTL: 604800,
    MAX_CACHE_SIZE: 300 * 1024 * 1024,
    RATE_LIMIT_WINDOW: 30,
    RATE_LIMIT_MAX: 50,
    IS_PRODUCTION: true,
}

const GITHUB_PATTERNS = [
    /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:releases|archive|tags|info|git-)\/.*$/i,
    /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:blob|raw)\/.*$/i,
    /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/actions\/runs\/\d+\/artifacts\/\d+(?:\/.*)?$/i,
    /^(?:https?:\/\/)?raw\.(?:githubusercontent|github)\.com\/.+?\/.+?\/.+?\/.+$/i,
    /^(?:https?:\/\/)?gist\.(?:githubusercontent|github)\.com\/.+?\/.+?\/.+$/i,
    /^(?:https?:\/\/)?api\.github\.com\/.*$/i,
    /^(?:https?:\/\/)?codeload\.github\.com\/.+?\/.+?\/(?:tar\.gz|zip|legacy\..*)$/i,
    /^(?:https?:\/\/)?objects\.githubusercontent\.com\/.*$/i,
    /^(?:https?:\/\/)?github\.githubassets\.com\/.*$/i,
    /^(?:https?:\/\/)?(?:copilot|actions)\.githubusercontent\.com\/.*$/i,
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
        'access-control-allow-headers': 'Content-Type, Authorization, Accept, X-Requested-With',
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

function isArtifactPath(pathname) {
    return /\/actions\/runs\/\d+\/artifacts\/\d+/.test(pathname)
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
        const isArtifact = isArtifactPath(pathname)
        const reqUrlObj = new URL(req.url)

        if (isArtifact) {
            const targetUrl = pathname.startsWith('http') ? pathname : `https://${pathname}`
            const targetUrlObj = newUrl(targetUrl)
            if (!targetUrlObj) return makeRes('Invalid target URL', 400)

            let token = reqUrlObj.searchParams.get('token')
            if (!token) {
                const authHeader = req.headers.get('authorization')
                if (authHeader) {
                    token = authHeader.replace(/^(Bearer|token)\s+/i, '')
                }
            }

            if (token) {
                const match = pathname.match(/github\.com\/([^/]+)\/([^/]+)\/actions\/runs\/\d+\/artifacts\/(\d+)/i)
                if (match) {
                    const [, owner, repo, artifactId] = match
                    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/actions/artifacts/${artifactId}/zip`
                    
                    try {
                        const apiRes = await fetch(apiUrl, {
                            method: 'GET',
                            headers: {
                                'Accept': 'application/vnd.github+json',
                                'Authorization': `Bearer ${token}`,
                                'X-GitHub-Api-Version': '2022-11-28',
                                'User-Agent': 'CF-GH-Proxy'
                            },
                            redirect: 'follow'
                        })

                        if (apiRes.ok) {
                            const finalHeaders = new Headers(apiRes.headers)
                            finalHeaders.delete('content-security-policy')
                            finalHeaders.delete('clear-site-data')
                            finalHeaders.delete('x-frame-options')
                            
                            applyCommonHeaders(finalHeaders)
                            finalHeaders.set('Content-Disposition', `attachment; filename="${repo}-artifact-${artifactId}.zip"`)
                            
                            return new Response(apiRes.body, {
                                status: apiRes.status,
                                headers: finalHeaders
                            })
                        } else {
                            const errText = await apiRes.text().catch(() => 'Unknown error')
                            return makeRes(`GitHub API Error: ${apiRes.status} - ${errText}`, apiRes.status)
                        }
                    } catch (apiErr) {
                        console.error('Artifact API fetch failed:', apiErr)
                    }
                }
            }

            return new Response(buildArtifactFallbackHTML(targetUrl), {
                status: 200,
                headers: {
                    'content-type': 'text/html; charset=utf-8',
                    ...CORS_HEADERS,
                    ...SECURITY_HEADERS,
                    'Cache-Control': 'no-store',
                }
            })
        }

        const cache = caches.default
        const cacheKey = buildCacheKey(pathname)
        const dynamicCors = getDynamicCorsHeaders(req, pathname)

        if (req.method === 'GET') {
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

        const targetUrl = pathname.startsWith('http') ? pathname : `https://${pathname}`
        const urlObj = newUrl(targetUrl)
        if (!urlObj) return makeRes('Invalid target URL', 400)

        const reqHdrNew = new Headers(req.headers)
        reqHdrNew.delete('cookie')
        reqHdrNew.delete('authorization')
        reqHdrNew.delete('host')
        
        const rangeHeader = req.headers.get('range')
        if (rangeHeader) reqHdrNew.set('range', rangeHeader)

        const response = await handleProxyFetch(urlObj, {
            method: req.method, 
            headers: reqHdrNew, 
            redirect: 'manual',
            body: req.body,
            cf: { 
                cacheEverything: true, 
                cacheTtlByStatus: { "200-299": CONFIG.CACHE_TTL, "301-302": 3600, "404": 1 } 
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
                     
                     e.waitUntil(cache.put(cacheKey, new Response(null, {
                         status: response.status,
                         headers: redirHeaders
                     })).catch(err => console.warn('Cache redirect failed', err)))
                     
                     return new Response(null, { status: response.status, headers: redirHeaders })
                 }
             }
        }

        if (!response.ok && response.status !== 304 && response.status !== 206) {
            const errHeaders = new Headers(response.headers)
            applyCommonHeaders(errHeaders)
            for (const [k, v] of Object.entries(dynamicCors)) errHeaders.set(k, v)
            return new Response(response.body, { status: response.status, headers: errHeaders })
        }

        if (req.method === 'GET' && response.status >= 200 && response.status < 400) {
            const contentLength = parseInt(response.headers.get('content-length') || '0', 10)
            const shouldCache = contentLength > 0 && contentLength <= CONFIG.MAX_CACHE_SIZE
            
            const finalHeaders = new Headers(response.headers)
            applyCommonHeaders(finalHeaders)
            for (const [k, v] of Object.entries(dynamicCors)) finalHeaders.set(k, v)

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
                finalHeaders.set('x-cache-status', contentLength > CONFIG.MAX_CACHE_SIZE ? 'BYPASS-LARGE' : 'BYPASS')
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

/**
 * 优化后的 Cache Key 生成逻辑
 * 1. 静态资源 (Raw, Releases, Assets): 完全忽略查询参数，极大提升命中率
 * 2. API 请求: 保留参数但清理追踪字段并排序
 * 3. 统一 Host 小写化
 */
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

function buildArtifactFallbackHTML(originalUrl) {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Artifact 下载提示</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0d1117;color:#c9d1d9;display:flex;justify-content:center;align-items:center;min-height:100vh;padding:20px}
.card{max-width:600px;width:100%;background:#161b22;border:1px solid #30363d;border-radius:12px;padding:32px;text-align:center}
.icon{font-size:48px;margin-bottom:16px}
h1{font-size:1.5rem;margin-bottom:12px;color:#f0f6fc}
p{line-height:1.6;margin-bottom:20px;color:#8b949e;font-size:0.95rem}
.btn{display:inline-block;padding:12px 24px;background:#238636;color:#fff;text-decoration:none;border-radius:8px;font-weight:600;transition:background .2s}
.btn:hover{background:#2ea043}
.btn-secondary{background:#21262d;border:1px solid #30363d;margin-left:12px}
.btn-secondary:hover{background:#30363d}
.note{margin-top:24px;padding:16px;background:#1c2128;border-radius:8px;font-size:0.85rem;color:#8b949e;text-align:left;line-height:1.5}
code{background:#1c2128;padding:2px 6px;border-radius:4px;font-size:0.85rem;color:#79c0ff;word-break:break-all}
</style>
</head>
<body>
<div class="card">
<div class="icon">⚠️</div>
<h1>Artifact 需要 GitHub 登录</h1>
<p>GitHub Actions Artifacts 要求用户登录后才能下载。<br>由于浏览器安全策略，代理无法获取您的 GitHub 登录状态。</p>
<div>
<a class="btn" href="${originalUrl}" target="_blank" rel="noopener">前往 GitHub 下载</a>
<button class="btn btn-secondary" onclick="navigator.clipboard.writeText('${originalUrl}').then(()=>this.textContent='已复制 ✓')">复制链接</button>
</div>
<div class="note">
<strong>💡 为什么不能直接代理下载？</strong><br>
GitHub 的 Artifact 下载链接绑定了您的浏览器 Session Cookie。当您通过代理访问时，浏览器不会将 github.com 的 Cookie 发送给代理域名，导致 GitHub 拒绝请求。这是浏览器的安全机制，无法绕过。<br><br>
<strong>🔑 如何通过代理直接下载？</strong><br>
您可以使用 GitHub Personal Access Token (PAT) 通过 API 下载。请在 URL 后添加 <code>?token=YOUR_TOKEN</code>，或在请求头中添加 <code>Authorization: Bearer YOUR_TOKEN</code>。<br>
示例：<code>${originalUrl}?token=ghp_xxxx</code><br><br>
<strong>建议：</strong>直接在 GitHub 页面点击下载，或使用 <code>gh run download</code> CLI 命令。
</div>
</div>
</body>
</html>`
}

function serveIndex() {
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <title>GitHub 文件加速</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root {
            --primary: #58a6ff;
            --primary-glow: rgba(88, 166, 255, 0.4);
            --bg-dark: #0d1117;
            --bg-card: rgba(22, 27, 34, 0.7);
            --border: rgba(48, 54, 61, 0.7);
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; outline: none; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            min-height: 100vh;
            background-color: var(--bg-dark);
            background-image: 
                radial-gradient(at 0% 0%, hsla(253,16%,7%,1) 0, transparent 50%), 
                radial-gradient(at 50% 0%, hsla(225,39%,30%,1) 0, transparent 50%), 
                radial-gradient(at 100% 0%, hsla(339,49%,30%,1) 0, transparent 50%);
            background-size: 200% 200%;
            animation: gradientMove 15s ease infinite;
            color: var(--text-main);
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            overflow-x: hidden;
        }

        @keyframes gradientMove {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        .container {
            width: 100%;
            max-width: 700px;
            padding: 40px;
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--border);
            border-radius: 24px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
            text-align: center;
            position: relative;
            z-index: 1;
        }

        .container::before {
            content: '';
            position: absolute;
            top: -2px; left: -2px; right: -2px; bottom: -2px;
            background: linear-gradient(45deg, #ff00cc, #3333ff, #00ccff);
            z-index: -1;
            border-radius: 26px;
            filter: blur(20px);
            opacity: 0.15;
        }

        .logo {
            margin-bottom: 1.5rem;
            transition: transform 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
            display: inline-block;
        }
        .logo:hover { transform: scale(1.1) rotate(5deg); }
        .logo svg { fill: var(--text-main); width: 64px; height: 64px; }

        .title {
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, #fff 0%, #a5d6ff 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.5px;
        }

        .subtitle {
            color: var(--text-muted);
            font-size: 1rem;
            margin-bottom: 2.5rem;
        }

        .search-container {
            position: relative;
            max-width: 500px;
            margin: 0 auto 2rem auto;
        }

        .search-input {
            width: 100%;
            height: 54px;
            padding: 0 60px 0 24px;
            font-size: 1rem;
            color: #fff;
            background: rgba(13, 17, 23, 0.6);
            border: 1px solid var(--border);
            border-radius: 16px;
            transition: all 0.3s ease;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);
        }

        .search-input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 4px var(--primary-glow), inset 0 2px 4px rgba(0,0,0,0.1);
            background: rgba(13, 17, 23, 0.8);
        }

        .search-input::placeholder { color: rgba(139, 148, 158, 0.6); }

        .search-button {
            position: absolute;
            right: 8px;
            top: 50%;
            transform: translateY(-50%);
            width: 40px;
            height: 40px;
            border: none;
            border-radius: 12px;
            background: var(--primary);
            color: #fff;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
        }

        .search-button:hover {
            background: #79c0ff;
            transform: translateY(-50%) scale(1.05);
            box-shadow: 0 4px 12px var(--primary-glow);
        }

        .links-area {
            display: flex;
            justify-content: center;
            gap: 15px;
            flex-wrap: wrap;
            margin-top: 1rem;
        }

        .link-btn {
            display: inline-flex;
            align-items: center;
            padding: 8px 16px;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border);
            border-radius: 20px;
            color: var(--text-muted);
            text-decoration: none;
            font-size: 0.9rem;
            transition: all 0.2s;
        }

        .link-btn:hover {
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
            border-color: var(--primary);
            transform: translateY(-2px);
        }

        .footer-note {
            margin-top: 2.5rem;
            font-size: 0.8rem;
            color: var(--text-muted);
            opacity: 0.6;
        }

        @media (max-width: 600px) {
            .container { padding: 30px 20px; }
            .title { font-size: 1.8rem; }
            .search-input { height: 48px; font-size: 0.95rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <a href="https://github.com/qfmc7040/CF-GH-Proxy/" target="_blank">
                <svg viewBox="0 0 98 96" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" clip-rule="evenodd" d="M48.854 0C21.839 0 0 22 0 49.217c0 21.756 13.993 40.172 33.405 46.69 2.427.49 3.316-1.059 3.316-2.362 0-1.141-.08-5.052-.08-9.127-13.59 2.934-16.42-5.867-16.42-5.867-2.184-5.704-5.42-7.17-5.42-7.17-4.448-3.015.324-3.015.324-3.015 4.934.326 7.523 5.052 7.523 5.052 4.367 7.496 11.404 5.378 14.235 4.074.404-3.178 1.699-5.378 3.074-6.6-10.839-1.141-22.243-5.378-22.243-24.283 0-5.378 1.94-9.778 5.014-13.2-.485-1.222-2.184-6.275.486-13.038 0 0 4.125-1.304 13.426 5.052a46.97 46.97 0 0 1 12.214-1.63c4.125 0 8.33.571 12.213 1.63 9.302-6.356 13.427-5.052 13.427-5.052 2.67 6.763.97 11.816.485 13.038 3.155 3.422 5.015 7.822 5.015 13.2 0 18.905-11.404 23.06-22.324 24.283 1.78 1.548 3.316 4.481 3.316 9.126 0 6.6-.08 11.897-.08 13.526 0 1.304.89 2.853 3.316 2.364 19.412-6.52 33.405-24.935 33.405-46.691C97.707 22 75.788 0 48.854 0z"/></svg>
            </a>
        </div>
        <h1 class="title">GitHub 加速代理</h1>
        <p class="subtitle">加速访问 Releases, Raw 文件及 API 接口</p>
        
        <form onsubmit="toSubmit(event)" class="search-container">
            <input type="text" class="search-input" name="q" placeholder="请输入GitHub文件或API链接" required autocomplete="off">
            <button type="submit" class="search-button">
                <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path d="M13 5l7 7-7 7M5 5l7 7-7 7" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </button>
        </form>

        <div class="links-area">
            <a href="https://github.com/qfmc7040/CF-GH-Proxy/" target="_blank" class="link-btn">
                <svg style="width:16px;height:16px;margin-right:6px" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
                项目源码
            </a>
            <a href="https://github.akams.cn/" target="_blank" class="link-btn">
                <svg style="width:16px;height:16px;margin-right:6px" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zm0 9l2.5-1.25L12 8.5l-2.5 1.25L12 11zm0 2.5l-5-2.5-5 2.5L12 22l10-8.5-5-2.5-5 2.5z"/></svg>
                聚合导航
            </a>
        </div>

        <div class="footer-note">
            Powered by Cloudflare Workers &copy; QFMC
        </div>
    </div>
    <script>
        function toSubmit(e){
            e.preventDefault();
            const input = document.getElementsByName('q')[0];
            let val = input.value.trim();
            if(!val) return;
            if (!val.startsWith('http')) {
                val = 'https://' + val;
            }
            window.location.href = location.origin + '/' + val.replace(/^https?:\/\//, '');
        }
    </script>
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
