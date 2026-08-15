'use strict'

const CONFIG = {
    PREFIX: '/',
    CACHE_TTL: 86400,
    MAX_CACHE_SIZE: 50 * 1024 * 1024,
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
    headers: { ...CORS_HEADERS, ...SECURITY_HEADERS,
        'access-control-allow-methods': 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS',
        'access-control-allow-headers': 'Content-Type, Authorization, Accept, X-Requested-With',
        'access-control-max-age': '1728000',
    },
})

function makeRes(body, status = 200, headers = {}) {
    return new Response(body, { status, headers: { ...CORS_HEADERS, ...SECURITY_HEADERS, ...headers } })
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
        let currentCount = 0
        const cacheReq = new Request(cacheKey, { method: 'GET' })
        const cached = await cache.match(cacheReq)
        if (cached) {
            currentCount = parseInt(await cached.text(), 10) || 0
            if (currentCount >= CONFIG.RATE_LIMIT_MAX) {
                const retryAfter = (Math.floor(now / CONFIG.RATE_LIMIT_WINDOW) + 1) * CONFIG.RATE_LIMIT_WINDOW - now
                return makeRes(JSON.stringify({ error: 'Rate limit exceeded', retry_after: retryAfter }), 429, {
                    'content-type': 'application/json; charset=utf-8', 'retry-after': String(retryAfter),
                })
            }
        }
        event.waitUntil(cache.put(cacheReq, new Response(String(currentCount + 1), {
            headers: { 'cache-control': `public, max-age=${CONFIG.RATE_LIMIT_WINDOW}` }
        })))
        return null
    } catch (e) { console.warn('Rate limit bypass:', e); return null }
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
        try { hostnameMatch = ALLOWED_HOSTNAMES.includes(new URL(normalizedPath).hostname.toLowerCase()) } catch {}
        if (patternMatch && hostnameMatch) {
            return Response.redirect('https://' + urlObj.host + CONFIG.PREFIX + normalizedPath, 301)
        }
        return makeRes('Blocked: Invalid redirect target.', 403)
    }

    let rawPath = urlObj.pathname
    if (CONFIG.PREFIX !== '/' && rawPath.startsWith(CONFIG.PREFIX)) rawPath = rawPath.slice(CONFIG.PREFIX.length)
    path = rawPath.replace(/^\//, '').replace(/^https?:\/+/, 'https://')

    if (!path) return serveIndex()
    if (GITHUB_PATTERNS.some(p => p.test(path))) return proxyRequest(e, req, path)

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
                            
                            for (const [k, v] of Object.entries(CORS_HEADERS)) finalHeaders.set(k, v)
                            for (const [k, v] of Object.entries(SECURITY_HEADERS)) finalHeaders.set(k, v)
                            
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
                    return new Response(null, { status: 304, headers: { ...dynamicCors, ...SECURITY_HEADERS, 'etag': cachedEtag, 'x-cache-status': 'HIT-304' } })
                }
                const hitHeaders = new Headers(cached.headers)
                hitHeaders.set('x-cache-status', 'HIT')
                for (const [k, v] of Object.entries(dynamicCors)) hitHeaders.set(k, v)
                for (const [k, v] of Object.entries(SECURITY_HEADERS)) hitHeaders.set(k, v)
                return new Response(cached.body, { status: cached.status, headers: hitHeaders })
            }
        }

        const targetUrl = pathname.startsWith('http') ? pathname : `https://${pathname}`
        const urlObj = newUrl(targetUrl)
        if (!urlObj) return makeRes('Invalid target URL', 400)

        const reqHdrNew = new Headers(req.headers)
        reqHdrNew.delete('cookie'); reqHdrNew.delete('authorization'); reqHdrNew.delete('host')
        const rangeHeader = req.headers.get('range')
        if (rangeHeader) reqHdrNew.set('range', rangeHeader)

        const response = await handleProxyFetch(urlObj, {
            method: req.method, headers: reqHdrNew, redirect: 'manual', body: req.body,
            cf: { cacheEverything: true, cacheTtlByStatus: { "200-299": CONFIG.CACHE_TTL, "404": 1 } }
        }, 0)

        if (!response.ok && response.status !== 304 && response.status !== 206) {
            const errHeaders = new Headers(response.headers)
            for (const [k, v] of Object.entries(dynamicCors)) errHeaders.set(k, v)
            for (const [k, v] of Object.entries(SECURITY_HEADERS)) errHeaders.set(k, v)
            return new Response(response.body, { status: response.status, headers: errHeaders })
        }

        if (req.method === 'GET' && response.status >= 200 && response.status < 400) {
            const contentLength = parseInt(response.headers.get('content-length') || '0', 10)
            const shouldCache = contentLength > 0 && contentLength <= CONFIG.MAX_CACHE_SIZE
            const finalHeaders = new Headers(response.headers)
            for (const [k, v] of Object.entries(dynamicCors)) finalHeaders.set(k, v)
            for (const [k, v] of Object.entries(SECURITY_HEADERS)) finalHeaders.set(k, v)

            if (shouldCache && response.body) {
                finalHeaders.set('Cache-Control', `public, max-age=${CONFIG.CACHE_TTL}`)
                finalHeaders.set('x-cache-status', 'MISS')
                try {
                    const [forClient, forCache] = response.body.tee()
                    e.waitUntil(cache.put(cacheKey, new Response(forCache, { status: response.status, headers: finalHeaders })))
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
        for (const [k, v] of Object.entries(dynamicCors)) missHeaders.set(k, v)
        for (const [k, v] of Object.entries(SECURITY_HEADERS)) missHeaders.set(k, v)
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
        const NO_SIMPLIFY = [/^api\.github\.com$/, /\/releases\/download\//, /^gist\.(?:githubusercontent|github)\.com$/, /\/actions\/runs\/\d+\/artifacts\//]
        if (NO_SIMPLIFY.some(p => p.test(url.hostname) || p.test(url.pathname))) return new Request(url.href, { method: 'GET' })
        const STABLE = ['ref', 'tag', 'branch', 'commit']
        for (const key of [...url.searchParams.keys()]) { if (!STABLE.includes(key)) url.searchParams.delete(key) }
        return new Request(url.href, { method: 'GET' })
    } catch { return new Request(`https://fallback.invalid/${pathname}`, { method: 'GET' }) }
}

function getDynamicCorsHeaders(req, targetUrl) {
    try {
        const url = newUrl(targetUrl)
        if (url && (url.hostname === 'api.github.com' || url.searchParams.has('token'))) {
            const origin = req.headers.get('origin')
            if (origin) return { 'access-control-allow-origin': origin, 'access-control-expose-headers': '*', 'vary': 'Origin' }
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
            if (SAFE_REDIRECT_HOSTS.has(nextUrl.hostname) || GITHUB_PATTERNS.some(p => p.test(nextUrl.href)) || isSafeAzureRedirect(nextUrl.hostname)) {
                return handleProxyFetch(nextUrl, init, redirectCount + 1)
            }
            const safeHeaders = new Headers(res.headers)
            safeHeaders.delete('set-cookie')
            safeHeaders.set('access-control-expose-headers', '*')
            for (const [k, v] of Object.entries(SECURITY_HEADERS)) safeHeaders.set(k, v)
            return new Response(null, { status: res.status, headers: safeHeaders })
        }
        const resHdrNew = new Headers(res.headers)
        resHdrNew.delete('content-security-policy'); resHdrNew.delete('clear-site-data'); resHdrNew.delete('x-frame-options')
        return new Response(res.body, { status: res.status, headers: resHdrNew })
    } catch (err) { return makeRes('Proxy Error: ' + err.message, 502) }
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
        :root{--primary-color:#1a1e21;--primary-hover:#0d1117;--text-color:#f0f6fc;--bg-gradient:linear-gradient(135deg,#1a1e21 0%,#0d1117 100%);--shadow:0 4px 12px rgba(0,0,0,.15)}
        *{box-sizing:border-box;margin:0;padding:0}
        body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;min-height:100vh;background:var(--bg-gradient);color:var(--text-color);display:flex;justify-content:center;align-items:center;padding:20px}
        .container{width:100%;max-width:800px;padding:40px 20px;text-align:center}
        .logo{margin-bottom:2rem;transform:scale(1);transition:transform .3s ease}.logo:hover{transform:scale(1.1)}
        .title{font-size:2.5rem;font-weight:600;margin-bottom:1rem;background:linear-gradient(45deg,#cdd5dd,#e2e8f0);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
        .search-container{position:relative;max-width:600px;margin:2rem auto}
        .search-input{width:100%;height:56px;padding:0 60px 0 24px;font-size:1rem;color:#1f2937;background:rgba(255,255,255,.9);border:2px solid transparent;border-radius:12px;box-shadow:var(--shadow);transition:all .3s ease}
        .search-input:focus{border-color:var(--primary-color);background:#fff;outline:none;box-shadow:0 0 0 3px rgba(0,102,255,.2)}
        .search-button{position:absolute;right:8px;top:50%;transform:translateY(-50%);width:44px;height:44px;border:none;border-radius:8px;background:var(--primary-color);color:#fff;cursor:pointer;transition:all .2s ease}
        .search-button:hover{background:var(--primary-hover);transform:translateY(-50%) scale(1.05)}
        .example-title{color:#9ba1a6;margin-bottom:1rem;font-size:1rem;font-weight:700;position:relative;padding-bottom:.8rem;border-bottom:1px solid rgba(255,255,255,.1)}
        .example{margin-top:2rem;padding:1.8rem;background:rgba(255,255,255,.05);border-radius:12px;text-align:left;border:1px solid rgba(255,255,255,.1);overflow-wrap:break-word}
        .example-list{max-height:260px;overflow-y:auto;margin-top:.5rem;padding-right:8px;scroll-behavior:smooth;scrollbar-width:thin;scrollbar-color:rgba(255,255,255,.2) rgba(255,255,255,.05)}
        .example-list::-webkit-scrollbar{width:6px}
        .example-list::-webkit-scrollbar-track{background:rgba(255,255,255,.05);border-radius:3px}
        .example-list::-webkit-scrollbar-thumb{background:rgba(255,255,255,.2);border-radius:3px}
        .example-list::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,.35)}
        .example-list p{margin:.6rem 0;font-family:monospace;font-size:.9rem;color:rgba(255,255,255,.8);padding-left:1.2rem;line-height:1.4;word-break:break-all}
        @media(max-width:640px){.container{padding:20px}.title{font-size:2rem}.search-input{height:50px;font-size:.9rem}.search-button{width:38px;height:38px}.example{padding:1rem;font-size:.8rem}.example-list{max-height:180px}}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo"><a href="https://github.com/qfmc7040/CF-GH-Proxy/" target="_blank"><svg xmlns="http://www.w3.org/2000/svg" width="120" height="90" viewBox="0 0 98 96" fill="#ffffff"><path fill-rule="evenodd" clip-rule="evenodd" d="M48.854 0C21.839 0 0 22 0 49.217c0 21.756 13.993 40.172 33.405 46.69 2.427.49 3.316-1.059 3.316-2.362 0-1.141-.08-5.052-.08-9.127-13.59 2.934-16.42-5.867-16.42-5.867-2.184-5.704-5.42-7.17-5.42-7.17-4.448-3.015.324-3.015.324-3.015 4.934.326 7.523 5.052 7.523 5.052 4.367 7.496 11.404 5.378 14.235 4.074.404-3.178 1.699-5.378 3.074-6.6-10.839-1.141-22.243-5.378-22.243-24.283 0-5.378 1.94-9.778 5.014-13.2-.485-1.222-2.184-6.275.486-13.038 0 0 4.125-1.304 13.426 5.052a46.97 46.97 0 0 1 12.214-1.63c4.125 0 8.33.571 12.213 1.63 9.302-6.356 13.427-5.052 13.427-5.052 2.67 6.763.97 11.816.485 13.038 3.155 3.422 5.015 7.822 5.015 13.2 0 18.905-11.404 23.06-22.324 24.283 1.78 1.548 3.316 4.481 3.316 9.126 0 6.6-.08 11.897-.08 13.526 0 1.304.89 2.853 3.316 2.364 19.412-6.52 33.405-24.935 33.405-46.691C97.707 22 75.788 0 48.854 0z"/></svg></a></div>
        <h1 class="title">GitHub文件及API加速</h1>
        <form onsubmit="toSubmit(event)" class="search-container">
            <input type="text" class="search-input" name="q" placeholder="请输入GitHub文件或API链接" required>
            <button type="submit" class="search-button"><svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M13 5l7 7-7 7M5 5l7 7-7 7" stroke-linecap="round" stroke-linejoin="round"/></svg></button>
        </form>
        <p style="margin-top:2rem;color:rgba(255,255,255,.6)"><a href="https://github.com/qfmc7040/CF-GH-Proxy/" style="color:inherit;text-decoration:none;border-bottom:1px dashed rgba(255,255,255,.4)">QFMC</a> 访问以参考项目</p>
        <p style="margin-top:2rem;color:rgba(255,255,255,.6)"><a href="https://github.akams.cn/" style="color:inherit;text-decoration:none;border-bottom:1px dashed rgba(255,255,255,.4)">GitHub Proxy</a> 点击访问GitHub 文件下载加速代理聚合项目</p>
    </div>
    <script>function toSubmit(e){e.preventDefault();const i=document.getElementsByName('q')[0];window.open(location.href.substr(0,location.href.lastIndexOf('/')+1)+i.value)}</script>
</body>
</html>`
    return new Response(html, {
        status: 200,
        headers: { 'content-type': 'text/html; charset=utf-8', ...CORS_HEADERS, ...SECURITY_HEADERS }
    })
}
