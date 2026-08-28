'use strict'

const CONFIG = {
    PREFIX: '/',
    CACHE_TTL: 604800,
    MAX_CACHE_SIZE: 250 * 1024 * 1024,
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

        const isRangeRequest = !!req.headers.get('range')
        
        if (req.method === 'GET' && !isRangeRequest) {
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
    <script>
        // 主题早期初始化：优先使用手动选择，否则按 UTC+8 时间判定昼夜（避免页面闪烁）
        (function () {
            function autoTheme() {
                var hour = new Date(Date.now() + 8 * 3600 * 1000).getUTCHours();
                return (hour >= 7 && hour < 18) ? 'light' : 'dark';
            }
            var pref = null;
            try { pref = localStorage.getItem('gh_proxy_theme'); } catch (e) {}
            var theme = (pref === 'light' || pref === 'dark') ? pref : autoTheme();
            document.documentElement.setAttribute('data-theme', theme);
        })();
    </script>
    <style>
        /* ========== 主题变量：默认夜间模式（保留原配色） ========== */
        :root {
            --primary: #58a6ff;
            --primary-glow: rgba(88, 166, 255, 0.4);
            --bg-dark: #0d1117;
            --bg-card: rgba(22, 27, 34, 0.7);
            --bg-panel: rgba(13, 17, 23, 0.6);
            --border: rgba(48, 54, 61, 0.7);
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --danger: #f85149;
            /* Scrollbar colors */
            --scrollbar-track: rgba(13, 17, 23, 0.3);
            --scrollbar-thumb: rgba(48, 54, 61, 0.8);
            --scrollbar-thumb-hover: rgba(88, 166, 255, 0.6);
            /* 页面背景渐变 */
            --body-bg-1: hsla(253,16%,7%,1);
            --body-bg-2: hsla(225,39%,30%,1);
            --body-bg-3: hsla(339,49%,30%,1);
            /* 输入框 */
            --input-bg: rgba(13, 17, 23, 0.6);
            --input-bg-focus: rgba(13, 17, 23, 0.8);
            --input-text: #ffffff;
            --input-placeholder: rgba(139, 148, 158, 0.6);
            /* 链接按钮与历史卡片 */
            --chip-bg: rgba(255, 255, 255, 0.05);
            --chip-bg-hover: rgba(255, 255, 255, 0.1);
            --chip-text-hover: #ffffff;
            --item-bg: rgba(255, 255, 255, 0.03);
            --item-bg-hover: rgba(255, 255, 255, 0.08);
            --meta-text: rgba(139, 148, 158, 0.6);
            /* 标题渐变 / 阴影 / 光晕 */
            --title-grad-start: #ffffff;
            --title-grad-end: #a5d6ff;
            --card-shadow: rgba(0, 0, 0, 0.4);
            --glow-opacity: 0.15;
            --toggle-bg: rgba(22, 27, 34, 0.7);
            color-scheme: dark;
        }

        /* ========== 白天模式（UTC+8 07:00-18:00 自动启用，或手动切换） ========== */
        html[data-theme="light"] {
            --primary: #0969da;
            --primary-glow: rgba(9, 105, 218, 0.25);
            --bg-dark: #eef2f7;
            --bg-card: rgba(255, 255, 255, 0.72);
            --bg-panel: rgba(255, 255, 255, 0.6);
            --border: rgba(208, 215, 222, 0.8);
            --text-main: #1f2328;
            --text-muted: #57606a;
            --danger: #cf222e;
            --scrollbar-track: rgba(234, 238, 242, 0.9);
            --scrollbar-thumb: rgba(175, 184, 193, 0.9);
            --scrollbar-thumb-hover: rgba(9, 105, 218, 0.55);
            --body-bg-1: hsla(210,100%,94%,1);
            --body-bg-2: hsla(212,95%,84%,1);
            --body-bg-3: hsla(330,85%,90%,1);
            --input-bg: rgba(255, 255, 255, 0.75);
            --input-bg-focus: rgba(255, 255, 255, 0.95);
            --input-text: #1f2328;
            --input-placeholder: rgba(87, 96, 106, 0.55);
            --chip-bg: rgba(31, 35, 40, 0.04);
            --chip-bg-hover: rgba(9, 105, 218, 0.08);
            --chip-text-hover: #0969da;
            --item-bg: rgba(31, 35, 40, 0.03);
            --item-bg-hover: rgba(9, 105, 218, 0.06);
            --meta-text: rgba(87, 96, 106, 0.65);
            --title-grad-start: #1f2328;
            --title-grad-end: #0969da;
            --card-shadow: rgba(140, 152, 175, 0.28);
            --glow-opacity: 0.18;
            --toggle-bg: rgba(255, 255, 255, 0.75);
            color-scheme: light;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; outline: none; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            min-height: 100vh;
            background-color: var(--bg-dark);
            background-image: 
                radial-gradient(at 0% 0%, var(--body-bg-1) 0, transparent 50%), 
                radial-gradient(at 50% 0%, var(--body-bg-2) 0, transparent 50%), 
                radial-gradient(at 100% 0%, var(--body-bg-3) 0, transparent 50%);
            background-size: 200% 200%;
            animation: gradientMove 15s ease infinite;
            color: var(--text-main);
            transition: color 0.3s ease;
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

        /* Main Layout Container */
        .main-wrapper {
            width: 100%;
            max-width: 1100px;
            display: grid;
            grid-template-columns: 1fr 350px;
            gap: 24px;
            position: relative;
            z-index: 1;
        }

        @media (max-width: 900px) {
            .main-wrapper {
                grid-template-columns: 1fr;
                max-width: 600px;
            }
        }

        /* Left Panel: Main Content */
        .left-panel {
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--border);
            border-radius: 24px;
            padding: 40px;
            box-shadow: 0 20px 40px var(--card-shadow);
            text-align: center;
            transition: background 0.3s ease, border-color 0.3s ease, box-shadow 0.3s ease;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }

        .left-panel::before {
            content: '';
            position: absolute;
            top: -2px; left: -2px; right: -2px; bottom: -2px;
            background: linear-gradient(45deg, #ff00cc, #3333ff, #00ccff);
            z-index: -1;
            border-radius: 26px;
            filter: blur(20px);
            opacity: var(--glow-opacity);
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
            background: linear-gradient(135deg, var(--title-grad-start) 0%, var(--title-grad-end) 100%);
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
            width: 100%;
        }

        .search-input {
            width: 100%;
            height: 54px;
            padding: 0 60px 0 24px;
            font-size: 1rem;
            color: var(--input-text);
            background: var(--input-bg);
            border: 1px solid var(--border);
            border-radius: 16px;
            transition: all 0.3s ease;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);
        }

        .search-input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 4px var(--primary-glow), inset 0 2px 4px rgba(0,0,0,0.1);
            background: var(--input-bg-focus);
        }

        .search-input::placeholder { color: var(--input-placeholder); }

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
            background: var(--chip-bg);
            border: 1px solid var(--border);
            border-radius: 20px;
            color: var(--text-muted);
            text-decoration: none;
            font-size: 0.9rem;
            transition: all 0.2s;
        }

        .link-btn:hover {
            background: var(--chip-bg-hover);
            color: var(--chip-text-hover);
            border-color: var(--primary);
            transform: translateY(-2px);
        }

        .footer-note {
            margin-top: 2.5rem;
            font-size: 0.8rem;
            color: var(--text-muted);
            opacity: 0.6;
        }

        /* Right Panel: History */
        .right-panel {
            background: var(--bg-panel);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--border);
            border-radius: 24px;
            padding: 24px;
            box-shadow: 0 20px 40px var(--card-shadow);
            transition: background 0.3s ease, border-color 0.3s ease, box-shadow 0.3s ease;
            display: flex;
            flex-direction: column;
            height: fit-content;
            max-height: 80vh;
        }

        .history-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border);
        }

        .history-title {
            color: var(--text-main);
            font-size: 1.1rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .clear-btn {
            background: none;
            border: none;
            color: var(--danger);
            cursor: pointer;
            font-size: 0.85rem;
            padding: 4px 8px;
            border-radius: 4px;
            transition: background 0.2s;
        }
        .clear-btn:hover {
            background: rgba(248, 81, 73, 0.1);
        }

        .history-list {
            list-style: none;
            overflow-y: auto;
            /* Firefox: Use opaque color for persistent scrollbar */
            scrollbar-width: thin;
            scrollbar-color: var(--scrollbar-thumb) var(--scrollbar-track);
            flex: 1;
            min-height: 100px;
            padding-right: 4px; /* Prevent content from touching scrollbar */
        }

        /* Webkit (Chrome, Edge, Safari): Persistent Scrollbar Styles */
        .history-list::-webkit-scrollbar {
            width: 8px;
            background-color: var(--scrollbar-track); /* Track background makes it visible */
        }

        .history-list::-webkit-scrollbar-thumb {
            background-color: var(--scrollbar-thumb);
            border-radius: 4px;
            border: 2px solid var(--scrollbar-track); /* Creates padding effect */
        }

        .history-list::-webkit-scrollbar-thumb:hover {
            background-color: var(--scrollbar-thumb-hover);
        }

        .history-item {
            display: flex;
            flex-direction: column;
            padding: 12px;
            margin-bottom: 10px;
            background: var(--item-bg);
            border: 1px solid transparent;
            border-radius: 12px;
            cursor: pointer;
            transition: all 0.2s;
            position: relative;
            overflow: hidden;
        }

        .history-item:hover {
            background: var(--item-bg-hover);
            border-color: var(--primary);
            transform: translateX(2px);
        }

        .history-filename {
            font-size: 0.95rem;
            font-weight: 600;
            color: var(--primary);
            margin-bottom: 4px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .history-url {
            font-size: 0.8rem;
            color: var(--text-muted);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            margin-bottom: 6px;
        }

        .history-meta {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.75rem;
            color: var(--meta-text);
        }

        .empty-history {
            text-align: center;
            color: var(--text-muted);
            padding: 20px 0;
            font-size: 0.9rem;
            opacity: 0.6;
        }

        /* Theme Toggle Button */
        .theme-toggle {
            position: fixed;
            top: 20px;
            right: 20px;
            width: 46px;
            height: 46px;
            border-radius: 50%;
            border: 1px solid var(--border);
            background: var(--toggle-bg);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            color: var(--text-main);
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 100;
            box-shadow: 0 4px 14px var(--card-shadow);
            transition: transform 0.2s ease, box-shadow 0.2s ease, background-color 0.3s ease, border-color 0.3s ease, color 0.3s ease;
        }

        .theme-toggle:hover {
            transform: scale(1.08);
            border-color: var(--primary);
            box-shadow: 0 4px 18px var(--primary-glow);
            color: var(--primary);
        }

        .theme-toggle svg {
            width: 20px;
            height: 20px;
            position: absolute;
            transition: opacity 0.25s ease, transform 0.25s ease;
        }

        /* 夜间模式显示太阳图标（点击切换到白天）；白天模式显示月亮图标 */
        .theme-toggle .icon-sun { opacity: 1; transform: rotate(0deg) scale(1); }
        .theme-toggle .icon-moon { opacity: 0; transform: rotate(-90deg) scale(0.4); }
        html[data-theme="light"] .theme-toggle .icon-sun { opacity: 0; transform: rotate(90deg) scale(0.4); }
        html[data-theme="light"] .theme-toggle .icon-moon { opacity: 1; transform: rotate(0deg) scale(1); }

        @media (max-width: 600px) {
            .theme-toggle { top: 12px; right: 12px; width: 40px; height: 40px; }
            .theme-toggle svg { width: 18px; height: 18px; }
            .left-panel { padding: 30px 20px; }
            .title { font-size: 1.8rem; }
            .search-input { height: 48px; font-size: 0.95rem; }
        }
    </style>
</head>
<body>
    <!-- 昼夜模式切换按钮 -->
    <button id="themeToggle" class="theme-toggle" type="button" title="切换白天/夜间模式（双击恢复按时间自动切换）" aria-label="切换白天/夜间模式">
        <svg class="icon-sun" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32l1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" stroke-linecap="round"/></svg>
        <svg class="icon-moon" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z" stroke-linecap="round" stroke-linejoin="round"/></svg>
    </button>

    <div class="main-wrapper">
        <!-- Left Panel: Main Content -->
        <div class="left-panel">
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
            </div>

            <div class="links-area">
                <a href="https://github.akams.cn/" target="_blank" class="link-btn">
                    <svg style="width:16px;height:16px;margin-right:6px" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zm0 9l2.5-1.25L12 8.5l-2.5 1.25L12 11zm0 2.5l-5-2.5-5 2.5L12 22l10-8.5-5-2.5-5 2.5z"/></svg>
                    代理聚合
                </a>
            </div>

            <div class="footer-note">
                Powered by Cloudflare Workers &copy; QFMC
            </div>
        </div>

        <!-- Right Panel: History -->
        <div class="right-panel">
            <div class="history-header">
                <div class="history-title">
                    <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" stroke-linecap="round" stroke-linejoin="round"/></svg>
                    最近访问
                </div>
                <button class="clear-btn" onclick="clearHistory()">清空</button>
            </div>
            <ul id="historyList" class="history-list">
                <!-- Items will be injected here -->
            </ul>
        </div>
    </div>

    <script>
        // --- Theme Logic ---
        const THEME_KEY = 'gh_proxy_theme';

        function getAutoTheme() {
            // 按 UTC+08:00 判定昼夜：07:00-18:00 为白天，其余为夜间
            var hour = new Date(Date.now() + 8 * 3600 * 1000).getUTCHours();
            return (hour >= 7 && hour < 18) ? 'light' : 'dark';
        }

        function currentTheme() {
            return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
        }

        function applyTheme(theme) {
            document.documentElement.setAttribute('data-theme', theme);
        }

        function initThemeToggle() {
            var btn = document.getElementById('themeToggle');
            if (!btn) return;

            // 单击：手动切换昼夜模式，并记住偏好
            btn.addEventListener('click', function () {
                var next = currentTheme() === 'light' ? 'dark' : 'light';
                applyTheme(next);
                try { localStorage.setItem(THEME_KEY, next); } catch (e) {}
            });

            // 双击：清除手动偏好，恢复按 UTC+8 时间自动切换
            btn.addEventListener('dblclick', function () {
                try { localStorage.removeItem(THEME_KEY); } catch (e) {}
                applyTheme(getAutoTheme());
            });

            // 无手动偏好时，跨越时间窗口（07:00 / 18:00）自动同步主题
            setInterval(function () {
                var pref = null;
                try { pref = localStorage.getItem(THEME_KEY); } catch (e) {}
                if (pref !== 'light' && pref !== 'dark') {
                    var auto = getAutoTheme();
                    if (auto !== currentTheme()) applyTheme(auto);
                }
            }, 60000);
        }

        // --- History Logic ---
        const STORAGE_KEY = 'gh_proxy_history_v2';
        const MAX_HISTORY = 50;

        function loadHistory() {
            try {
                const data = localStorage.getItem(STORAGE_KEY);
                return data ? JSON.parse(data) : [];
            } catch (e) {
                return [];
            }
        }

        function extractFilename(url) {
            try {
                const urlObj = new URL(url);
                const pathParts = urlObj.pathname.split('/');
                const lastPart = pathParts[pathParts.length - 1];
                if (lastPart && lastPart.includes('.')) return lastPart;
                if (pathParts.length > 2) return pathParts[pathParts.length - 2] + '/' + lastPart;
                return urlObj.hostname;
            } catch (e) {
                return url;
            }
        }

        function saveHistory(url) {
            let history = loadHistory();
            // Remove if exists to move to top
            history = history.filter(item => item.url !== url);
            
            const filename = extractFilename(url);
            
            // Add new
            history.unshift({
                url: url,
                filename: filename,
                time: Date.now()
            });
            
            // Limit size
            if (history.length > MAX_HISTORY) {
                history = history.slice(0, MAX_HISTORY);
            }
            
            localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
            renderHistory();
        }

        function clearHistory() {
            localStorage.removeItem(STORAGE_KEY);
            renderHistory();
        }

        function renderHistory() {
            const history = loadHistory();
            const list = document.getElementById('historyList');
            
            if (history.length === 0) {
                list.innerHTML = '<div class="empty-history">暂无访问记录</div>';
                return;
            }

            list.innerHTML = '';

            history.forEach(item => {
                const li = document.createElement('li');
                li.className = 'history-item';
                li.onclick = () => {
                    // Re-use the submit logic but directly with the URL
                    // Remove protocol for the proxy path
                    const path = item.url.replace(/^https?:\\/\\//, '');
                    window.location.href = location.origin + '/' + path;
                };
                
                const timeAgo = getTimeAgo(item.time);
                
                li.innerHTML = \`
                    <div class="history-filename" title="\${item.filename}">\${item.filename}</div>
                    <div class="history-url" title="\${item.url}">\${item.url}</div>
                    <div class="history-meta">
                        <span>\${timeAgo}</span>
                        <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" stroke-linecap="round" stroke-linejoin="round"/></svg>
                    </div>
                \`;
                list.appendChild(li);
            });
        }

        function getTimeAgo(timestamp) {
            const seconds = Math.floor((Date.now() - timestamp) / 1000);
            if (seconds < 60) return '刚刚';
            const minutes = Math.floor(seconds / 60);
            if (minutes < 60) return minutes + '分钟前';
            const hours = Math.floor(minutes / 60);
            if (hours < 24) return hours + '小时前';
            const days = Math.floor(hours / 24);
            return days + '天前';
        }

        // --- Submit Logic ---
        function toSubmit(e){
            e.preventDefault();
            const input = document.getElementsByName('q')[0];
            let val = input.value.trim();
            if(!val) return;
            
            // Normalize URL for storage and redirection
            let originalVal = val;
            if (!val.startsWith('http')) {
                val = 'https://' + val;
            }
            
            // Save to history before redirecting
            saveHistory(val);
            
            // Redirect
            window.location.href = location.origin + '/' + val.replace(/^https?:\\/\\//, '');
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', function () {
            renderHistory();
            initThemeToggle();
        });
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
