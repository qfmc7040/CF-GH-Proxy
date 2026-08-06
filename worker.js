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
    'objects.githubusercontent.com',
    'github-releases.githubusercontent.com',
    'release-assets.githubusercontent.com',
    'raw.githubusercontent.com',
    'gist.githubusercontent.com',
    'codeload.github.com',
    'github.githubassets.com',
    'copilot.githubusercontent.com',
    'actions.githubusercontent.com',
])

const AZURE_BLOB_SUFFIXES = [
    '.blob.core.windows.net',
    '.azureedge.net',
]

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

function makeRes(body, status = 200, headers = {}) {
    return new Response(body, {
        status,
        headers: { ...CORS_HEADERS, ...SECURITY_HEADERS, ...headers }
    })
}

function makeErrorRes(err) {
    if (CONFIG.IS_PRODUCTION) {
        console.error('[Worker Error]', err)
        return makeRes('Internal Server Error', 500)
    }
    return makeRes('cfworker error:\n' + err.stack, 502)
}

function newUrl(urlStr) {
    try { return new URL(urlStr) } catch { return null }
}

function isSensitivePath(urlStr) {
    try {
        const url = new URL(urlStr.startsWith('http') ? urlStr : `https://${urlStr}`)
        if (url.hostname === 'api.github.com') return true
        if (url.searchParams.has('token') || url.searchParams.has('key')) return true
        return false
    } catch { return false }
}

function isArtifactPath(pathname) {
    return /\/actions\/runs\/\d+\/artifacts\/\d+/.test(pathname)
}

function isSafeAzureRedirect(hostname) {
    return AZURE_BLOB_SUFFIXES.some(suffix => hostname.endsWith(suffix))
}

function getDynamicCorsHeaders(req, targetUrl) {
    if (isSensitivePath(targetUrl)) {
        const origin = req.headers.get('origin')
        if (origin) {
            return {
                'access-control-allow-origin': origin,
                'access-control-expose-headers': '*',
                'vary': 'Origin',
            }
        }
        return { 'access-control-expose-headers': '*' }
    }
    return { ...CORS_HEADERS }
}

async function checkRateLimit(req, event) {
    const ip = req.headers.get('cf-connecting-ip') || 'unknown'
    const now = Math.floor(Date.now() / 1000)
    const windowKey = `rl:${ip}:${Math.floor(now / CONFIG.RATE_LIMIT_WINDOW)}`
    const cacheKey = new Request(`https://rate-limit.internal/${windowKey}`, { method: 'GET' })
    const cache = caches.default

    let currentCount = 0
    const cached = await cache.match(cacheKey)
    
    if (cached) {
        currentCount = parseInt(await cached.text(), 10) || 0
        
        if (currentCount >= CONFIG.RATE_LIMIT_MAX) {
            const retryAfter = (Math.floor(now / CONFIG.RATE_LIMIT_WINDOW) + 1) * CONFIG.RATE_LIMIT_WINDOW - now
            return makeRes(
                JSON.stringify({ error: 'Rate limit exceeded', retry_after: retryAfter }),
                429,
                {
                    'content-type': 'application/json; charset=utf-8',
                    'retry-after': String(retryAfter),
                }
            )
        }
    }

    const newCount = currentCount + 1
    const counterResp = new Response(String(newCount), {
        headers: {
            'cache-control': `public, max-age=${CONFIG.RATE_LIMIT_WINDOW}`
        }
    })
    event.waitUntil(cache.put(cacheKey, counterResp))
    return null
}

addEventListener('fetch', e => {
    const ret = fetchHandler(e).catch(err => makeErrorRes(err))
    e.respondWith(ret)
})

async function fetchHandler(e) {
    const req = e.request
    const urlObj = new URL(req.url)

    if (req.method === 'OPTIONS') {
        return PREFLIGHT_RESP
    }

    const rateLimited = await checkRateLimit(req)
    if (rateLimited) return rateLimited

    let path = urlObj.searchParams.get('q')
    if (path) {
        const normalizedPath = path.replace(/^\//, '').replace(/^https?:\/+/, 'https://')

        const patternMatch = GITHUB_PATTERNS.some(p => p.test(normalizedPath))
        let hostnameMatch = false
        try {
            const parsedUrl = new URL(normalizedPath)
            hostnameMatch = ALLOWED_HOSTNAMES.includes(parsedUrl.hostname.toLowerCase())
        } catch { hostnameMatch = false }

        if (patternMatch && hostnameMatch) {
            return Response.redirect(
                'https://' + urlObj.host + CONFIG.PREFIX + normalizedPath, 301
            )
        }
        return makeRes('Blocked: Invalid redirect target. Only GitHub URLs are allowed.', 403)
    }

    let rawPath = urlObj.pathname
    if (CONFIG.PREFIX !== '/' && rawPath.startsWith(CONFIG.PREFIX)) {
        rawPath = rawPath.slice(CONFIG.PREFIX.length)
    }
    path = rawPath.replace(/^\//, '').replace(/^https?:\/+/, 'https://')

    if (!path) {
        return serveIndex()
    }

    if (GITHUB_PATTERNS.some(p => p.test(path))) {
        return proxyRequest(e, req, path)
    }

    return makeRes(
        JSON.stringify({
            error: 'Not Found',
            message: 'Only GitHub URLs are supported.',
        }),
        404,
        { 'content-type': 'application/json; charset=utf-8' }
    )
}

function buildCacheKey(pathname) {
    const url = new URL(pathname.startsWith('http') ? pathname : `https://${pathname}`)
    const NO_SIMPLIFY_PATTERNS = [
        /^api\.github\.com$/,
        /\/releases\/download\//,
        /^gist\.(?:githubusercontent|github)\.com$/,
        /\/actions\/runs\/\d+\/artifacts\//,
    ]
    if (NO_SIMPLIFY_PATTERNS.some(p => p.test(url.hostname) || p.test(url.pathname))) {
        return new Request(url.href, { method: 'GET' });
    }
    const STABLE_PARAMS = ['ref', 'tag', 'branch', 'commit']
    for (const key of [...url.searchParams.keys()]) {
        if (!STABLE_PARAMS.includes(key)) url.searchParams.delete(key)
    }
    return new Request(url.href, { method: 'GET' })
}

async function proxyRequest(e, req, pathname) {
    const cacheKey = buildCacheKey(pathname)
    const cache = caches.default
    const dynamicCors = getDynamicCorsHeaders(req, pathname)
    const isArtifact = isArtifactPath(pathname)

    if (isArtifactPath(pathname)) {
        const targetUrl = pathname.startsWith('http') ? pathname : `https://${pathname}`;
        const urlObj = newUrl(targetUrl);
        if (!urlObj) return makeRes('Invalid target URL', 400);

        const probeHeaders = new Headers(req.headers);
        probeHeaders.delete('host');
        probeHeaders.delete('content-length');
        probeHeaders.delete('connection');
        probeHeaders.delete('keep-alive');

        try {
            const probeRes = await fetch(urlObj.href, {
                method: 'HEAD',
                headers: probeHeaders,
                redirect: 'manual',
                cf: { cacheEverything: false }
            });

            if ([301, 302, 303, 307, 308].includes(probeRes.status)) {
                const location = probeRes.headers.get('location');
                if (location) {
                    try {
                        const nextUrl = new URL(location, urlObj.href);
                        if (SAFE_REDIRECT_HOSTS.has(nextUrl.hostname) || isSafeAzureRedirect(nextUrl.hostname)) {
                            return new Response(null, {
                                status: 302,
                                headers: {
                                    'Location': location,
                                    'Access-Control-Allow-Origin': '*',
                                    'X-Cache-Status': 'ARTIFACT-DIRECT',
                                    'Cache-Control': 'no-store'
                                }
                            });
                        }
                    } catch (urlErr) {
                        console.error('[Artifact URL Parse Error]', location, urlErr);
                    }
                }
            }
        } catch (err) {
            console.error('[Artifact Direct Link Failed]', err);
        }
    }

    if (req.method === 'GET' && !isArtifact) {
        const cached = await cache.match(cacheKey)
        if (cached) {
            const clientEtag = req.headers.get('if-none-match')
            const clientLastModified = req.headers.get('if-modified-since')
            const cachedEtag = cached.headers.get('etag')
            const cachedLastModified = cached.headers.get('last-modified')

            if ((clientEtag && clientEtag === cachedEtag) ||
                (clientLastModified && clientLastModified === cachedLastModified)) {
                return new Response(null, {
                    status: 304,
                    headers: {
                        ...dynamicCors,
                        ...SECURITY_HEADERS,
                        'etag': cachedEtag || '',
                        'last-modified': cachedLastModified || '',
                        'x-cache-status': 'HIT-304'
                    }
                })
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
    if (!isArtifact) {
        reqHdrNew.delete('cookie')
        reqHdrNew.delete('authorization')
    }
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
            cacheEverything: true,
            cacheTtlByStatus: isArtifact
                ? { "200-299": 0, "301-399": 0, "404": 1 }
                : { "200-299": CONFIG.CACHE_TTL, "404": 1 },
        }
    }, 0)

    if (!response.ok && response.status !== 304 && response.status !== 206) {
        const errorHeaders = new Headers(response.headers)
        for (const [k, v] of Object.entries(dynamicCors)) errorHeaders.set(k, v)
        for (const [k, v] of Object.entries(SECURITY_HEADERS)) errorHeaders.set(k, v)
        return new Response(response.body, { status: response.status, headers: errorHeaders })
    }

    if (req.method === 'GET' && !isArtifact && (response.status >= 200 && response.status < 400)) {
        const contentLength = parseInt(response.headers.get('content-length') || '0', 10)
        const shouldCache = contentLength > 0 && contentLength <= CONFIG.MAX_CACHE_SIZE

        const finalHeaders = new Headers(response.headers)
        for (const [k, v] of Object.entries(dynamicCors)) finalHeaders.set(k, v)
        for (const [k, v] of Object.entries(SECURITY_HEADERS)) finalHeaders.set(k, v)

        if (shouldCache) {
            finalHeaders.set('Cache-Control', `public, max-age=${CONFIG.CACHE_TTL}`)
            finalHeaders.set('x-cache-status', 'MISS')

            const [forClient, forCache] = response.body.tee()

            e.waitUntil(cache.put(cacheKey, new Response(forCache, {
                status: response.status,
                headers: finalHeaders
            })))

            return new Response(forClient, { status: response.status, headers: finalHeaders })
        } else {
            finalHeaders.set('x-cache-status', contentLength > CONFIG.MAX_CACHE_SIZE ? 'BYPASS-LARGE' : 'BYPASS')
            return new Response(response.body, { status: response.status, headers: finalHeaders })
        }
    }

    const missHeaders = new Headers(response.headers)
    missHeaders.set('x-cache-status', isArtifact ? 'BYPASS-ARTIFACT' : 'BYPASS')
    for (const [k, v] of Object.entries(dynamicCors)) missHeaders.set(k, v)
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) missHeaders.set(k, v)
    return new Response(response.body, { status: response.status, headers: missHeaders })
}

async function handleProxyFetch(urlObj, init, redirectCount) {
    if (redirectCount > 5) return makeRes('Too many redirects', 508)
    try {
        const res = await fetch(urlObj.href, init)

        if ([301, 302, 303, 307, 308].includes(res.status)) {
            const location = res.headers.get('location')
            if (!location) return res

            const nextUrl = new URL(location, urlObj.href)

            if (SAFE_REDIRECT_HOSTS.has(nextUrl.hostname) ||
                GITHUB_PATTERNS.some(p => p.test(nextUrl.href)) ||
                isSafeAzureRedirect(nextUrl.hostname)) {
                return handleProxyFetch(nextUrl, init, redirectCount + 1)
            } else {
                const safeHeaders = new Headers(res.headers)
                safeHeaders.delete('set-cookie')
                safeHeaders.set('access-control-expose-headers', '*')
                for (const [k, v] of Object.entries(SECURITY_HEADERS)) safeHeaders.set(k, v)
                return new Response(null, { status: res.status, headers: safeHeaders })
            }
        }

        const resHdrNew = new Headers(res.headers)
        resHdrNew.delete('content-security-policy')
        resHdrNew.delete('clear-site-data')
        resHdrNew.delete('x-frame-options')

        return new Response(res.body, {
            status: res.status,
            headers: resHdrNew
        })
    } catch (err) {
        return makeRes('Proxy Error: ' + err.message, 502)
    }
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
        <div class="example">
            <div class="example-title">📃 合法输入示例：</div>
            <div class="example-list">
                <p>📄 https://github.com/user/repo/archive/master.zip</p>
                <p>📦 https://github.com/user/repo/archive/refs/heads/main.tar.gz</p>
                <p>🏷️ https://github.com/user/repo/tags</p>
                <p>ℹ️ https://github.com/user/repo/info/refs?service=git-upload-pack</p>
                <p>🔧 https://github.com/user/repo/git-upload-pack</p>
                <p>📂 https://github.com/user/repo/releases/download/v1.0/file.zip</p>
                <p>💾 https://github.com/user/repo/blob/main/README.md</p>
                <p>📝 https://github.com/user/repo/raw/main/src/index.js</p>
                <p>⏩ https://github.com/user/repo/actions/runs/123456/artifacts/789012</p>
                <p>📥 https://github.com/user/repo/actions/runs/123456/artifacts/789012/zip</p>
                <p>🌐 https://raw.githubusercontent.com/user/repo/main/file.txt</p>
                <p>🌐 https://raw.github.com/user/repo/main/file.txt</p>
                <p>🖨️ https://gist.githubusercontent.com/user/hash/raw/file.py</p>
                <p>🖨️ https://gist.github.com/user/hash</p>
                <p>☁️ https://api.github.com/repos/user/repo</p>
                <p>☁️ https://api.github.com/users/user</p>
                <p>🗜️ https://codeload.github.com/user/repo/tar.gz/main</p>
                <p>🗜️ https://codeload.github.com/user/repo/zip/refs/tags/v1.0</p>
                <p>🗜️ https://codeload.github.com/user/repo/legacy.zip/main</p>
                <p>🔗 https://objects.githubusercontent.com/github-production-upload/...</p>
                <p>🎨 https://github.githubassets.com/assets/mona-xxx.svg</p>
                <p>🤖 https://copilot.githubusercontent.com/...</p>
                <p>⚙️ https://actions.githubusercontent.com/...</p>
            </div>
        </div>
        <p style="margin-top:2rem;color:rgba(255,255,255,.6)"><a href="https://github.com/qfmc7040/CF-GH-Proxy/" style="color:inherit;text-decoration:none;border-bottom:1px dashed rgba(255,255,255,.4)">QFMC</a> 访问以参考项目</p>
    </div>
    <script>function toSubmit(e){e.preventDefault();const i=document.getElementsByName('q')[0];window.open(location.href.substr(0,location.href.lastIndexOf('/')+1)+i.value)}</script>
</body>
</html>`
    return new Response(html, {
        status: 200,
        headers: { 'content-type': 'text/html; charset=utf-8', ...CORS_HEADERS, ...SECURITY_HEADERS }
    })
}
