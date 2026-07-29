'use strict'

const CONFIG = {
    ASSET_URL: 'https://geekertao.github.io/gh-proxy/',
    PREFIX: '/',
    JSDELIVR: false,
    WHITE_LIST: [],
    CACHE_TTL: 86400,
}

const GITHUB_PATTERNS = [
    /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:releases|archive|tags|info|git-)\/.*$/i,
    /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:blob|raw)\/.*$/i,
    /^(?:https?:\/\/)?raw\.(?:githubusercontent|github)\.com\/.+?\/.+?\/.+?\/.+$/i,
    /^(?:https?:\/\/)?gist\.(?:githubusercontent|github)\.com\/.+?\/.+?\/.+$/i,
    /^(?:https?:\/\/)?api\.github\.com\/.*$/i,
]

const CORS_HEADERS = {
    'access-control-allow-origin': '*',
    'access-control-expose-headers': '*',
}

const PREFLIGHT_RESP = new Response(null, {
    status: 204,
    headers: {
        ...CORS_HEADERS,
        'access-control-allow-methods': 'GET,POST,PUT,PATCH,TRACE,DELETE,HEAD,OPTIONS',
        'access-control-max-age': '1728000',
    },
})

function makeRes(body, status = 200, headers = {}) {
    return new Response(body, { status, headers: { ...CORS_HEADERS, ...headers } })
}

function newUrl(urlStr) {
    try {
        return new URL(urlStr)
    } catch (err) {
        return null
    }
}

addEventListener('fetch', e => {
    const ret = fetchHandler(e).catch(err => makeRes('cfworker error:\n' + err.stack, 502))
    e.respondWith(ret)
})

async function fetchHandler(e) {
    const req = e.request
    const urlObj = new URL(req.url)

    let path = urlObj.searchParams.get('q')
    if (path) {
        return Response.redirect('https://' + urlObj.host + CONFIG.PREFIX + path, 301)
    }

    let rawPath = urlObj.pathname
    if (CONFIG.PREFIX !== '/' && rawPath.startsWith(CONFIG.PREFIX)) {
        rawPath = rawPath.slice(CONFIG.PREFIX.length)
    }
    path = rawPath.replace(/^\//, '').replace(/^https?:\/+/, 'https://')

    if (!path) {
        const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <title>GitHub 文件加速</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root {
            --primary-color: #1a1e21;
            --primary-hover: #0d1117;
            --text-color: #f0f6fc;
            --bg-gradient: linear-gradient(135deg, #1a1e21 0%, #0d1117 100%);
            --shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            min-height: 100vh;
            background: var(--bg-gradient);
            color: var(--text-color);
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container { width: 100%; max-width: 800px; padding: 40px 20px; text-align: center; }
        .logo { margin-bottom: 2rem; transform: scale(1); transition: transform 0.3s ease; }
        .logo:hover { transform: scale(1.1); }
        .title {
            font-size: 2.5rem; font-weight: 600; margin-bottom: 1rem;
            background: linear-gradient(45deg, #cdd5dd, #e2e8f0);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        .tips a { color: #9ba1a6; text-decoration: none; border-bottom: 1px dashed #9ba1a6; transition: all 0.2s ease; }
        .tips a:hover { color: #fff; border-bottom-color: #fff; }
        .search-container { position: relative; max-width: 600px; margin: 2rem auto; }
        .search-input {
            width: 100%; height: 56px; padding: 0 60px 0 24px; font-size: 1rem; color: #1f2937;
            background: rgba(255, 255, 255, 0.9); border: 2px solid transparent; border-radius: 12px;
            box-shadow: var(--shadow); transition: all 0.3s ease;
        }
        .search-input:focus { border-color: var(--primary-color); background: white; outline: none; box-shadow: 0 0 0 3px rgba(0, 102, 255, 0.2); }
        .search-button {
            position: absolute; right: 8px; top: 50%; transform: translateY(-50%);
            width: 44px; height: 44px; border: none; border-radius: 8px;
            background: var(--primary-color); color: white; cursor: pointer; transition: all 0.2s ease;
        }
        .search-button:hover { background: var(--primary-hover); transform: translateY(-50%) scale(1.05); }
        .tips { margin-top: 2rem; color: rgba(255, 255, 255, 0.8); line-height: 1.6; text-align: left; padding-left: 1.8rem; }
        .example-title {
            color: #9ba1a6; margin-bottom: 1.5rem; font-size: 1rem; font-weight: 700;
            position: relative; padding-bottom: 0.8rem; border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .example p { margin: 0.8rem 0; font-family: monospace; font-size: 0.95rem; color: rgba(255, 255, 255, 0.8); padding-left: 1.5rem; line-height: 1.4; word-break: break-all; }
        .example { margin-top: 2rem; padding: 1.8rem; background: rgba(255, 255, 255, 0.05); border-radius: 12px; text-align: left; border: 1px solid rgba(255, 255, 255, 0.1); overflow-wrap: break-word; word-wrap: break-word; }
        @media (max-width: 640px) {
            .container { padding: 20px; }
            .title { font-size: 2rem; }
            .search-input { height: 50px; font-size: 0.9rem; }
            .search-button { width: 38px; height: 38px; }
            .example { padding: 1rem; font-size: 0.8rem; padding-left: 1rem; padding-right: 1rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <a href="https://github.com/Geekertao/CF-Workers-GitHub-Proxy" target="_blank">
                <svg xmlns="http://www.w3.org/2000/svg" width="120" height="90" viewBox="0 0 98 96" fill="#ffffff">
                    <path fill-rule="evenodd" clip-rule="evenodd" d="M48.854 0C21.839 0 0 22 0 49.217c0 21.756 13.993 40.172 33.405 46.69 2.427.49 3.316-1.059 3.316-2.362 0-1.141-.08-5.052-.08-9.127-13.59 2.934-16.42-5.867-16.42-5.867-2.184-5.704-5.42-7.17-5.42-7.17-4.448-3.015.324-3.015.324-3.015 4.934.326 7.523 5.052 7.523 5.052 4.367 7.496 11.404 5.378 14.235 4.074.404-3.178 1.699-5.378 3.074-6.6-10.839-1.141-22.243-5.378-22.243-24.283 0-5.378 1.94-9.778 5.014-13.2-.485-1.222-2.184-6.275.486-13.038 0 0 4.125-1.304 13.426 5.052a46.97 46.97 0 0 1 12.214-1.63c4.125 0 8.33.571 12.213 1.63 9.302-6.356 13.427-5.052 13.427-5.052 2.67 6.763.97 11.816.485 13.038 3.155 3.422 5.015 7.822 5.015 13.2 0 18.905-11.404 23.06-22.324 24.283 1.78 1.548 3.316 4.481 3.316 9.126 0 6.6-.08 11.897-.08 13.526 0 1.304.89 2.853 3.316 2.364 19.412-6.52 33.405-24.935 33.405-46.691C97.707 22 75.788 0 48.854 0z"/>
                </svg>
            </a>
        </div>
        <h1 class="title">GitHub文件及api加速</h1>
        <form onsubmit="toSubmit(event)" class="search-container">
            <input type="text" class="search-input" name="q" placeholder="请输入GitHub文件or api链接" pattern="^((https|http)://)?(github.com/.+?/.+?/(?:releases|archive|blob|raw|suites)|((?:raw|gist|api).(?:githubusercontent|github).com))/.+$" required>
            <button type="submit" class="search-button">
                <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M13 5l7 7-7 7M5 5l7 7-7 7" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </button>
        </form>
        <div class="example">
            <div class="example-title">📃 合法输入示例：</div>
            <p>📄 分支源码：https://github.com/xxxxxx/project/archive/master.zip</p>
            <p>📁 release源码：https://github.com/xxxxxx/project/archive/v0.1.0.tar.gz</p>
            <p>📂 release文件：https://github.com/xxxxxx/project/releases/download/v0.1.0/example.zip</p>
            <p>💾 commit文件：https://github.com/xxxxxx/project/blob/123/filename</p>
            <p>🖨️ gist：https://gist.githubusercontent.com/xxxxxx/123/raw/cmd.py</p>
            <p>☁️ api： https://api.github.com/repos/xxxxxx/CF-Workers-GitHub-Proxy</p>
        </div>
            <p><a href="https://github.com/qfmc7040/CF-GitHub-Proxy/">QFMC</a> 访问以参考项目</p>
    </div>
    <script>
        function toSubmit(e) {
            e.preventDefault();
            const input = document.getElementsByName('q')[0];
            const baseUrl = location.href.substr(0, location.href.lastIndexOf('/') + 1);
            window.open(baseUrl + input.value);
        }
    </script>
</body>
</html>`;
        return new Response(html, {
            status: 200,
            headers: { 'content-type': 'text/html; charset=utf-8', ...CORS_HEADERS }
        });
    }

    if (GITHUB_PATTERNS.some(p => p.test(path))) {
        return proxyRequest(e, req, path)
    } else {
        return fetch(CONFIG.ASSET_URL + path)
    }
}

async function proxyRequest(e, req, pathname) {
    if (req.method === 'OPTIONS' && req.headers.has('access-control-request-headers')) {
        return PREFLIGHT_RESP
    }

    if (CONFIG.WHITE_LIST.length > 0) {
        const isAllowed = CONFIG.WHITE_LIST.some(i => pathname.includes(i))
        if (!isAllowed) return new Response("blocked", { status: 403 })
    }

    const cacheKey = new Request(pathname, { method: 'GET' })
    const cache = caches.default

    if (req.method === 'GET') {
        const cached = await cache.match(cacheKey)
        if (cached) return cached
    }

    const targetUrl = pathname.startsWith('http') ? pathname : `https://${pathname}`
    const urlObj = newUrl(targetUrl)
    if (!urlObj) return makeRes('Invalid target URL', 400)

    const reqHdrNew = new Headers(req.headers)
    reqHdrNew.delete('cookie')
    reqHdrNew.delete('authorization')

    const init = {
        method: req.method,
        headers: reqHdrNew,
        redirect: 'manual',
        body: req.body
    }

    const response = await handleProxyFetch(urlObj, init, 0)

    if (req.method === 'GET' && response.status >= 200 && response.status < 400) {
        const cachedResponse = new Response(response.body, {
            status: response.status,
            headers: new Headers(response.headers)
        })
        cachedResponse.headers.set('Cache-Control', `public, max-age=${CONFIG.CACHE_TTL}`)
        e.waitUntil(cache.put(cacheKey, cachedResponse.clone()))
        return cachedResponse
    }

    return response
}

async function handleProxyFetch(urlObj, init, redirectCount) {
    if (redirectCount > 5) return makeRes('Too many redirects', 508)

    try {
        const res = await fetch(urlObj.href, init)

        if ([301, 302, 303, 307, 308].includes(res.status)) {
            let location = res.headers.get('location')
            if (!location) return res

            const nextUrl = new URL(location, urlObj.href)

            if (GITHUB_PATTERNS.some(p => p.test(nextUrl.href))) {
                return new Response(null, {
                    status: res.status,
                    headers: {
                        ...Object.fromEntries(res.headers),
                        location: CONFIG.PREFIX + nextUrl.href,
                        ...CORS_HEADERS
                    }
                })
            }

            return handleProxyFetch(nextUrl, init, redirectCount + 1)
        }

        const resHdrNew = new Headers(res.headers)
        resHdrNew.delete('content-security-policy')
        resHdrNew.delete('clear-site-data')
        resHdrNew.delete('x-frame-options')

        return new Response(res.body, {
            status: res.status,
            headers: { ...resHdrNew, ...CORS_HEADERS }
        })

    } catch (err) {
        return makeRes('Proxy Error: ' + err.message, 502)
    }
}
