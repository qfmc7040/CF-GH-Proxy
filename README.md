# CF-GH-Proxy
本项目是一个基于 Cloudflare Workers 的 Github 镜像代理工具。它能够中转 Github 项目请求，解决一些访问限制和加速访问的问题。

## 参考图(开关夜间模式）

![白](image/白.png)

![黑](image/黑.png)

## Workers 部署方法
### 部署 Cloudflare Worker：

   - 在 [Cloudflare Worker](https://dash.cloudflare.com/) 控制台中创建一个新的 Worker。
   - 将 [worker.js](./worker.js) 的内容粘贴到 Worker 编辑器中。

### 配置 GITHUB_TOKEN（推荐）

不配置也能用，但所有访客共用 Cloudflare 的出口 IP，匿名额度只有 60 次/小时，很容易被别人用光。

1. 在 GitHub 建一个 Token：Settings → Developer settings → [Personal access tokens](https://github.com/settings/personal-access-tokens)。
   - **Classic token**（`Generate new token (classic)`）：只读公开数据一个 scope 都不用勾；要下载私有仓库的 Actions Artifacts，勾 `repo`（`repo` 已包含 Actions 读权限）。
   - **Fine-grained token**：这个 Token 能访问哪些仓库，就等于本代理能代理哪些仓库——两个部分共同决定，缺一不可：
     - `Repository access`：`Public Repositories`（只有公开仓库）/ `All repositories`（含私有仓库）/ `Only select repositories`（只放行勾选的那些仓库，公开私有都可以）。
     - `Permissions` → `Repositories` → Add permissions → `Actions: Read-only`（下载 Actions Artifacts 必需）；如需用本代理下载私有仓库的 Release 附件，再加 `Contents: Read-only`。
     ![Fine-grained personal access tokens](image/Fine-grained%20personal%20access%20tokens.png)
   - 举例：只想放行一个私有仓库的构建产物，就选 `Only select repositories` 并勾那个仓库，再给 `Actions: Read-only`。此时其他仓库的 artifact 下载会被上游拒绝（404/403），本代理不再做公开性判断，完全按这个 Token 的实际权限走。



2. 在 Cloudflare 控制台 → Workers & Pages → 选中这个 Worker → Settings → Variables and Secrets → Add。Type 选 **Secret**，Variable name 填 `GITHUB_TOKEN`，Value 填 Token。

![cloudflare](image/cloudflare配置.png)

3. **点 Deploy 才会生效**，代码不用改。生效后额度提升到每小时 5000 次。

取用顺序：调用方自己带 `Authorization` 就用调用方的，否则用 `GITHUB_TOKEN`。这个头只会发给 `api.github.com`，不会泄漏给 CDN 或其他目标。

## Release 列表模式

首页输入框下方有「Release 列表模式」开关（状态存在浏览器 localStorage，键名 `gh_proxy_release_mode`）。

- 开启后，按钮文字由 `Go` 变为 `获取列表`；输入 `github.com/owner/repo` 或 `owner/repo` 后提交，不再跳转，而是在浮窗里列出该仓库的 Release。
- 浮窗里每个 Release 显示 tag、标题、发布时间、作者、文件数量和已折叠的更新说明（超过 400 字可展开），以及各附件的大小；附件与 tag 链接都按本代理格式改写后再打开。每页 20 条，滚到底部可「加载更多」，翻页失败时保留已加载内容并给出「重试」。
- 数据来自本代理的 `/api.github.com/repos/<owner>/<repo>/releases`，因此同样受 `per_page`、`page` 与匿名额度限制；额度耗尽时浮窗内会提示 `x-ratelimit-reset` 对应的恢复时间。
- 关闭开关后按钮恢复 `Go`，行为与之前完全一致。
- 明确指向具体文件的链接不会被拦截，仍按原方式下载或预览：`releases/download/...`、`archive/...`、`blob/...`、`raw/...`、`tags/...`、`info/...`、`git-...` 以及 `raw.githubusercontent.com`、`codeload.github.com`、`gist.githubusercontent.com`、`raw.github.com` 的子路径，和以常见压缩包/安装包后缀结尾的链接。
- 无法识别为仓库的输入也不会进入浮窗，按原有逻辑跳转。

## Actions Artifacts 下载

可以直接走本代理下载 GitHub Actions 的构建产物（artifact）：

```
/<你的 Worker 域名>/api.github.com/repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip
```

也可以直接把 `https://api.github.com/repos/.../actions/artifacts/.../zip` 粘进首页输入框。

**网页地址也能直接用**：GitHub Actions 页面里的 artifact 链接是
`https://github.com/{owner}/{repo}/actions/runs/{run_id}/artifacts/{artifact_id}`，
在网页上点「下载」是前端 JS 另发请求，这个地址本身拿不到文件。本代理会把这种地址自动 302 到对应的 API zip 路径，所以下面两种写法等价：

```
/<你的 Worker 域名>/https://github.com/{owner}/{repo}/actions/runs/{run_id}/artifacts/{artifact_id}
/<你的 Worker 域名>/https://api.github.com/repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip
```

跳转只换地址，不放宽校验：落地的 API zip 请求仍要过下面的总开关。

**可下载范围由 Token 的权限决定**：本代理不再按仓库公开性做任何拦截，也不再请求 `/repos/{owner}/{repo}` 预检。

- **谁的身份**：调用方**自带 `Authorization`** 时优先用它，本代理不注入也不拦截，能下什么完全由调用方自己的 Token 决定；没有带时用部署方配置的 `GITHUB_TOKEN`。
- **能下什么**：完全由该 Token 的「仓库访问范围 + `Actions: Read` 权限」决定，Worker 不做可见性判断。公开仓库照常能下，私有仓库只要有权限也照样能下，没有任何额外限制。
- **文件字节是否经过本代理，取决于上游把下载指向哪个域**：这一跳由本代理的跟随白名单（`SAFE_REDIRECT_HOSTS` 与 `*.blob.core.windows.net` 等 Azure 下载域）决定。跳转目标在白名单内时，本代理跟随过去并把文件流式转发给你；不在白名单内时，本代理把上游那个 `302` 原样交还浏览器，由浏览器直接向 GitHub 的下载域取文件——这种情况下文件字节不经过本代理，本代理只负责给出地址。
- **权限不足时**：上游通常返回 `404`（GitHub 对无权访问的私有仓库返回 404，避免泄漏仓库是否存在），个别情况返回 `403`，artifact 过期也是 404。本代理保留原始状态码，只把响应体换成一句可读提示，说明「需要 Token 具备该仓库的 Actions 读取权限」，并指向本节；不会改写成 200，也不写入边缘缓存。
- **风险**：部署方 Token 能访问的私有仓库 artifact，对所有知道这个 Worker 域名的人都是开放的。请把 Token 范围压到最小——只要公开仓库就选 `Public Repositories`，要放行私有仓库就选 `Only select repositories` 逐一勾选。

其他说明：

- 想整体关掉这个能力，把 `CONFIG.ARTIFACT_DOWNLOAD_ENABLED` 设为 `false`：artifact zip 请求直接返回 `403`，不转发上游。
- artifact 下载响应标 `BYPASS-API` + `no-store`，不进边缘缓存，不会被匿名请求复用。
- 32 MB 大文件策略（`CONFIG.CACHE_MAX_SIZE` / `CONFIG.LARGE_CACHE_TTL`，超过阈值的响应标 `STREAM-LARGE`）**只作用于非 `api.github.com` 的静态下载路径**，例如 Releases 附件、Archive 包、raw 文件。artifact zip 的请求恒为 `api.github.com`，在 API 分支就已返回，标记是 `BYPASS-API`，**不会**出现 `STREAM-LARGE`，所以 32 MB 这个阈值不影响 artifact 的下载行为。
- 重定向到 `*.blob.core.windows.net` 的下载链接只在 query 里带 SAS 签名，**不带** `Authorization`。该头在跟随 302 时会重新按目标域名剥离，不会随重定向泄漏给 Azure 或其他下载域。

## 缓存与限流

- `api.github.com` 的响应默认仍不写边缘缓存，直接回源并带 `Cache-Control: no-store`，避免拿到过期的 Star 数等数据。
- 唯一例外是 Release 列表（`/repos/{owner}/{repo}/releases`）：它每次打开页面都会打一次 API，而匿名额度只有 60 次/小时，所以对它做 60 秒边缘短缓存（`CONFIG.API_CACHE_TTL`，与 GitHub 自己响应头里的 `max-age=60` 对齐），响应头带 `x-cache-status: MISS-API`。其余 API 路径不受影响，仍标 `BYPASS-API`。
- 调用方**自带 `Authorization`** 时既读不到也写不进这层缓存，避免把某个身份的数据发给别人；只有用部署方 `GITHUB_TOKEN` 取到的结果才会被缓存。
- 缓存键带完整查询参数（此前只取 pathname，导致 `?per_page=6` 与 `?per_page=2` 撞成同一个键、翻页与每页条数全部失效）。静态下载链接的签名参数仍由 `buildCacheKey` 内部清空，不会制造垃圾条目。
- 命中缓存时用当前配置重写 API 的 `Cache-Control`，不信任条目里存的旧值：否则一次错误的 `max-age` 会让这个键在边缘滞留很久。
- 其他 GitHub 静态资源仍按原策略缓存，但**只缓存 32 MB 以内的响应**（`CONFIG.CACHE_MAX_SIZE`）。更大的文件直接流式回源，不写边缘缓存：响应体 `tee()` 的两支共享背压，写缓存那一支慢会拖住发给客户端的那一支，大文件下载会被限速。这类响应头带 `x-cache-status: STREAM-LARGE`，可据此确认走的是直通路径。
- 超过 32 MB 的响应虽不进边缘缓存，但会补一个 `Cache-Control: public, max-age=86400`（`CONFIG.LARGE_CACHE_TTL`）交给浏览器，同一个文件重复下载不必再经过 Worker。GitHub 的下载源本身不发 `Cache-Control`，没有这个头浏览器每次都会重新拉。
- 未配置 Token 时，GitHub 对同一出口 IP 的匿名 API 额度是 60 次/小时；在 Worker 里配置 `GITHUB_TOKEN` 后提升到 5000 次/小时，见上一节。
- 额度耗尽时 GitHub 返回 `403` 或 `429`，并附带 `x-ratelimit-remaining: 0` 与 `x-ratelimit-reset`（本代理原样透传）。页面只在 `x-ratelimit-remaining` 确实为 `0` 时提示「额度已用尽 + 恢复时间」；403 但仍有额度时，提示的是「仓库被禁用 / 触发二级限流 / 不允许匿名访问」这类真实原因，不再一律归咎于额度。
- 代理请求中，`Authorization` 头只会转发给 `api.github.com`；其他目标（包括 GitHub 的 CDN、Azure 下载域）会移除该头。跟随 302 重定向时每一跳都会重新按目标域名判断一次，不会因为源站是 `api.github.com` 就把 Token 带到跳转后的域名。调用方未带该头且 Worker 配置了 `GITHUB_TOKEN` 时，由 Worker 补上，调用方自带的 Token 优先级更高。
- 支持 `release-assets.githubusercontent.com`、`github-releases.githubusercontent.com` 等 GitHub Release 下载直链（它们此前不在允许列表里，粘贴直链会 404）。
- 首页 HTML 也带 `Cache-Control: public, max-age=3600`（`CONFIG.INDEX_TTL`）。首页是纯静态模板，缓存后刷新不再触发 Worker 执行，可直接省每日请求额度；代价是改了首页样式后老访客最长要等 1 小时才看到新版本，改版期间可临时把该项调成 0。
- 限流只统计需要回源的请求：命中边缘缓存的请求不计入额度，因此单 IP 额度放宽为 30 秒 300 次。若需要更强的全局防护，建议在 Cloudflare 面板另配原生 Rate Limiting 规则（在边缘层拦截，不占用 Worker 执行时间，且计数全局共享）。
- 带 `Range` 的请求也会先查边缘缓存：若缓存里已有完整对象，直接从缓存切片返回 `206`，不再回源（响应头 `x-cache-status: HIT-RANGE`）。起点偏移超过 32 MB、单次切片超过 64 MB、缓存对象经过 gzip 压缩、或请求是多段 Range 时，仍走回源。把 `CONFIG.RANGE_CACHE_ENABLED` 设为 `false` 即可整体关闭该行为。`If-Range` 与缓存版本不匹配时按 RFC 返回完整 `200`。

# 致谢
[gh-proxy](https://github.com/hunshcn/gh-proxy)、[jsproxy](https://github.com/EtherDream/jsproxy/)、[CF-Workers-GitHub](https://github.com/cmliu/CF-Workers-GitHub/)、[CF-GitHub-Proxy](https://github.com/hubporg/CF-GitHub-Proxy)
