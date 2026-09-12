const enc = new TextEncoder();
const SESSION_TTL = 8 * 60 * 60;
const COOKIE = '__Host-note_session';
const hex = bytes => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
const digest = async (algorithm, value) => hex(await crypto.subtle.digest(algorithm, enc.encode(value)));
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status, headers: { 'Content-Type': 'application/json;charset=UTF-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers }
});
const cookie = (value, age = SESSION_TTL) => `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;
function equal(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}
const envValue = value => typeof value === 'string' ? value.trim() : '';
async function signingKey(env) {
  const material = JSON.stringify([envValue(env.SESSION_SECRET), envValue(env.PASSWORD_SALT), envValue(env.PASSWORD_HASH), loginPath(env)]);
  return crypto.subtle.importKey('raw', await crypto.subtle.digest('SHA-256', enc.encode(material)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
function loginPath(env) {
  const value = typeof env.login === 'string' ? env.login.trim().replace(/^\/+|\/+$/g, '') : '';
  return /^[A-Za-z0-9][A-Za-z0-9_-]{2,127}$/.test(value) && !['api', 'robots.txt'].includes(value) ? '/' + value : null;
}
function missingConfig(env) {
  return [
    [!!envValue(env.PASSWORD_HASH), 'PASSWORD_HASH（填 32 位十六进制加盐 MD5，或直接填密码原文）'],
    [!!envValue(env.PASSWORD_SALT), 'PASSWORD_SALT（任意非空字符串，建议随机十六进制）'],
    [!!envValue(env.SESSION_SECRET), 'SESSION_SECRET（任意非空字符串，建议随机十六进制）'],
    [!!env.CLOUD_EDITOR_KV, 'CLOUD_EDITOR_KV（Settings → Bindings 里的 KV 绑定）'],
    [!!env.LOGIN_RATE_LIMITER, 'LOGIN_RATE_LIMITER（登录限流绑定）'],
  ].filter(([ok]) => !ok).map(([, label]) => label);
}
function pageResponse(content, privatePage = false) {
  return new Response(content, { headers: {
    'Content-Type': 'text/html;charset=UTF-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
    ...(privatePage ? { 'X-Robots-Tag': 'noindex, nofollow, noarchive' } : {}),
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
  } });
}
async function makeSession(env) {
  const payload = `${Math.floor(Date.now() / 1000) + SESSION_TTL}.${hex(crypto.getRandomValues(new Uint8Array(32)))}`;
  return payload + '.' + hex(await crypto.subtle.sign('HMAC', await signingKey(env), enc.encode(payload)));
}
async function authenticated(request, env) {
  const token = (request.headers.get('Cookie') || '').split(';').map(s => s.trim()).find(s => s.startsWith(COOKIE + '='))?.slice(COOKIE.length + 1);
  if (!token || !/^\d{10}\.[a-f0-9]{64}\.[a-f0-9]{64}$/.test(token)) return false;
  const [expires, nonce, signature] = token.split('.');
  const now = Math.floor(Date.now() / 1000);
  if (+expires <= now || +expires > now + SESSION_TTL) return false;
  return crypto.subtle.verify('HMAC', await signingKey(env), Uint8Array.from(signature.match(/../g), b => parseInt(b, 16)), enc.encode(expires + '.' + nonce));
}
class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
async function boundedBody(message, limit) {
  if (Number(message.headers.get('Content-Length')) > limit) throw new HttpError(413, '内容超过大小限制');
  const reader = message.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks = []; let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) { await reader.cancel(); throw new HttpError(413, '内容超过大小限制'); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const result = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
  return result;
}
async function readJson(request, limit) {
  if (!/^application\/json(?:;|$)/i.test(request.headers.get('Content-Type') || '')) throw new HttpError(415, '请使用 JSON 请求');
  try { return JSON.parse(new TextDecoder().decode(await boundedBody(request, limit))); }
  catch (error) { if (error instanceof HttpError) throw error; throw new HttpError(400, 'JSON 格式错误'); }
}
function validData(data) {
  const item = value => value && typeof value === 'object' && typeof value.id === 'string' && /^[a-zA-Z0-9_-]{1,128}$/.test(value.id) && typeof value.title === 'string';
  return data && Array.isArray(data.notes) && Array.isArray(data.novels) &&
    data.notes.every(n => item(n) && typeof n.content === 'string') &&
    data.novels.every(n => item(n) && (n.type === 'short' ? typeof n.content === 'string' :
      Array.isArray(n.volumes) && n.volumes.every(v => item(v) && Array.isArray(v.chapters) && v.chapters.every(c => item(c) && typeof c.content === 'string'))));
}
function allowedTarget(raw, env) {
  let target;
  try { target = new URL(raw); } catch { throw new HttpError(400, '网址格式错误'); }
  const allowed = (env.PROXY_ALLOWED_HOSTS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  if (!allowed.length) throw new HttpError(403, '请先配置采集域名 PROXY_ALLOWED_HOSTS');
  if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password || target.port || !allowed.includes(target.hostname.toLowerCase()) || target.hostname === 'localhost' || target.hostname.endsWith('.local') || target.hostname.endsWith('.internal') || /^[\d.]+$/.test(target.hostname) || target.hostname.includes(':')) throw new HttpError(403, '采集域名未授权');
  return target;
}
const HISTORY_KEY = 'user_creative_history';
async function readHistory(env) {
  try {
    const entries = JSON.parse(await env.CLOUD_EDITOR_KV.get(HISTORY_KEY) || '[]');
    return Array.isArray(entries) ? entries.filter(e => e && /^\d{13}$/.test(String(e.ts)) && typeof e.data === 'string' && Number.isFinite(e.size)) : [];
  } catch { return []; }
}
async function saveHistory(env, previousRaw, force = false) {
  if (!previousRaw || previousRaw.length > 15 * 1024 * 1024) return;
  try {
    const entries = await readHistory(env);
    if (!force && entries[0] && Date.now() - entries[0].ts < 10 * 60 * 1000) return;
    entries.unshift({ ts: Date.now(), size: previousRaw.length, data: previousRaw });
    const keep = []; let total = 0;
    for (const entry of entries.slice(0, 10)) {
      total += entry.size;
      if (total > 15 * 1024 * 1024) break;
      keep.push(entry);
    }
    await env.CLOUD_EDITOR_KV.put(HISTORY_KEY, JSON.stringify(keep));
  } catch {}
}
export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const entrance = loginPath(env);
      if (request.method === 'GET' && entrance && [entrance, entrance + '/'].includes(url.pathname)) return pageResponse(htmlContent, true);
      if (request.method === 'GET' && !url.pathname.includes('/api/')) return pageResponse(publicContent);
      if (!entrance || !url.pathname.startsWith(entrance + '/api/')) return json({ error: 'Not Found' }, 404);
      url.pathname = url.pathname.slice(entrance.length);
      if (!url.pathname.startsWith('/api/')) return json({ error: 'Not Found' }, 404);
      if (request.method === 'POST' && (request.headers.get('Origin') !== url.origin || request.headers.get('X-Requested-With') !== 'note-editor')) return json({ error: '请求来源无效' }, 403);
      const missing = missingConfig(env);
      if (missing.length) return json({ error: '服务配置不完整，缺少：' + missing.join('；') }, 503);
      if (url.pathname === '/api/login' && request.method === 'POST') {
        const { success } = await env.LOGIN_RATE_LIMITER.limit({ key: request.headers.get('CF-Connecting-IP') || 'local' });
        if (!success) return json({ error: '尝试次数过多，请稍后重试' }, 429, { 'Retry-After': '60' });
        const body = await readJson(request, 4096);
        if (!body || typeof body.password !== 'string' || !body.password || body.password.length > 1024) return json({ error: '密码格式错误' }, 400);
        const salt = envValue(env.PASSWORD_SALT);
        const stored = envValue(env.PASSWORD_HASH);
        const actual = await digest('MD5', salt + ':' + body.password);
        const expected = /^[a-f0-9]{32}$/i.test(stored) ? stored.toLowerCase() : await digest('MD5', salt + ':' + stored);
        if (!equal(actual, expected)) return json({ error: '密码错误' }, 401);
        return json({ success: true }, 200, { 'Set-Cookie': cookie(await makeSession(env)) });
      }
      if (url.pathname === '/api/logout' && request.method === 'POST') return json({ success: true }, 200, { 'Set-Cookie': cookie('', 0) });
      if (!await authenticated(request, env)) return json({ error: '登录已失效，请重新登录' }, 401);
      if (url.pathname === '/api/session' && request.method === 'GET') return json({ authenticated: true });
      if (url.pathname === '/api/get-data' && request.method === 'GET') {
        const raw = await env.CLOUD_EDITOR_KV.get('user_creative_data');
        return json(raw ? JSON.parse(raw) : { notes: [], novels: [] });
      }
      if (url.pathname === '/api/save-data' && request.method === 'POST') {
        const data = await readJson(request, 20 * 1024 * 1024);
        if (!validData(data)) return json({ error: '笔记或小说数据结构不正确' }, 400);
        const serialized = JSON.stringify(data);
        const existing = await env.CLOUD_EDITOR_KV.get('user_creative_data');
        if (existing !== serialized) await saveHistory(env, existing, url.searchParams.get('history') === 'force');
        await env.CLOUD_EDITOR_KV.put('user_creative_data', serialized);
        return json({ success: true });
      }
      if (url.pathname === '/api/history' && request.method === 'GET') {
        return json({ items: (await readHistory(env)).map(e => ({ ts: e.ts, size: e.size })) });
      }
      if (url.pathname === '/api/history-item' && request.method === 'GET') {
        const ts = Number(url.searchParams.get('ts'));
        const entry = (await readHistory(env)).find(e => e.ts === ts);
        if (!entry) return json({ error: '历史版本不存在或已被清理' }, 404);
        return new Response(entry.data, { headers: { 'Content-Type': 'application/json;charset=UTF-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
      }
      if (url.pathname === '/api/proxy' && request.method === 'GET') {
        let target = allowedTarget(url.searchParams.get('url'), env);
        const signal = AbortSignal.timeout(15000);
        for (let hop = 0; hop < 5; hop++) {
          const response = await fetch(target, { redirect: 'manual', signal, headers: { 'User-Agent': 'Mozilla/5.0' } });
          if ([301, 302, 303, 307, 308].includes(response.status)) {
            const location = response.headers.get('Location');
            await response.body?.cancel();
            if (!location) throw new HttpError(502, '目标站重定向无效');
            target = allowedTarget(new URL(location, target).href, env); continue;
          }
          if (!response.ok) { await response.body?.cancel(); throw new HttpError(502, '目标站返回错误'); }
          const bytes = await boundedBody(response, 5 * 1024 * 1024);
          const charset = /gbk|gb2312/i.test(response.headers.get('Content-Type') || '') ? 'gbk' : 'utf-8';
          return new Response(new TextDecoder(charset).decode(bytes), { headers: { 'Content-Type': 'text/plain;charset=UTF-8', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' } });
        }
        throw new HttpError(502, '目标站重定向过多');
      }
      return json({ error: '接口不存在或请求方法错误' }, 404);
    } catch (error) {
      return json({ error: error instanceof HttpError ? error.message : '服务暂时不可用，请稍后重试' }, error instanceof HttpError ? error.status : 500);
    }
  }
};


// MARKDOWN_VENDOR_START
const markdownVendor = "(()=>{function It(){return{async:!1,breaks:!1,extensions:null,gfm:!0,hooks:null,pedantic:!1,renderer:null,silent:!1,tokenizer:null,walkTokens:null}}var de=It();function Cn(t){de=t}var he={exec:()=>null};function Ae(t){let e=[];return n=>{let i=Math.max(0,Math.min(3,n-1)),s=e[i];return s||(s=t(i),e[i]=s),s}}function T(t,e=\"\"){let n=typeof t==\"string\"?t:t.source,i={replace:(s,o)=>{let c=typeof o==\"string\"?o:o.source;return c=c.replace(N.caret,\"$1\"),n=n.replace(s,c),i},getRegex:()=>new RegExp(n,e)};return i}var $r=((t=\"\")=>{try{return!!new RegExp(\"(?<=1)(?<!1)\"+t)}catch{return!1}})(),N={codeRemoveIndent:/^(?: {1,4}| {0,3}\\t)/gm,outputLinkReplace:/\\\\([\\[\\]])/g,indentCodeCompensation:/^(\\s+)(?:```)/,beginningSpace:/^\\s+/,endingHash:/#$/,startingSpaceChar:/^ /,endingSpaceChar:/ $/,endingSpaceTabChar:/[ \\t]$/,nonSpaceChar:/[^ ]/,newLineCharGlobal:/\\n/g,tabCharGlobal:/\\t/g,multipleSpaceGlobal:/\\s+/g,blankLine:/^[ \\t]*$/,doubleBlankLine:/\\n[ \\t]*\\n[ \\t]*$/,blockquoteStart:/^ {0,3}>/,blockquoteSetextReplace:/\\n {0,3}((?:=+|-+) *)(?=\\n|$)/g,blockquoteSetextReplace2:/^ {0,3}>[ \\t]?/gm,listReplaceNesting:/^ {1,4}(?=( {4})*[^ ])/g,listIsTask:/^\\[[ xX]\\] +\\S/,listReplaceTask:/^\\[[ xX]\\] +/,listTaskCheckbox:/\\[[ xX]\\]/,anyLine:/\\n.*\\n/,hrefBrackets:/^<(.*)>$/,tableDelimiter:/[:|]/,tableAlignChars:/^\\||\\| *$/g,tableRowBlankLine:/\\n[ \\t]*$/,tableAlignRight:/^ *-+: *$/,tableAlignCenter:/^ *:-+: *$/,tableAlignLeft:/^ *:-+ *$/,startATag:/^<a /i,endATag:/^<\\/a>/i,startPreScriptTag:/^<(pre|code|kbd|script)(\\s|>)/i,endPreScriptTag:/^<\\/(pre|code|kbd|script)(\\s|>)/i,startAngleBracket:/^</,endAngleBracket:/>$/,pedanticHrefTitle:/^([^'\"]*[^\\s])\\s+(['\"])(.*)\\2/,unicodeAlphaNumeric:/[\\p{L}\\p{N}]/u,escapeTest:/[&<>\"']/,escapeReplace:/[&<>\"']/g,escapeTestNoEncode:/[<>\"']|&(?!(#\\d{1,7}|#[Xx][a-fA-F0-9]{1,6}|\\w+);)/,escapeReplaceNoEncode:/[<>\"']|&(?!(#\\d{1,7}|#[Xx][a-fA-F0-9]{1,6}|\\w+);)/g,caret:/(^|[^\\[])\\^/g,percentDecode:/%25/g,findPipe:/\\|/g,splitPipe:/ \\|/,slashPipe:/\\\\\\|/g,carriageReturn:/\\r\\n|\\r/g,spaceLine:/^ +$/gm,notSpaceStart:/^\\S*/,endingNewline:/\\n$/,listItemRegex:t=>new RegExp(`^( {0,3}${t})((?:[\t ][^\\\\n]*)?(?:\\\\n|$))`),nextBulletRegex:Ae(t=>new RegExp(`^ {0,${t}}(?:[*+-]|\\\\d{1,9}[.)])((?:[ \t][^\\\\n]*)?(?:\\\\n|$))`)),hrRegex:Ae(t=>new RegExp(`^ {0,${t}}((?:- *){3,}|(?:_ *){3,}|(?:\\\\* *){3,})(?:\\\\n+|$)`)),fencesBeginRegex:Ae(t=>new RegExp(`^ {0,${t}}(?:\\`\\`\\`|~~~)`)),headingBeginRegex:Ae(t=>new RegExp(`^ {0,${t}}#`)),htmlBeginRegex:Ae(t=>new RegExp(`^ {0,${t}}<(?:[a-z].*>|!--)`,\"i\")),blockquoteBeginRegex:Ae(t=>new RegExp(`^ {0,${t}}>`))},vr=/^(?:[ \\t]*(?:\\n|$))+/,Ur=/^((?: {4}| {0,3}\\t)[^\\n]+(?:\\n(?:[ \\t]*(?:\\n|$))*)?)+/,Fr=/^ {0,3}(`{3,}(?=[^`\\n]*(?:\\n|$))|~{3,})([^\\n]*)(?:\\n|$)(?:|([\\s\\S]*?)(?:\\n|$))(?: {0,3}\\1[~`]* *(?=\\n|$)|$)/,Me=/^ {0,3}((?:-[\\t ]*){3,}|(?:_[ \\t]*){3,}|(?:\\*[ \\t]*){3,})(?:\\n+|$)/,Br=/^ {0,3}(#{1,6})(?=\\s|$)(.*)(?:\\n+|$)/,Dt=/ {0,3}(?:[*+-]|\\d{1,9}[.)])/,Nn=/^(?!bull |blockCode|fences|blockquote|heading|html|table)((?:.|\\n(?!\\s*?\\n|bull |blockCode|fences|blockquote|heading|html|table))+?)\\n {0,3}(=+|-+) *(?:\\n+|$)/,zn=T(Nn).replace(/bull/g,Dt).replace(/blockCode/g,/(?: {4}| {0,3}\\t)/).replace(/fences/g,/ {0,3}(?:`{3,}|~{3,})/).replace(/blockquote/g,/ {0,3}>/).replace(/heading/g,/ {0,3}#{1,6}(?:\\s|$)/).replace(/html/g,/ {0,3}<[^\\n>]+>\\n/).replace(/\\|table/g,\"\").getRegex(),Hr=T(Nn).replace(/bull/g,Dt).replace(/blockCode/g,/(?: {4}| {0,3}\\t)/).replace(/fences/g,/ {0,3}(?:`{3,}|~{3,})/).replace(/blockquote/g,/ {0,3}>/).replace(/heading/g,/ {0,3}#{1,6}(?:\\s|$)/).replace(/html/g,/ {0,3}<[^\\n>]+>\\n/).replace(/table/g,/ {0,3}\\|?(?:[:\\- ]*\\|)+[\\:\\- ]*\\n/).getRegex(),Pt=/^([^\\n]+(?:\\n(?!hr|heading|lheading|blockquote|fences|list|html|table|[ \\t]+\\n)[^\\n]+)*)/,Gr=/^[^\\n]+/,Ct=/(?!\\s*\\])(?:\\\\[\\s\\S]|[^\\[\\]\\\\])+/,Wr=T(/^ {0,3}\\[(label)\\]: *(?:\\n[ \\t]*)?([^<\\s][^\\s]*|<.*?>)(?:(?: +(?:\\n[ \\t]*)?| *\\n[ \\t]*)(title))? *(?:\\n+|$)/).replace(\"label\",Ct).replace(\"title\",/(?:\"(?:\\\\\"?|[^\"\\\\])*\"|'[^'\\n]*(?:\\n[^'\\n]+)*\\n?'|\\([^()]*\\))/).getRegex(),qr=T(/^(bull)([ \\t][^\\n]*?)?(?:\\n|$)/).replace(/bull/g,Dt).getRegex(),lt=\"address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|li|link|main|menu|menuitem|meta|nav|noframes|ol|optgroup|option|p|param|search|section|summary|table|tbody|td|tfoot|th|thead|title|tr|track|ul\",Nt=/<!--(?:-?>|[\\s\\S]*?(?:-->|$))/,jr=T(\"^ {0,3}(?:<(script|pre|style|textarea)[\\\\s>][\\\\s\\\\S]*?(?:</\\\\1>[^\\\\n]*\\\\n*|$)|comment[^\\\\n]*(\\\\n+|$)|<\\\\?[\\\\s\\\\S]*?(?:\\\\?>[^\\\\n]*\\\\n*|$)|<![A-Z][\\\\s\\\\S]*?(?:>[^\\\\n]*\\\\n*|$)|<!\\\\[CDATA\\\\[[\\\\s\\\\S]*?(?:\\\\]\\\\]>[^\\\\n]*\\\\n*|$)|</?(tag)(?: +|\\\\n|/?>)[\\\\s\\\\S]*?(?:(?:\\\\n[ \t]*)+\\\\n|$)|<(?!script|pre|style|textarea)([a-z][a-z0-9-]*)(?:attribute)*? */?>(?=[ \\\\t]*(?:\\\\n|$))[\\\\s\\\\S]*?(?:(?:\\\\n[ \t]*)+\\\\n|$)|</(?!script|pre|style|textarea)[a-z][a-z0-9-]*\\\\s*>(?=[ \\\\t]*(?:\\\\n|$))[\\\\s\\\\S]*?(?:(?:\\\\n[ \t]*)+\\\\n|$))\",\"i\").replace(\"comment\",Nt).replace(\"tag\",lt).replace(\"attribute\",/ +[a-zA-Z:_][\\w.:-]*(?: *= *\"[^\"\\n]*\"| *= *'[^'\\n]*'| *= *[^\\s\"'=<>`]+)?/).getRegex(),Mn=t=>T(Pt).replace(\"hr\",Me).replace(\"heading\",\" {0,3}#{1,6}(?:\\\\s|$)\").replace(\"|lheading\",\"\").replace(\"|table\",\"\").replace(\"blockquote\",\" {0,3}>\").replace(\"fences\",\" {0,3}(?:`{3,}(?=[^`\\\\n]*(?:\\\\n|$))|~~~)[^\\\\n]*(?:\\\\n|$)\").replace(\"list\",t).replace(\"html\",\"</?(?:tag)(?: +|\\\\n|/?>)|<(?:script|pre|style|textarea|!--)\").replace(\"tag\",lt).getRegex(),Yr=Mn(/ {0,3}(?:[*+-]|1[.)])[ \\t]+[^ \\t\\n]/),Zr=Mn(/ {0,3}(?:[*+-]|\\d{1,9}[.)])(?:[ \\t]|\\n|$)/),Xr=T(/^( {0,3}> ?(paragraph|[^\\n]*)(?:\\n|$))+/).replace(\"paragraph\",Zr).getRegex(),zt={blockquote:Xr,code:Ur,def:Wr,fences:Fr,heading:Br,hr:Me,html:jr,lheading:zn,list:qr,newline:vr,paragraph:Yr,table:he,text:Gr},En=T(\"^ *([^\\\\n ].*)\\\\n {0,3}((?:\\\\| *)?:?-+:? *(?:\\\\| *:?-+:? *)*(?:\\\\| *)?)(?:\\\\n((?:(?! *\\\\n|hr|heading|blockquote|code|fences|list|html).*(?:\\\\n|$))*)\\\\n*|$)\").replace(\"hr\",Me).replace(\"heading\",\" {0,3}#{1,6}(?:\\\\s|$)\").replace(\"blockquote\",\" {0,3}>\").replace(\"code\",\"(?: {4}| {0,3}\t)[^\\\\n]\").replace(\"fences\",\" {0,3}(?:`{3,}(?=[^`\\\\n]*(?:\\\\n|$))|~~~)[^\\\\n]*(?:\\\\n|$)\").replace(\"list\",\" {0,3}(?:[*+-]|1[.)])[ \\\\t]\").replace(\"html\",\"</?(?:tag)(?: +|\\\\n|/?>)|<(?:script|pre|style|textarea|!--)\").replace(\"tag\",lt).getRegex(),Qr={...zt,lheading:Hr,table:En,paragraph:T(Pt).replace(\"hr\",Me).replace(\"heading\",\" {0,3}#{1,6}(?:\\\\s|$)\").replace(\"|lheading\",\"\").replace(\"table\",En).replace(\"blockquote\",\" {0,3}>\").replace(\"fences\",\" {0,3}(?:`{3,}(?=[^`\\\\n]*(?:\\\\n|$))|~~~)[^\\\\n]*(?:\\\\n|$)\").replace(\"list\",\" {0,3}(?:[*+-]|1[.)])[ \\\\t]+[^ \\\\t\\\\n]\").replace(\"html\",\"</?(?:tag)(?: +|\\\\n|/?>)|<(?:script|pre|style|textarea|!--)\").replace(\"tag\",lt).getRegex()},Vr={...zt,html:T(`^ *(?:comment *(?:\\\\n|\\\\s*$)|<(tag)[\\\\s\\\\S]+?</\\\\1> *(?:\\\\n{2,}|\\\\s*$)|<tag(?:\"[^\"]*\"|'[^']*'|\\\\s[^'\"/>\\\\s]*)*?/?> *(?:\\\\n{2,}|\\\\s*$))`).replace(\"comment\",Nt).replace(/tag/g,\"(?!(?:a|em|strong|small|s|cite|q|dfn|abbr|data|time|code|var|samp|kbd|sub|sup|i|b|u|mark|ruby|rt|rp|bdi|bdo|span|br|wbr|ins|del|img)\\\\b)\\\\w+(?!:|[^\\\\w\\\\s@]*@)\\\\b\").getRegex(),def:/^ *\\[([^\\]]+)\\]: *<?([^\\s>]+)>?(?: +([\"(][^\\n]+[\")]))? *(?:\\n+|$)/,heading:/^(#{1,6})(.*)(?:\\n+|$)/,fences:he,lheading:/^(.+?)\\n {0,3}(=+|-+) *(?:\\n+|$)/,paragraph:T(Pt).replace(\"hr\",Me).replace(\"heading\",` *#{1,6} *[^\n]`).replace(\"lheading\",zn).replace(\"|table\",\"\").replace(\"blockquote\",\" {0,3}>\").replace(\"|fences\",\"\").replace(\"|list\",\"\").replace(\"|html\",\"\").replace(\"|tag\",\"\").getRegex()},Kr=/^\\\\([!\"#$%&'()*+,\\-./:;<=>?@\\[\\]\\\\^_`{|}~])/,Jr=/^(`+)([^`]|[^`][\\s\\S]*?[^`])\\1(?!`)/,$n=/^( {2,}|\\\\)\\n(?!\\s*$)/,ei=/^(`+|[^`])(?:(?= {2,}\\n)|[\\s\\S]*?(?:(?=[\\\\<!\\[`*_]|\\b_|$)|[^ ](?= {2,}\\n)))/,te=/[\\p{P}\\p{S}]/u,Se=/[\\s\\p{P}\\p{S}]/u,$e=/[^\\s\\p{P}\\p{S}]/u,ti=T(/^((?![*_])punctSpace)/,\"u\").replace(/punctSpace/g,Se).getRegex(),ni=/[\\p{Pi}\\p{Ps}\"']/u,vn=/(?!~)[\\p{P}\\p{S}]/u,ri=/(?!~)[\\s\\p{P}\\p{S}]/u,ii=/(?:[^\\s\\p{P}\\p{S}]|~)/u,si=T(/link|precode-code|html/,\"g\").replace(\"link\",/\\[(?:[^\\[\\]`]|(?<a>`+)[^`]+\\k<a>(?!`))*?\\]\\((?:\\\\[\\s\\S]|[^\\\\\\(\\)]|\\((?:\\\\[\\s\\S]|[^\\\\\\(\\)])*\\))*\\)/).replace(\"precode-\",$r?\"(?<!`)()\":\"(^^|[^`])\").replace(\"code\",/(?<b>`+)[^`]+\\k<b>(?!`)/).replace(\"html\",/<(?! )[^<>]*?>/).getRegex(),Un=/^(?:\\*+(?:((?!\\*)punct)|([^\\s*]))?)|^_+(?:((?!_)punct)|([^\\s_]))?/,oi=T(Un,\"u\").replace(/punct/g,te).getRegex(),li=T(Un,\"u\").replace(/punct/g,vn).getRegex(),ai=/^(?:\\*+(?:((?!\\*)(?!openQuote)punct)|([^\\s*]))?)|^_+(?:((?!_)(?!openQuote)punct)|([^\\s_]))?/,ci=T(ai,\"u\").replace(/openQuote/g,ni).replace(/punct/g,te).getRegex(),Fn=\"^[^_*]*?__[^_*]*?\\\\*[^_*]*?(?=__)|[^*]+(?=[^*])|(?!\\\\*)punct(\\\\*+)(?=[\\\\s]|$)|notPunctSpace(\\\\*+)(?!\\\\*)(?=punctSpace|$)|(?!\\\\*)punctSpace(\\\\*+)(?=notPunctSpace)|[\\\\s](\\\\*+)(?!\\\\*)(?=punct)|(?!\\\\*)punct(\\\\*+)(?!\\\\*)(?=punct)|notPunctSpace(\\\\*+)(?=notPunctSpace)\",ui=T(Fn,\"gu\").replace(/notPunctSpace/g,$e).replace(/punctSpace/g,Se).replace(/punct/g,te).getRegex(),pi=T(Fn,\"gu\").replace(/notPunctSpace/g,ii).replace(/punctSpace/g,ri).replace(/punct/g,vn).getRegex(),hi=\"^[^_*]*?__[^_*]*?\\\\*[^_*]*?(?=__)|[^*]+(?=[^*])|(?!\\\\*)punct(\\\\*+)(?=[\\\\s]|$)|notPunctSpace(\\\\*+)(?!\\\\*)(?=punctSpace|$)|(?!\\\\*)[\\\\s](\\\\*+)(?=notPunctSpace)|[\\\\s](\\\\*+)(?!\\\\*)(?=punct)|(?!\\\\*)punct(\\\\*+)(?!\\\\*)(?=punct)|(?:(?!\\\\*)punct|notPunctSpace)(\\\\*+)(?!\\\\*)(?=notPunctSpace)\",fi=T(hi,\"gu\").replace(/notPunctSpace/g,$e).replace(/punctSpace/g,Se).replace(/punct/g,te).getRegex(),di=T(\"^[^_*]*?\\\\*\\\\*[^_*]*?_[^_*]*?(?=\\\\*\\\\*)|[^_]+(?=[^_])|(?!_)punct(_+)(?=[\\\\s]|$)|notPunctSpace(_+)(?!_)(?=punctSpace|$)|(?!_)punctSpace(_+)(?=notPunctSpace)|[\\\\s](_+)(?!_)(?=punct)|(?!_)punct(_+)(?!_)(?=punct)\",\"gu\").replace(/notPunctSpace/g,$e).replace(/punctSpace/g,Se).replace(/punct/g,te).getRegex(),gi=\"^[^_*]*?\\\\*\\\\*[^_*]*?_[^_*]*?(?=\\\\*\\\\*)|[^_]+(?=[^_])|(?!_)punct(_+)(?=[\\\\s]|$)|notPunctSpace(_+)(?!_)(?=punctSpace|$)|(?!_)[\\\\s](_+)(?=notPunctSpace)|[\\\\s](_+)(?!_)(?=punct)|(?!_)punct(_+)(?!_)(?=punct)|(?:(?!_)punct|notPunctSpace)(_+)(?!_)(?=notPunctSpace)\",mi=T(gi,\"gu\").replace(/notPunctSpace/g,$e).replace(/punctSpace/g,Se).replace(/punct/g,te).getRegex(),ki=T(/^~~?(?:((?!~)punct)|[^\\s~])/,\"u\").replace(/punct/g,te).getRegex(),bi=\"^[^~]+(?=[^~])|(?!~)punct(~~?)(?=[\\\\s]|$)|notPunctSpace(~~?)(?!~)(?=punctSpace|$)|(?!~)punctSpace(~~?)(?=notPunctSpace)|[\\\\s](~~?)(?!~)(?=punct)|(?!~)punct(~~?)(?!~)(?=punct)|notPunctSpace(~~?)(?=notPunctSpace)\",xi=T(bi,\"gu\").replace(/notPunctSpace/g,$e).replace(/punctSpace/g,Se).replace(/punct/g,te).getRegex(),Ti=T(/\\\\(punct)/,\"gu\").replace(/punct/g,te).getRegex(),_i=T(/^<(scheme:[^\\s\\x00-\\x1f<>]*|email)>/).replace(\"scheme\",/[a-zA-Z][a-zA-Z0-9+.-]{1,31}/).replace(\"email\",/[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+(@)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+(?![-_])/).getRegex(),wi=T(Nt).replace(\"(?:-->|$)\",\"-->\").getRegex(),yi=T(\"^comment|^</[a-zA-Z][a-zA-Z0-9-]*\\\\s*>|^<[a-zA-Z][a-zA-Z0-9-]*(?:attribute)*?\\\\s*/?>|^<\\\\?[\\\\s\\\\S]*?\\\\?>|^<![a-zA-Z]+\\\\s[\\\\s\\\\S]*?>|^<!\\\\[CDATA\\\\[[\\\\s\\\\S]*?\\\\]\\\\]>\").replace(\"comment\",wi).replace(\"attribute\",/\\s+[a-zA-Z:_][\\w.:-]*(?:\\s*=\\s*\"[^\"]*\"|\\s*=\\s*'[^']*'|\\s*=\\s*[^\\s\"'=<>`]+)?/).getRegex(),Ai=/\\[(?:\\\\[\\s\\S]|[^\\[\\]\\\\])*\\]/,it=T(/(?:\\[(?:brackets|\\\\[\\s\\S]|[^\\[\\]\\\\])*\\]|\\\\[\\s\\S]|`+(?!`)[^`]*?`+(?!`)|``+(?=\\])|[^\\[\\]\\\\`])*?/).replace(\"brackets\",Ai).getRegex(),Si=T(/^!?\\[(label)\\]\\(\\s*(href)(?:(?:[ \\t]+(?:\\n[ \\t]*)?|\\n[ \\t]*)(title))?\\s*\\)/).replace(\"label\",it).replace(\"href\",/<(?:\\\\.|[^\\n<>\\\\])+>|[^ \\t\\n\\x00-\\x1f]+|(?=\\))/).replace(\"title\",/\"(?:\\\\\"?|[^\"\\\\])*\"|'(?:\\\\'?|[^'\\\\])*'|\\((?:\\\\\\)?|[^)\\\\])*\\)/).getRegex(),Bn=T(/^!?\\[(label)\\]\\[(ref)\\]/).replace(\"label\",it).replace(\"ref\",Ct).getRegex(),Hn=T(/^!?\\[(ref)\\](?:\\[\\])?/).replace(\"ref\",Ct).getRegex(),Ei=T(\"reflink|nolink(?!\\\\()\",\"g\").replace(\"reflink\",Bn).replace(\"nolink\",Hn).getRegex(),Rn=/[hH][tT][tT][pP][sS]?|[fF][tT][pP]/,Mt={_backpedal:he,anyPunctuation:Ti,autolink:_i,blockSkip:si,br:$n,code:Jr,del:he,delLDelim:he,delRDelim:he,emStrongLDelim:oi,emStrongRDelimAst:ui,emStrongRDelimUnd:di,escape:Kr,link:Si,nolink:Hn,punctuation:ti,reflink:Bn,reflinkSearch:Ei,tag:yi,text:ei,url:he},Ri={...Mt,emStrongLDelim:ci,emStrongRDelimAst:fi,emStrongRDelimUnd:mi,link:T(/^!?\\[(label)\\]\\((.*?)\\)/).replace(\"label\",it).getRegex(),reflink:T(/^!?\\[(label)\\]\\s*\\[([^\\]]*)\\]/).replace(\"label\",it).getRegex()},Rt={...Mt,emStrongRDelimAst:pi,emStrongLDelim:li,delLDelim:ki,delRDelim:xi,url:T(/^((?:protocol):\\/\\/|www\\.)(?:[a-zA-Z0-9\\-]+\\.?)+[^\\s<]*|^email/).replace(\"protocol\",Rn).replace(\"email\",/[A-Za-z0-9._+-]+(@)[a-zA-Z0-9-_]+(?:\\.[a-zA-Z0-9-_]*[a-zA-Z0-9])+(?![\\w-])/).getRegex(),_backpedal:/(?:[^?!.,:;*_'\"~()&]+|\\([^)]*\\)|&(?![a-zA-Z0-9]+;$)|[?!.,:;*_'\"~)]+(?!$))+/,del:/^(~~?)(?=[^\\s~])((?:\\\\[\\s\\S]|[^\\\\])*?(?:\\\\[\\s\\S]|[^\\s~\\\\]))\\1(?=[^~]|$)/,text:T(/^(`+|~+|[^`~])(?:(?=[`~])|(?= {2,}\\n)|(?=[a-zA-Z0-9.!#$%&'*+\\/=?_`{\\|}~-]+@)|[\\s\\S]*?(?:(?=[\\\\<!\\[`*~_]|\\b_|protocol:\\/\\/|www\\.|$)|[^ ](?= {2,}\\n)|[^a-zA-Z0-9.!#$%&'*+\\/=?_`{\\|}~-](?=[a-zA-Z0-9.!#$%&'*+\\/=?_`{\\|}~-]+@)))/).replace(\"protocol\",Rn).getRegex()},Li={...Rt,br:T($n).replace(\"{2,}\",\"*\").getRegex(),text:T(Rt.text).replace(\"\\\\b_\",\"\\\\b_| {2,}\\\\n\").replace(/\\{2,\\}/g,\"*\").getRegex()},rt={normal:zt,gfm:Qr,pedantic:Vr},Ne={normal:Mt,gfm:Rt,breaks:Li,pedantic:Ri},Oi={\"&\":\"&amp;\",\"<\":\"&lt;\",\">\":\"&gt;\",'\"':\"&quot;\",\"'\":\"&#39;\"},Ln=t=>Oi[t];function H(t,e){if(e){if(N.escapeTest.test(t))return t.replace(N.escapeReplace,Ln)}else if(N.escapeTestNoEncode.test(t))return t.replace(N.escapeReplaceNoEncode,Ln);return t}function On(t){try{t=encodeURI(t).replace(N.percentDecode,\"%\")}catch{return null}return t}function In(t,e){let n=t.replace(N.findPipe,(o,c,a)=>{let f=!1,h=c;for(;--h>=0&&a[h]===\"\\\\\";)f=!f;return f?\"|\":\" |\"}),i=n.split(N.splitPipe),s=0;if(i[0].trim()||i.shift(),i.length>0&&!i.at(-1)?.trim()&&i.pop(),e)if(i.length>e)i.splice(e);else for(;i.length<e;)i.push(\"\");for(;s<i.length;s++)i[s]=i[s].trim().replace(N.slashPipe,\"|\");return i}function se(t,e,n){let i=t.length;if(i===0)return\"\";let s=0;for(;s<i;){let o=t.charAt(i-s-1);if(o===e&&!n)s++;else if(o!==e&&n)s++;else break}return t.slice(0,i-s)}function Dn(t){let e=t.split(`\n`),n=e.length-1;for(;n>=0&&N.blankLine.test(e[n]);)n--;return e.length-n<=2?t:e.slice(0,n+1).join(`\n`)}function Ii(t,e){if(t.indexOf(e[1])===-1)return-1;let n=0;for(let i=0;i<t.length;i++)if(t[i]===\"\\\\\")i++;else if(t[i]===e[0])n++;else if(t[i]===e[1]&&(n--,n<0))return i;return n>0?-2:-1}function Di(t,e=0){let n=e,i=\"\";for(let s of t)if(s===\"\t\"){let o=4-n%4;i+=\" \".repeat(o),n+=o}else i+=s,n++;return i}function Pn(t,e,n,i,s){let o=e.href,c=e.title||null,a=t[1].replace(s.other.outputLinkReplace,\"$1\"),f=t[0].charAt(0)===\"!\";i.state.inLink=!0;let h=i.state.linkEmitted,k=i.state.inRawBlock;i.state.linkEmitted=!1;let m=i.inlineTokens(a),x=i.state.linkEmitted;if(i.state.linkEmitted=h,i.state.inLink=!1,!f){if(x){i.state.inRawBlock=k;return}i.state.linkEmitted=!0}return{type:f?\"image\":\"link\",raw:n,href:o,title:c,text:a,tokens:m}}function Pi(t,e,n){let i=t.match(n.other.indentCodeCompensation);if(i===null)return e;let s=i[1];return e.split(`\n`).map(o=>{let c=o.match(n.other.beginningSpace);if(c===null)return o;let[a]=c;return o.slice(Math.min(a.length,s.length))}).join(`\n`)}var st=class{options;rules;lexer;constructor(t){this.options=t||de}space(t){let e=this.rules.block.newline.exec(t);if(e&&e[0].length>0)return{type:\"space\",raw:e[0]}}code(t){let e=this.rules.block.code.exec(t);if(e){let n=this.options.pedantic?e[0]:Dn(e[0]),i=n.replace(this.rules.other.codeRemoveIndent,\"\");return{type:\"code\",raw:n,codeBlockStyle:\"indented\",text:i}}}fences(t){let e=this.rules.block.fences.exec(t);if(e){let n=e[0],i=Pi(n,e[3]||\"\",this.rules);return{type:\"code\",raw:n,lang:e[2]?e[2].trim().replace(this.rules.inline.anyPunctuation,\"$1\"):e[2],text:i}}}heading(t){let e=this.rules.block.heading.exec(t);if(e){let n=e[2].trim();if(this.rules.other.endingHash.test(n)){let i=se(n,\"#\");(this.options.pedantic||!i||this.rules.other.endingSpaceTabChar.test(i))&&(n=i.trim())}return{type:\"heading\",raw:se(e[0],`\n`),depth:e[1].length,text:n,tokens:this.lexer.inline(n)}}}hr(t){let e=this.rules.block.hr.exec(t);if(e)return{type:\"hr\",raw:se(e[0],`\n`)}}blockquote(t){let e=this.rules.block.blockquote.exec(t);if(e){let n=se(e[0],`\n`).split(`\n`),i=\"\",s=\"\",o=[];for(;n.length>0;){let c=!1,a=[],f;for(f=0;f<n.length;f++)if(this.rules.other.blockquoteStart.test(n[f]))a.push(n[f]),c=!0;else if(!c)a.push(n[f]);else break;n=n.slice(f);let h=a.join(`\n`),k=h.replace(this.rules.other.blockquoteSetextReplace,`\n    $1`).replace(this.rules.other.blockquoteSetextReplace2,\"\");i=i?`${i}\n${h}`:h,s=s?`${s}\n${k}`:k;let m=this.lexer.state.top;if(this.lexer.state.top=!0,this.lexer.blockTokens(k,o,!0),this.lexer.state.top=m,n.length===0)break;let x=o.at(-1);if(x?.type===\"code\")break;if(x?.type===\"blockquote\"){let C=x,w=n.join(`\n`),B=C.raw+`\n`+w.replace(this.rules.other.blockquoteSetextReplace2,\"\"),le=this.blockquote(B);o[o.length-1]=le,i=`${i}\n${w}`,s=s.substring(0,s.length-C.text.length)+le.text;break}else if(x?.type===\"list\"){let C=x,w=C.raw+`\n`+n.join(`\n`),B=this.list(w);o[o.length-1]=B,i=i.substring(0,i.length-x.raw.length)+B.raw,s=s.substring(0,s.length-C.raw.length)+B.raw,n=w.substring(o.at(-1).raw.length).split(`\n`);continue}}return{type:\"blockquote\",raw:i,tokens:o,text:s}}}list(t){let e=this.rules.block.list.exec(t);if(e){let n=e[1].trim(),i=n.length>1,s={type:\"list\",raw:\"\",ordered:i,start:i?+n.slice(0,-1):\"\",loose:!1,items:[]};n=i?`\\\\d{1,9}\\\\${n.slice(-1)}`:`\\\\${n}`,this.options.pedantic&&(n=i?n:\"[*+-]\");let o=this.rules.other.listItemRegex(n),c=!1;for(;t;){let f=!1,h=\"\",k=\"\";if(!(e=o.exec(t))||this.rules.block.hr.test(t))break;h=e[0],t=t.substring(h.length);let m=Di(e[2].split(`\n`,1)[0],e[1].length),x=t.split(`\n`,1)[0],C=!m.trim(),w=0;if(this.options.pedantic?(w=2,k=m.trimStart()):C?w=e[1].length+1:(w=m.search(this.rules.other.nonSpaceChar),w=w>4?1:w,k=m.slice(w),w+=e[1].length),C&&this.rules.other.blankLine.test(x)&&(h+=x+`\n`,t=t.substring(x.length+1),f=!0),!f){let B=this.rules.other.nextBulletRegex(w),le=this.rules.other.hrRegex(w),J=this.rules.other.fencesBeginRegex(w),ee=this.rules.other.headingBeginRegex(w),He=this.rules.other.htmlBeginRegex(w),Le=this.rules.other.blockquoteBeginRegex(w);for(;t;){let Y=t.split(`\n`,1)[0],q;if(x=Y,this.options.pedantic?(x=x.replace(this.rules.other.listReplaceNesting,\"  \"),q=x):q=x.replace(this.rules.other.tabCharGlobal,\"    \"),J.test(x)||ee.test(x)||He.test(x)||Le.test(x)||B.test(x)||le.test(x))break;if(q.search(this.rules.other.nonSpaceChar)>=w||!x.trim())k+=`\n`+q.slice(w);else{if(C||m.replace(this.rules.other.tabCharGlobal,\"    \").search(this.rules.other.nonSpaceChar)>=4||J.test(m)||ee.test(m)||le.test(m))break;k+=`\n`+x}C=!x.trim(),h+=Y+`\n`,t=t.substring(Y.length+1),m=q.slice(w)}}s.loose||(c?s.loose=!0:this.rules.other.doubleBlankLine.test(h)&&(c=!0)),s.items.push({type:\"list_item\",raw:h,task:!!this.options.gfm&&this.rules.other.listIsTask.test(k),loose:!1,text:k,tokens:[]}),s.raw+=h}let a=s.items.at(-1);if(a)a.raw=a.raw.trimEnd(),a.text=a.text.trimEnd();else return;s.raw=s.raw.trimEnd();for(let f of s.items)if(this.lexer.state.top=!1,f.tokens=this.lexer.blockTokens(f.text,[]),!s.loose){let h=f.tokens.filter(m=>m.type===\"space\"),k=h.length>0&&h.some(m=>this.rules.other.anyLine.test(m.raw));s.loose=k}for(let f of s.items){let h=f.tokens[0];if(f.task&&(h?.type===\"text\"||h?.type===\"paragraph\")){f.text=f.text.replace(this.rules.other.listReplaceTask,\"\"),h.raw=h.raw.replace(this.rules.other.listReplaceTask,\"\"),h.text=h.text.replace(this.rules.other.listReplaceTask,\"\");for(let m=this.lexer.inlineQueue.length-1;m>=0;m--)if(this.rules.other.listIsTask.test(this.lexer.inlineQueue[m].src)){this.lexer.inlineQueue[m].src=this.lexer.inlineQueue[m].src.replace(this.rules.other.listReplaceTask,\"\");break}let k=this.rules.other.listTaskCheckbox.exec(f.raw);if(k){let m={type:\"checkbox\",raw:k[0]+\" \",checked:k[0]!==\"[ ]\"};f.checked=m.checked,s.loose?f.tokens[0]&&[\"paragraph\",\"text\"].includes(f.tokens[0].type)&&\"tokens\"in f.tokens[0]&&f.tokens[0].tokens?(f.tokens[0].raw=m.raw+f.tokens[0].raw,f.tokens[0].text=m.raw+f.tokens[0].text,f.tokens[0].tokens.unshift(m)):f.tokens.unshift({type:\"paragraph\",raw:m.raw,text:m.raw,tokens:[m]}):f.tokens.unshift(m)}}else f.task&&(f.task=!1)}if(s.loose)for(let f of s.items){f.loose=!0;for(let h of f.tokens)h.type===\"text\"&&(h.type=\"paragraph\")}return s}}html(t){let e=this.rules.block.html.exec(t);if(e){let n=Dn(e[0]);return{type:\"html\",block:!0,raw:n,pre:e[1]===\"pre\"||e[1]===\"script\"||e[1]===\"style\",text:n}}}def(t){let e=this.rules.block.def.exec(t);if(e){let n=e[1].toLowerCase().replace(this.rules.other.multipleSpaceGlobal,\" \"),i=e[2]?e[2].replace(this.rules.other.hrefBrackets,\"$1\").replace(this.rules.inline.anyPunctuation,\"$1\"):\"\",s=e[3]?e[3].substring(1,e[3].length-1).replace(this.rules.inline.anyPunctuation,\"$1\"):e[3];return{type:\"def\",tag:n,raw:se(e[0],`\n`),href:i,title:s}}}table(t){let e=this.rules.block.table.exec(t);if(!e||!this.rules.other.tableDelimiter.test(e[2]))return;let n=In(e[1]),i=e[2].replace(this.rules.other.tableAlignChars,\"\").split(\"|\"),s=e[3]?.trim()?e[3].replace(this.rules.other.tableRowBlankLine,\"\").split(`\n`):[],o={type:\"table\",raw:se(e[0],`\n`),header:[],align:[],rows:[]};if(n.length===i.length){for(let c of i)this.rules.other.tableAlignRight.test(c)?o.align.push(\"right\"):this.rules.other.tableAlignCenter.test(c)?o.align.push(\"center\"):this.rules.other.tableAlignLeft.test(c)?o.align.push(\"left\"):o.align.push(null);for(let c=0;c<n.length;c++)o.header.push({text:n[c],tokens:this.lexer.inline(n[c]),header:!0,align:o.align[c]});for(let c of s)o.rows.push(In(c,o.header.length).map((a,f)=>({text:a,tokens:this.lexer.inline(a),header:!1,align:o.align[f]})));return o}}lheading(t){let e=this.rules.block.lheading.exec(t);if(e){let n=e[1].trim();return{type:\"heading\",raw:se(e[0],`\n`),depth:e[2].charAt(0)===\"=\"?1:2,text:n,tokens:this.lexer.inline(n)}}}paragraph(t){let e=this.rules.block.paragraph.exec(t);if(e){let n=e[1].charAt(e[1].length-1)===`\n`?e[1].slice(0,-1):e[1];return{type:\"paragraph\",raw:e[0],text:n,tokens:this.lexer.inline(n)}}}text(t){let e=this.rules.block.text.exec(t);if(e)return{type:\"text\",raw:e[0],text:e[0],tokens:this.lexer.inline(e[0])}}escape(t){let e=this.rules.inline.escape.exec(t);if(e)return{type:\"escape\",raw:e[0],text:e[1]}}tag(t){let e=this.rules.inline.tag.exec(t);if(e)return!this.lexer.state.inLink&&this.rules.other.startATag.test(e[0])?this.lexer.state.inLink=!0:this.lexer.state.inLink&&this.rules.other.endATag.test(e[0])&&(this.lexer.state.inLink=!1),!this.lexer.state.inRawBlock&&this.rules.other.startPreScriptTag.test(e[0])?this.lexer.state.inRawBlock=!0:this.lexer.state.inRawBlock&&this.rules.other.endPreScriptTag.test(e[0])&&(this.lexer.state.inRawBlock=!1),{type:\"html\",raw:e[0],inLink:this.lexer.state.inLink,inRawBlock:this.lexer.state.inRawBlock,block:!1,text:e[0]}}link(t){let e=this.rules.inline.link.exec(t);if(e){let n=e[2].trim();if(!this.options.pedantic&&this.rules.other.startAngleBracket.test(n)){if(!this.rules.other.endAngleBracket.test(n))return;let o=se(n.slice(0,-1),\"\\\\\");if((n.length-o.length)%2===0)return}else{let o=Ii(e[2],\"()\");if(o===-2)return;if(o>-1){let c=(e[0].indexOf(\"!\")===0?5:4)+e[1].length+o;e[2]=e[2].substring(0,o),e[0]=e[0].substring(0,c).trim(),e[3]=\"\"}}let i=e[2],s=\"\";if(this.options.pedantic){let o=this.rules.other.pedanticHrefTitle.exec(i);o&&(i=o[1],s=o[3])}else s=e[3]?e[3].slice(1,-1):\"\";return i=i.trim(),this.rules.other.startAngleBracket.test(i)&&(this.options.pedantic&&!this.rules.other.endAngleBracket.test(n)?i=i.slice(1):i=i.slice(1,-1)),Pn(e,{href:i&&i.replace(this.rules.inline.anyPunctuation,\"$1\"),title:s&&s.replace(this.rules.inline.anyPunctuation,\"$1\")},e[0],this.lexer,this.rules)}}reflink(t,e){let n;if((n=this.rules.inline.reflink.exec(t))||(n=this.rules.inline.nolink.exec(t))){let i=(n[2]||n[1]).replace(this.rules.other.multipleSpaceGlobal,\" \"),s=e[i.toLowerCase()];if(!s){let o=n[0].charAt(0);return{type:\"text\",raw:o,text:o}}return Pn(n,s,n[0],this.lexer,this.rules)}}emStrong(t,e,n=\"\"){let i=this.rules.inline.emStrongLDelim.exec(t);if(!(!i||!i[1]&&!i[2]&&!i[3]&&!i[4]||i[4]&&n.match(this.rules.other.unicodeAlphaNumeric))&&(!(i[1]||i[3])||!n||this.rules.inline.punctuation.exec(n))){let s=[...i[0]].length-1,o,c,a=s,f=0,h=i[0][0],k=n===h,m=h===\"*\"?this.rules.inline.emStrongRDelimAst:this.rules.inline.emStrongRDelimUnd;for(m.lastIndex=0,e=e.slice(-1*t.length+s);(i=m.exec(e))!==null;){if(o=i[1]||i[2]||i[3]||i[4]||i[5]||i[6],!o)continue;if(c=[...o].length,i[3]||i[4]){a+=c;continue}else if(i[5]||i[6]){if(s%3&&!((s+c)%3)){f+=c;continue}if(k)break}if(a-=c,a>0)continue;c=Math.min(c,c+a+f);let x=[...i[0]][0].length,C=t.slice(0,s+i.index+x+c);if(Math.min(s,c)%2){let B=C.slice(1,-1);return{type:\"em\",raw:C,text:B,tokens:this.lexer.inlineTokens(B)}}let w=C.slice(2,-2);return{type:\"strong\",raw:C,text:w,tokens:this.lexer.inlineTokens(w)}}}}codespan(t){let e=this.rules.inline.code.exec(t);if(e){let n=e[2].replace(this.rules.other.newLineCharGlobal,\" \"),i=this.rules.other.nonSpaceChar.test(n),s=this.rules.other.startingSpaceChar.test(n)&&this.rules.other.endingSpaceChar.test(n);return i&&s&&(n=n.substring(1,n.length-1)),{type:\"codespan\",raw:e[0],text:n}}}br(t){let e=this.rules.inline.br.exec(t);if(e)return{type:\"br\",raw:e[0]}}del(t,e,n=\"\"){let i=this.rules.inline.delLDelim.exec(t);if(i&&(!i[1]||!n||this.rules.inline.punctuation.exec(n))){let s=[...i[0]].length-1,o,c,a=s,f=this.rules.inline.delRDelim;for(f.lastIndex=0,e=e.slice(-1*t.length+s);(i=f.exec(e))!==null;){if(o=i[1]||i[2]||i[3]||i[4]||i[5]||i[6],!o||(c=[...o].length,c!==s))continue;if(i[3]||i[4]){a+=c;continue}if(a-=c,a>0)continue;c=Math.min(c,c+a);let h=[...i[0]][0].length,k=t.slice(0,s+i.index+h+c),m=k.slice(s,-s);return{type:\"del\",raw:k,text:m,tokens:this.lexer.inlineTokens(m)}}}}autolink(t){let e=this.rules.inline.autolink.exec(t);if(e){let n,i;return e[2]===\"@\"?(n=e[1],i=\"mailto:\"+n):(n=e[1],i=n),{type:\"link\",raw:e[0],text:n,href:i,autolink:!0,tokens:[{type:\"text\",raw:n,text:n}]}}}url(t){let e;if(e=this.rules.inline.url.exec(t)){let n,i;if(e[2]===\"@\")n=e[0],i=\"mailto:\"+n;else{let s;do s=e[0],e[0]=this.rules.inline._backpedal.exec(e[0])?.[0]??\"\";while(s!==e[0]);n=e[0],e[1]===\"www.\"?i=\"http://\"+e[0]:i=e[0]}return{type:\"link\",raw:e[0],text:n,href:i,autolink:!0,tokens:[{type:\"text\",raw:n,text:n}]}}}inlineText(t){let e=this.rules.inline.text.exec(t);if(e){let n=this.lexer.state.inRawBlock;return{type:\"text\",raw:e[0],text:e[0],escaped:n}}}},Z=class Lt{tokens;options;state;inlineQueue;tokenizer;constructor(e){this.tokens=[],this.tokens.links=Object.create(null),this.options=e||de,this.options.tokenizer=this.options.tokenizer||new st,this.tokenizer=this.options.tokenizer,this.tokenizer.options=this.options,this.tokenizer.lexer=this,this.inlineQueue=[],this.state={inLink:!1,inRawBlock:!1,linkEmitted:!1,top:!0};let n={other:N,block:rt.normal,inline:Ne.normal};this.options.pedantic?(n.block=rt.pedantic,n.inline=Ne.pedantic):this.options.gfm&&(n.block=rt.gfm,this.options.breaks?n.inline=Ne.breaks:n.inline=Ne.gfm),this.tokenizer.rules=n}static get rules(){return{block:rt,inline:Ne}}static lex(e,n){return new Lt(n).lex(e)}static lexInline(e,n){return new Lt(n).inlineTokens(e)}lex(e){e=e.replace(N.carriageReturn,`\n`),this.blockTokens(e,this.tokens);for(let n=0;n<this.inlineQueue.length;n++){let i=this.inlineQueue[n];this.inlineTokens(i.src,i.tokens)}return this.inlineQueue=[],this.tokens}blockTokens(e,n=[],i=!1){this.tokenizer.lexer=this,this.options.pedantic&&(e=e.replace(N.tabCharGlobal,\"    \").replace(N.spaceLine,\"\"));let s=1/0;for(;e;){if(e.length<s)s=e.length;else{this.infiniteLoopError(e.charCodeAt(0));break}let o;if(this.options.extensions?.block?.some(a=>(o=a.call({lexer:this},e,n))?(e=e.substring(o.raw.length),n.push(o),!0):!1))continue;if(o=this.tokenizer.space(e)){e=e.substring(o.raw.length);let a=n.at(-1);o.raw.length===1&&a!==void 0?a.raw+=`\n`:n.push(o);continue}if(o=this.tokenizer.code(e)){e=e.substring(o.raw.length);let a=n.at(-1);a?.type===\"paragraph\"||a?.type===\"text\"?(a.raw+=(a.raw.endsWith(`\n`)?\"\":`\n`)+o.raw,a.text+=`\n`+o.text,this.inlineQueue.at(-1).src=a.text):n.push(o);continue}if(o=this.tokenizer.fences(e)){e=e.substring(o.raw.length),n.push(o);continue}if(o=this.tokenizer.heading(e)){e=e.substring(o.raw.length),n.push(o);continue}if(o=this.tokenizer.hr(e)){e=e.substring(o.raw.length),n.push(o);continue}if(o=this.tokenizer.blockquote(e)){e=e.substring(o.raw.length),n.push(o);continue}if(o=this.tokenizer.list(e)){e=e.substring(o.raw.length),n.push(o);continue}if(o=this.tokenizer.html(e)){e=e.substring(o.raw.length),n.push(o);continue}if(o=this.tokenizer.def(e)){e=e.substring(o.raw.length);let a=n.at(-1);a?.type===\"paragraph\"||a?.type===\"text\"?(a.raw+=(a.raw.endsWith(`\n`)?\"\":`\n`)+o.raw,a.text+=`\n`+o.raw,this.inlineQueue.at(-1).src=a.text):this.tokens.links[o.tag]||(this.tokens.links[o.tag]={href:o.href,title:o.title},n.push(o));continue}if(o=this.tokenizer.table(e)){e=e.substring(o.raw.length),n.push(o);continue}if(o=this.tokenizer.lheading(e)){e=e.substring(o.raw.length),n.push(o);continue}let c=e;if(this.options.extensions?.startBlock){let a=1/0,f=e.slice(1),h;this.options.extensions.startBlock.forEach(k=>{h=k.call({lexer:this},f),typeof h==\"number\"&&h>=0&&(a=Math.min(a,h))}),a<1/0&&a>=0&&(c=e.substring(0,a+1))}if(this.state.top&&(o=this.tokenizer.paragraph(c))){let a=n.at(-1);i&&a?.type===\"paragraph\"?(a.raw+=(a.raw.endsWith(`\n`)?\"\":`\n`)+o.raw,a.text+=`\n`+o.text,this.inlineQueue.pop(),this.inlineQueue.at(-1).src=a.text):n.push(o),i=c.length!==e.length,e=e.substring(o.raw.length);continue}if(o=this.tokenizer.text(e)){e=e.substring(o.raw.length);let a=n.at(-1);a?.type===\"text\"?(a.raw+=(a.raw.endsWith(`\n`)?\"\":`\n`)+o.raw,a.text+=`\n`+o.text,this.inlineQueue.pop(),this.inlineQueue.at(-1).src=a.text):n.push(o);continue}if(e){this.infiniteLoopError(e.charCodeAt(0));break}}return this.state.top=!0,n}inline(e,n=[]){return this.inlineQueue.push({src:e,tokens:n}),n}linkInText(e){if(!e.includes(\"[\"))return!1;let n=this.tokenizer.rules.inline.link;for(let i of e.matchAll(this.tokenizer.rules.inline.blockSkip))if(n.test(i[0])&&e.charAt(i.index-1)!==\"!\")return!0;for(let i of e.matchAll(this.tokenizer.rules.inline.reflinkSearch)){let s=i[0],o=s.lastIndexOf(\"[\");if(!(s.charAt(0)===\"!\"||!Object.hasOwn(this.tokens.links,s.slice(o+1,-1)))&&!(o>1&&this.linkInText(s.slice(1,o-1))))return!0}return!1}inlineTokens(e,n=[]){this.tokenizer.lexer=this;let i=e;if(this.tokens.links&&e.includes(\"[\")){let a=this.tokenizer.rules.inline.reflinkSearch,f=h=>{let k=h.lastIndexOf(\"[\");if(!Object.hasOwn(this.tokens.links,h.slice(k+1,-1)))return h;if(k>1&&h.charAt(0)!==\"!\"){let m=h.slice(1,k-1);if(this.linkInText(m))return\"[\"+m.replace(a,f)+\"][\"+\"a\".repeat(h.length-k-2)+\"]\"}return\"[\"+\"a\".repeat(h.length-2)+\"]\"};i=i.replace(a,f)}i=i.replace(this.tokenizer.rules.inline.anyPunctuation,a=>\"+\".repeat(a.length)),i=i.replace(this.tokenizer.rules.inline.blockSkip,(a,f,h)=>{let k=h?h.length:0;return a.slice(0,k)+\"[\"+\"a\".repeat(a.length-k-2)+\"]\"}),i=this.options.hooks?.emStrongMask?.call({lexer:this},i)??i;let s=!1,o=\"\",c=1/0;for(;e;){if(e.length<c)c=e.length;else{this.infiniteLoopError(e.charCodeAt(0));break}s||(o=\"\"),s=!1;let a;if(this.options.extensions?.inline?.some(h=>(a=h.call({lexer:this},e,n))?(e=e.substring(a.raw.length),n.push(a),!0):!1))continue;if(a=this.tokenizer.escape(e)){e=e.substring(a.raw.length),n.push(a);continue}if(a=this.tokenizer.tag(e)){e=e.substring(a.raw.length),n.push(a);continue}if(a=this.tokenizer.link(e)){e=e.substring(a.raw.length),n.push(a);continue}if(a=this.tokenizer.reflink(e,this.tokens.links)){e=e.substring(a.raw.length);let h=n.at(-1);a.type===\"text\"&&h?.type===\"text\"?(h.raw+=a.raw,h.text+=a.text):n.push(a);continue}if(a=this.tokenizer.emStrong(e,i,o)){e=e.substring(a.raw.length),n.push(a);continue}if(a=this.tokenizer.codespan(e)){e=e.substring(a.raw.length),n.push(a);continue}if(a=this.tokenizer.br(e)){e=e.substring(a.raw.length),n.push(a);continue}if(a=this.tokenizer.del(e,i,o)){e=e.substring(a.raw.length),n.push(a);continue}if(a=this.tokenizer.autolink(e)){e=e.substring(a.raw.length),n.push(a);continue}if(!this.state.inLink&&(a=this.tokenizer.url(e))){e=e.substring(a.raw.length),n.push(a);continue}let f=e;if(this.options.extensions?.startInline){let h=1/0,k=e.slice(1),m;this.options.extensions.startInline.forEach(x=>{m=x.call({lexer:this},k),typeof m==\"number\"&&m>=0&&(h=Math.min(h,m))}),h<1/0&&h>=0&&(f=e.substring(0,h+1))}if(a=this.tokenizer.inlineText(f)){e=e.substring(a.raw.length),a.raw.slice(-1)!==\"_\"&&(o=a.raw.slice(-1)),s=!0;let h=n.at(-1);h?.type===\"text\"?(h.raw+=a.raw,h.text+=a.text):n.push(a);continue}if(e){this.infiniteLoopError(e.charCodeAt(0));break}}return n}infiniteLoopError(e){let n=\"Infinite loop on byte: \"+e;if(this.options.silent)console.error(n);else throw new Error(n)}},ot=class{options;parser;constructor(t){this.options=t||de}space(t){return\"\"}code({text:t,lang:e,escaped:n}){let i=(e||\"\").match(N.notSpaceStart)?.[0],s=t?t.replace(N.endingNewline,\"\")+`\n`:\"\";return i?'<pre><code class=\"language-'+H(i)+'\">'+(n?s:H(s,!0))+`</code></pre>\n`:\"<pre><code>\"+(n?s:H(s,!0))+`</code></pre>\n`}blockquote({tokens:t}){return`<blockquote>\n${this.parser.parse(t)}</blockquote>\n`}html({text:t}){return t}def(t){return\"\"}heading({tokens:t,depth:e}){return`<h${e}>${this.parser.parseInline(t)}</h${e}>\n`}hr(t){return`<hr>\n`}list(t){let e=t.ordered,n=t.start,i=\"\";for(let c=0;c<t.items.length;c++){let a=t.items[c];i+=this.listitem(a)}let s=e?\"ol\":\"ul\",o=e&&n!==1?' start=\"'+n+'\"':\"\";return\"<\"+s+o+`>\n`+i+\"</\"+s+`>\n`}listitem(t){return`<li>${this.parser.parse(t.tokens)}</li>\n`}checkbox({checked:t}){return\"<input \"+(t?'checked=\"\" ':\"\")+'disabled=\"\" type=\"checkbox\"> '}paragraph({tokens:t}){return`<p>${this.parser.parseInline(t)}</p>\n`}table(t){let e=\"\",n=\"\";for(let s=0;s<t.header.length;s++)n+=this.tablecell(t.header[s]);e+=this.tablerow({text:n});let i=\"\";for(let s=0;s<t.rows.length;s++){let o=t.rows[s];n=\"\";for(let c=0;c<o.length;c++)n+=this.tablecell(o[c]);i+=this.tablerow({text:n})}return i&&(i=`<tbody>${i}</tbody>`),`<table>\n<thead>\n`+e+`</thead>\n`+i+`</table>\n`}tablerow({text:t}){return`<tr>\n${t}</tr>\n`}tablecell(t){let e=this.parser.parseInline(t.tokens),n=t.header?\"th\":\"td\";return(t.align?`<${n} align=\"${t.align}\">`:`<${n}>`)+e+`</${n}>\n`}strong({tokens:t}){return`<strong>${this.parser.parseInline(t)}</strong>`}em({tokens:t}){return`<em>${this.parser.parseInline(t)}</em>`}codespan({text:t}){return`<code>${H(t,!0)}</code>`}br(t){return\"<br>\"}del({tokens:t}){return`<del>${this.parser.parseInline(t)}</del>`}link({href:t,title:e,text:n,tokens:i,autolink:s}){let o=s?H(n,!0):this.parser.parseInline(i),c=On(t);if(c===null)return o;t=H(c,s);let a='<a href=\"'+t+'\"';return e&&(a+=' title=\"'+H(e)+'\"'),a+=\">\"+o+\"</a>\",a}image({href:t,title:e,text:n,tokens:i}){i&&(n=this.parser.parseInline(i,this.parser.textRenderer));let s=On(t);if(s===null)return H(n);t=s;let o=`<img src=\"${H(t)}\" alt=\"${H(n)}\"`;return e&&(o+=` title=\"${H(e)}\"`),o+=\">\",o}text(t){return\"tokens\"in t&&t.tokens?this.parser.parseInline(t.tokens):\"escaped\"in t&&t.escaped?t.text:H(t.text)}},$t=class{strong({text:t}){return t}em({text:t}){return t}codespan({text:t}){return t}del({text:t}){return t}html({text:t}){return t}text({text:t}){return t}link({text:t}){return\"\"+t}image({text:t}){return\"\"+t}br(){return\"\"}checkbox({raw:t}){return t}},X=class Ot{options;renderer;textRenderer;constructor(e){this.options=e||de,this.options.renderer=this.options.renderer||new ot,this.renderer=this.options.renderer,this.renderer.options=this.options,this.renderer.parser=this,this.textRenderer=new $t}static parse(e,n){return new Ot(n).parse(e)}static parseInline(e,n){return new Ot(n).parseInline(e)}parse(e){this.renderer.parser=this;let n=\"\";for(let i=0;i<e.length;i++){let s=e[i];if(this.options.extensions?.renderers?.[s.type]){let c=s,a=this.options.extensions.renderers[c.type].call({parser:this},c);if(a!==!1||![\"space\",\"hr\",\"heading\",\"code\",\"table\",\"blockquote\",\"list\",\"checkbox\",\"html\",\"def\",\"paragraph\",\"text\"].includes(c.type)){n+=a||\"\";continue}}let o=s;switch(o.type){case\"space\":{n+=this.renderer.space(o);break}case\"hr\":{n+=this.renderer.hr(o);break}case\"heading\":{n+=this.renderer.heading(o);break}case\"code\":{n+=this.renderer.code(o);break}case\"table\":{n+=this.renderer.table(o);break}case\"blockquote\":{n+=this.renderer.blockquote(o);break}case\"list\":{n+=this.renderer.list(o);break}case\"checkbox\":{n+=this.renderer.checkbox(o);break}case\"html\":{n+=this.renderer.html(o);break}case\"def\":{n+=this.renderer.def(o);break}case\"paragraph\":{n+=this.renderer.paragraph(o);break}case\"text\":{n+=this.renderer.text(o);break}default:{let c='Token with \"'+o.type+'\" type was not found.';if(this.options.silent)return console.error(c),\"\";throw new Error(c)}}}return n}parseInline(e,n=this.renderer){this.renderer.parser=this;let i=\"\";for(let s=0;s<e.length;s++){let o=e[s];if(this.options.extensions?.renderers?.[o.type]){let a=this.options.extensions.renderers[o.type].call({parser:this},o);if(a!==!1||![\"escape\",\"html\",\"link\",\"image\",\"checkbox\",\"strong\",\"em\",\"codespan\",\"br\",\"del\",\"text\"].includes(o.type)){i+=a||\"\";continue}}let c=o;switch(c.type){case\"escape\":{i+=n.text(c);break}case\"html\":{i+=n.html(c);break}case\"link\":{i+=n.link(c);break}case\"image\":{i+=n.image(c);break}case\"checkbox\":{i+=n.checkbox(c);break}case\"strong\":{i+=n.strong(c);break}case\"em\":{i+=n.em(c);break}case\"codespan\":{i+=n.codespan(c);break}case\"br\":{i+=n.br(c);break}case\"del\":{i+=n.del(c);break}case\"text\":{i+=n.text(c);break}default:{let a='Token with \"'+c.type+'\" type was not found.';if(this.options.silent)return console.error(a),\"\";throw new Error(a)}}}return i}},ze=class{options;block;constructor(t){this.options=t||de}static passThroughHooks=new Set([\"preprocess\",\"postprocess\",\"processAllTokens\",\"emStrongMask\"]);static passThroughHooksRespectAsync=new Set([\"preprocess\",\"postprocess\",\"processAllTokens\"]);preprocess(t){return t}postprocess(t){return t}processAllTokens(t){return t}emStrongMask(t){return t}provideLexer(t=this.block){return t?Z.lex:Z.lexInline}provideParser(t=this.block){return t?X.parse:X.parseInline}},Ci=class{defaults=It();options=this.setOptions;parse=this.parseMarkdown(!0);parseInline=this.parseMarkdown(!1);Parser=X;Renderer=ot;TextRenderer=$t;Lexer=Z;Tokenizer=st;Hooks=ze;constructor(...t){this.use(...t)}walkTokens(t,e){let n=[];for(let i of t)switch(n=n.concat(e.call(this,i)),i.type){case\"table\":{let s=i;for(let o of s.header)n=n.concat(this.walkTokens(o.tokens,e));for(let o of s.rows)for(let c of o)n=n.concat(this.walkTokens(c.tokens,e));break}case\"list\":{let s=i;n=n.concat(this.walkTokens(s.items,e));break}default:{let s=i;this.defaults.extensions?.childTokens?.[s.type]?this.defaults.extensions.childTokens[s.type].forEach(o=>{let c=s[o].flat(1/0);n=n.concat(this.walkTokens(c,e))}):s.tokens&&(n=n.concat(this.walkTokens(s.tokens,e)))}}return n}use(...t){let e=this.defaults.extensions||{renderers:{},childTokens:{}};return t.forEach(n=>{let i={...n};if(i.async=this.defaults.async||i.async||!1,n.extensions&&(n.extensions.forEach(s=>{if(!s.name)throw new Error(\"extension name required\");if(\"renderer\"in s){let o=e.renderers[s.name];o?e.renderers[s.name]=function(...c){let a=s.renderer.apply(this,c);return a===!1&&(a=o.apply(this,c)),a}:e.renderers[s.name]=s.renderer}if(\"tokenizer\"in s){if(!s.level||s.level!==\"block\"&&s.level!==\"inline\")throw new Error(\"extension level must be 'block' or 'inline'\");let o=e[s.level];o?o.unshift(s.tokenizer):e[s.level]=[s.tokenizer],s.start&&(s.level===\"block\"?e.startBlock?e.startBlock.push(s.start):e.startBlock=[s.start]:s.level===\"inline\"&&(e.startInline?e.startInline.push(s.start):e.startInline=[s.start]))}\"childTokens\"in s&&s.childTokens&&(e.childTokens[s.name]=s.childTokens)}),i.extensions=e),n.renderer){let s=this.defaults.renderer||new ot(this.defaults);for(let o in n.renderer){if(!(o in s))throw new Error(`renderer '${o}' does not exist`);if([\"options\",\"parser\"].includes(o))continue;let c=o,a=n.renderer[c],f=s[c];s[c]=(...h)=>{let k=a.apply(s,h);return k===!1&&(k=f.apply(s,h)),k||\"\"}}i.renderer=s}if(n.tokenizer){let s=this.defaults.tokenizer||new st(this.defaults);for(let o in n.tokenizer){if(!(o in s))throw new Error(`tokenizer '${o}' does not exist`);if([\"options\",\"rules\",\"lexer\"].includes(o))continue;let c=o,a=n.tokenizer[c],f=s[c];s[c]=(...h)=>{let k=a.apply(s,h);return k===!1&&(k=f.apply(s,h)),k}}i.tokenizer=s}if(n.hooks){let s=this.defaults.hooks||new ze;for(let o in n.hooks){if(!(o in s))throw new Error(`hook '${o}' does not exist`);if([\"options\",\"block\"].includes(o))continue;let c=o,a=n.hooks[c],f=s[c];ze.passThroughHooks.has(o)?s[c]=h=>{if(this.defaults.async&&ze.passThroughHooksRespectAsync.has(o))return(async()=>{let m=await a.call(s,h);return f.call(s,m)})();let k=a.call(s,h);return f.call(s,k)}:s[c]=(...h)=>{if(this.defaults.async)return(async()=>{let m=await a.apply(s,h);return m===!1&&(m=await f.apply(s,h)),m})();let k=a.apply(s,h);return k===!1&&(k=f.apply(s,h)),k}}i.hooks=s}if(n.walkTokens){let s=this.defaults.walkTokens,o=n.walkTokens;i.walkTokens=function(c){let a=[];return a.push(o.call(this,c)),s&&(a=a.concat(s.call(this,c))),a}}this.defaults={...this.defaults,...i}}),this}setOptions(t){return this.defaults={...this.defaults,...t},this}lexer(t,e){return Z.lex(t,e??this.defaults)}parser(t,e){return X.parse(t,e??this.defaults)}parseMarkdown(t){return(e,n)=>{let i={...n},s={...this.defaults,...i},o=this.onError(!!s.silent,!!s.async);if(this.defaults.async===!0&&i.async===!1)return o(new Error(\"marked(): The async option was set to true by an extension. Remove async: false from the parse options object to return a Promise.\"));if(typeof e>\"u\"||e===null)return o(new Error(\"marked(): input parameter is undefined or null\"));if(typeof e!=\"string\")return o(new Error(\"marked(): input parameter is of type \"+Object.prototype.toString.call(e)+\", string expected\"));if(s.hooks&&(s.hooks.options=s,s.hooks.block=t),s.async)return(async()=>{let c=s.hooks?await s.hooks.preprocess(e):e,a=await(s.hooks?await s.hooks.provideLexer(t):t?Z.lex:Z.lexInline)(c,s),f=s.hooks?await s.hooks.processAllTokens(a):a;s.walkTokens&&await Promise.all(this.walkTokens(f,s.walkTokens));let h=await(s.hooks?await s.hooks.provideParser(t):t?X.parse:X.parseInline)(f,s);return s.hooks?await s.hooks.postprocess(h):h})().catch(o);try{s.hooks&&(e=s.hooks.preprocess(e));let c=(s.hooks?s.hooks.provideLexer(t):t?Z.lex:Z.lexInline)(e,s);s.hooks&&(c=s.hooks.processAllTokens(c)),s.walkTokens&&this.walkTokens(c,s.walkTokens);let a=(s.hooks?s.hooks.provideParser(t):t?X.parse:X.parseInline)(c,s);return s.hooks&&(a=s.hooks.postprocess(a)),a}catch(c){return o(c)}}}onError(t,e){return n=>{if(n.message+=`\nPlease report this to https://github.com/markedjs/marked.`,t){let i=\"<p>An error occurred:</p><pre>\"+H(n.message+\"\",!0)+\"</pre>\";return e?Promise.resolve(i):i}if(e)return Promise.reject(n);throw n}}},fe=new Ci;function y(t,e){return fe.parse(t,e)}y.options=y.setOptions=function(t){return fe.setOptions(t),y.defaults=fe.defaults,Cn(y.defaults),y};y.getDefaults=It;y.defaults=de;function Ni(...t){return fe.use(...t),y.defaults=fe.defaults,Cn(y.defaults),y}y.use=Ni;y.walkTokens=function(t,e){return fe.walkTokens(t,e)};y.parseInline=fe.parseInline;y.Parser=X;y.parser=X.parse;y.Renderer=ot;y.TextRenderer=$t;y.Lexer=Z;y.lexer=Z.lex;y.Tokenizer=st;y.Hooks=ze;y.parse=y;var ms=y.options,ks=y.setOptions,bs=y.walkTokens,xs=y.parseInline;var Ts=X.parse,_s=Z.lex;/*! @license DOMPurify 3.4.15 | (c) Cure53 and other contributors | Released under the Apache license 2.0 and Mozilla Public License 2.0 | github.com/cure53/DOMPurify/blob/3.4.15/LICENSE */function Gn(t,e){(e==null||e>t.length)&&(e=t.length);for(var n=0,i=Array(e);n<e;n++)i[n]=t[n];return i}function zi(t){if(Array.isArray(t))return t}function Mi(t,e){var n=t==null?null:typeof Symbol<\"u\"&&t[Symbol.iterator]||t[\"@@iterator\"];if(n!=null){var i,s,o,c,a=[],f=!0,h=!1;try{if(o=(n=n.call(t)).next,e!==0)for(;!(f=(i=o.call(n)).done)&&(a.push(i.value),a.length!==e);f=!0);}catch(k){h=!0,s=k}finally{try{if(!f&&n.return!=null&&(c=n.return(),Object(c)!==c))return}finally{if(h)throw s}}return a}}function $i(){throw new TypeError(`Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.`)}function vi(t,e){return zi(t)||Mi(t,e)||Ui(t,e)||$i()}function Ui(t,e){if(t){if(typeof t==\"string\")return Gn(t,e);var n={}.toString.call(t).slice(8,-1);return n===\"Object\"&&t.constructor&&(n=t.constructor.name),n===\"Map\"||n===\"Set\"?Array.from(t):n===\"Arguments\"||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(n)?Gn(t,e):void 0}}var ir=Object.entries,Wn=Object.setPrototypeOf,Fi=Object.isFrozen,Bi=Object.getPrototypeOf,Hi=Object.getOwnPropertyDescriptor,D=Object.freeze,P=Object.seal,Ee=Object.create,sr=typeof Reflect<\"u\"&&Reflect,Wt=sr.apply,qt=sr.construct;D||(D=function(e){return e});P||(P=function(e){return e});Wt||(Wt=function(e,n){for(var i=arguments.length,s=new Array(i>2?i-2:0),o=2;o<i;o++)s[o-2]=arguments[o];return e.apply(n,s)});qt||(qt=function(e){for(var n=arguments.length,i=new Array(n>1?n-1:0),s=1;s<n;s++)i[s-1]=arguments[s];return new e(...i)});var me=I(Array.prototype.forEach),Gi=I(Array.prototype.lastIndexOf),qn=I(Array.prototype.pop),ve=I(Array.prototype.push),Wi=I(Array.prototype.splice),Re=Array.isArray,Be=I(String.prototype.toLowerCase),vt=I(String.prototype.toString),jn=I(String.prototype.match),Ue=I(String.prototype.replace),Yn=I(String.prototype.indexOf),qi=I(String.prototype.trim),ji=I(Number.prototype.toString),Yi=I(Boolean.prototype.toString),Zn=typeof BigInt>\"u\"?null:I(BigInt.prototype.toString),Xn=typeof Symbol>\"u\"?null:I(Symbol.prototype.toString),F=I(Object.prototype.hasOwnProperty),Fe=I(Object.prototype.toString),z=I(RegExp.prototype.test),ge=Zi(TypeError);function I(t){return function(e){e instanceof RegExp&&(e.lastIndex=0);for(var n=arguments.length,i=new Array(n>1?n-1:0),s=1;s<n;s++)i[s-1]=arguments[s];return Wt(t,e,i)}}function Zi(t){return function(){for(var e=arguments.length,n=new Array(e),i=0;i<e;i++)n[i]=arguments[i];return qt(t,n)}}function _(t,e){let n=arguments.length>2&&arguments[2]!==void 0?arguments[2]:Be;if(Wn&&Wn(t,null),!Re(e))return t;let i=e.length;for(;i--;){let s=e[i];if(typeof s==\"string\"){let o=n(s);o!==s&&(Fi(e)||(e[i]=o),s=o)}t[s]=!0}return t}function Xi(t){for(let e=0;e<t.length;e++)F(t,e)||(t[e]=null);return t}function W(t){let e=Ee(null);for(let i of ir(t)){var n=vi(i,2);let s=n[0],o=n[1];F(t,s)&&(Re(o)?e[s]=Xi(o):o&&typeof o==\"object\"&&o.constructor===Object?e[s]=W(o):e[s]=o)}return e}function Qi(t){switch(typeof t){case\"string\":return t;case\"number\":return ji(t);case\"boolean\":return Yi(t);case\"bigint\":return Zn?Zn(t):\"0\";case\"symbol\":return Xn?Xn(t):\"Symbol()\";case\"undefined\":return Fe(t);case\"function\":case\"object\":{if(t===null)return Fe(t);let e=t,n=j(e,\"toString\");if(typeof n==\"function\"){let i=n(e);return typeof i==\"string\"?i:Fe(i)}return Fe(t)}default:return Fe(t)}}function j(t,e){for(;t!==null;){let i=Hi(t,e);if(i){if(i.get)return I(i.get);if(typeof i.value==\"function\")return I(i.value)}t=Bi(t)}function n(){return null}return n}function Vi(t){try{return z(t,\"\"),!0}catch{return!1}}var Qn=D([\"a\",\"abbr\",\"acronym\",\"address\",\"area\",\"article\",\"aside\",\"audio\",\"b\",\"bdi\",\"bdo\",\"big\",\"blink\",\"blockquote\",\"body\",\"br\",\"button\",\"canvas\",\"caption\",\"center\",\"cite\",\"code\",\"col\",\"colgroup\",\"content\",\"data\",\"datalist\",\"dd\",\"decorator\",\"del\",\"details\",\"dfn\",\"dialog\",\"dir\",\"div\",\"dl\",\"dt\",\"element\",\"em\",\"fieldset\",\"figcaption\",\"figure\",\"font\",\"footer\",\"form\",\"h1\",\"h2\",\"h3\",\"h4\",\"h5\",\"h6\",\"head\",\"header\",\"hgroup\",\"hr\",\"html\",\"i\",\"img\",\"input\",\"ins\",\"kbd\",\"label\",\"legend\",\"li\",\"main\",\"map\",\"mark\",\"marquee\",\"menu\",\"menuitem\",\"meter\",\"nav\",\"nobr\",\"ol\",\"optgroup\",\"option\",\"output\",\"p\",\"picture\",\"pre\",\"progress\",\"q\",\"rp\",\"rt\",\"ruby\",\"s\",\"samp\",\"search\",\"section\",\"select\",\"shadow\",\"slot\",\"small\",\"source\",\"spacer\",\"span\",\"strike\",\"strong\",\"style\",\"sub\",\"summary\",\"sup\",\"table\",\"tbody\",\"td\",\"template\",\"textarea\",\"tfoot\",\"th\",\"thead\",\"time\",\"tr\",\"track\",\"tt\",\"u\",\"ul\",\"var\",\"video\",\"wbr\"]),Ut=D([\"svg\",\"a\",\"altglyph\",\"altglyphdef\",\"altglyphitem\",\"animatecolor\",\"animatemotion\",\"animatetransform\",\"circle\",\"clippath\",\"defs\",\"desc\",\"ellipse\",\"enterkeyhint\",\"exportparts\",\"filter\",\"font\",\"g\",\"glyph\",\"glyphref\",\"hkern\",\"image\",\"inputmode\",\"line\",\"lineargradient\",\"marker\",\"mask\",\"metadata\",\"mpath\",\"part\",\"path\",\"pattern\",\"polygon\",\"polyline\",\"radialgradient\",\"rect\",\"stop\",\"style\",\"switch\",\"symbol\",\"text\",\"textpath\",\"title\",\"tref\",\"tspan\",\"view\",\"vkern\"]),Ft=D([\"feBlend\",\"feColorMatrix\",\"feComponentTransfer\",\"feComposite\",\"feConvolveMatrix\",\"feDiffuseLighting\",\"feDisplacementMap\",\"feDistantLight\",\"feDropShadow\",\"feFlood\",\"feFuncA\",\"feFuncB\",\"feFuncG\",\"feFuncR\",\"feGaussianBlur\",\"feImage\",\"feMerge\",\"feMergeNode\",\"feMorphology\",\"feOffset\",\"fePointLight\",\"feSpecularLighting\",\"feSpotLight\",\"feTile\",\"feTurbulence\"]),Ki=D([\"animate\",\"color-profile\",\"cursor\",\"discard\",\"font-face\",\"font-face-format\",\"font-face-name\",\"font-face-src\",\"font-face-uri\",\"foreignobject\",\"hatch\",\"hatchpath\",\"mesh\",\"meshgradient\",\"meshpatch\",\"meshrow\",\"missing-glyph\",\"script\",\"set\",\"solidcolor\",\"unknown\",\"use\"]),Bt=D([\"math\",\"menclose\",\"merror\",\"mfenced\",\"mfrac\",\"mglyph\",\"mi\",\"mlabeledtr\",\"mmultiscripts\",\"mn\",\"mo\",\"mover\",\"mpadded\",\"mphantom\",\"mroot\",\"mrow\",\"ms\",\"mspace\",\"msqrt\",\"mstyle\",\"msub\",\"msup\",\"msubsup\",\"mtable\",\"mtd\",\"mtext\",\"mtr\",\"munder\",\"munderover\",\"mprescripts\"]),Ji=D([\"maction\",\"maligngroup\",\"malignmark\",\"mlongdiv\",\"mscarries\",\"mscarry\",\"msgroup\",\"mstack\",\"msline\",\"msrow\",\"semantics\",\"annotation\",\"annotation-xml\",\"mprescripts\",\"none\"]),Vn=D([\"#text\"]),Kn=D([\"accept\",\"action\",\"align\",\"alt\",\"autocapitalize\",\"autocomplete\",\"autopictureinpicture\",\"autoplay\",\"background\",\"bgcolor\",\"border\",\"capture\",\"cellpadding\",\"cellspacing\",\"checked\",\"cite\",\"class\",\"clear\",\"color\",\"cols\",\"colspan\",\"command\",\"commandfor\",\"controls\",\"controlslist\",\"coords\",\"crossorigin\",\"datetime\",\"decoding\",\"default\",\"dir\",\"disabled\",\"disablepictureinpicture\",\"disableremoteplayback\",\"download\",\"draggable\",\"enctype\",\"enterkeyhint\",\"exportparts\",\"face\",\"for\",\"headers\",\"height\",\"hidden\",\"high\",\"href\",\"hreflang\",\"id\",\"inert\",\"inputmode\",\"integrity\",\"ismap\",\"kind\",\"label\",\"lang\",\"list\",\"loading\",\"loop\",\"low\",\"max\",\"maxlength\",\"media\",\"method\",\"min\",\"minlength\",\"multiple\",\"muted\",\"name\",\"nonce\",\"noshade\",\"novalidate\",\"nowrap\",\"open\",\"optimum\",\"part\",\"pattern\",\"placeholder\",\"playsinline\",\"popover\",\"popovertarget\",\"popovertargetaction\",\"poster\",\"preload\",\"pubdate\",\"radiogroup\",\"readonly\",\"rel\",\"required\",\"rev\",\"reversed\",\"role\",\"rows\",\"rowspan\",\"spellcheck\",\"scope\",\"selected\",\"shape\",\"size\",\"sizes\",\"slot\",\"span\",\"srclang\",\"start\",\"src\",\"srcset\",\"step\",\"style\",\"summary\",\"tabindex\",\"title\",\"translate\",\"type\",\"usemap\",\"valign\",\"value\",\"width\",\"wrap\",\"xmlns\"]),Ht=D([\"accent-height\",\"accumulate\",\"additive\",\"alignment-baseline\",\"amplitude\",\"ascent\",\"attributename\",\"attributetype\",\"azimuth\",\"basefrequency\",\"baseline-shift\",\"begin\",\"bias\",\"by\",\"class\",\"clip\",\"clippathunits\",\"clip-path\",\"clip-rule\",\"color\",\"color-interpolation\",\"color-interpolation-filters\",\"color-profile\",\"color-rendering\",\"cx\",\"cy\",\"d\",\"dx\",\"dy\",\"diffuseconstant\",\"direction\",\"display\",\"divisor\",\"dominant-baseline\",\"dur\",\"edgemode\",\"elevation\",\"end\",\"exponent\",\"fill\",\"fill-opacity\",\"fill-rule\",\"filter\",\"filterunits\",\"flood-color\",\"flood-opacity\",\"font-family\",\"font-size\",\"font-size-adjust\",\"font-stretch\",\"font-style\",\"font-variant\",\"font-weight\",\"fx\",\"fy\",\"g1\",\"g2\",\"glyph-name\",\"glyphref\",\"gradientunits\",\"gradienttransform\",\"height\",\"href\",\"id\",\"image-rendering\",\"in\",\"in2\",\"intercept\",\"k\",\"k1\",\"k2\",\"k3\",\"k4\",\"kerning\",\"keypoints\",\"keysplines\",\"keytimes\",\"lang\",\"lengthadjust\",\"letter-spacing\",\"kernelmatrix\",\"kernelunitlength\",\"lighting-color\",\"local\",\"marker-end\",\"marker-mid\",\"marker-start\",\"markerheight\",\"markerunits\",\"markerwidth\",\"maskcontentunits\",\"maskunits\",\"max\",\"mask\",\"mask-type\",\"media\",\"method\",\"mode\",\"min\",\"name\",\"numoctaves\",\"offset\",\"operator\",\"opacity\",\"order\",\"orient\",\"orientation\",\"origin\",\"overflow\",\"paint-order\",\"path\",\"pathlength\",\"patterncontentunits\",\"patterntransform\",\"patternunits\",\"pointer-events\",\"points\",\"preservealpha\",\"preserveaspectratio\",\"primitiveunits\",\"r\",\"rx\",\"ry\",\"radius\",\"refx\",\"refy\",\"repeatcount\",\"repeatdur\",\"restart\",\"result\",\"rotate\",\"scale\",\"seed\",\"shape-rendering\",\"slope\",\"specularconstant\",\"specularexponent\",\"spreadmethod\",\"startoffset\",\"stddeviation\",\"stitchtiles\",\"stop-color\",\"stop-opacity\",\"stroke-dasharray\",\"stroke-dashoffset\",\"stroke-linecap\",\"stroke-linejoin\",\"stroke-miterlimit\",\"stroke-opacity\",\"stroke\",\"stroke-width\",\"style\",\"surfacescale\",\"systemlanguage\",\"tabindex\",\"tablevalues\",\"targetx\",\"targety\",\"transform\",\"transform-origin\",\"text-anchor\",\"text-decoration\",\"text-orientation\",\"text-rendering\",\"textlength\",\"type\",\"u1\",\"u2\",\"unicode\",\"values\",\"vector-effect\",\"viewbox\",\"visibility\",\"version\",\"vert-adv-y\",\"vert-origin-x\",\"vert-origin-y\",\"width\",\"word-spacing\",\"wrap\",\"writing-mode\",\"xchannelselector\",\"ychannelselector\",\"x\",\"x1\",\"x2\",\"xmlns\",\"y\",\"y1\",\"y2\",\"z\",\"zoomandpan\"]),Jn=D([\"accent\",\"accentunder\",\"align\",\"bevelled\",\"close\",\"columnalign\",\"columnlines\",\"columnspacing\",\"columnspan\",\"denomalign\",\"depth\",\"dir\",\"display\",\"displaystyle\",\"encoding\",\"fence\",\"frame\",\"height\",\"href\",\"id\",\"largeop\",\"length\",\"linethickness\",\"lquote\",\"lspace\",\"mathbackground\",\"mathcolor\",\"mathsize\",\"mathvariant\",\"maxsize\",\"minsize\",\"movablelimits\",\"notation\",\"numalign\",\"open\",\"rowalign\",\"rowlines\",\"rowspacing\",\"rowspan\",\"rspace\",\"rquote\",\"scriptlevel\",\"scriptminsize\",\"scriptsizemultiplier\",\"selection\",\"separator\",\"separators\",\"stretchy\",\"subscriptshift\",\"supscriptshift\",\"symmetric\",\"voffset\",\"width\",\"xmlns\"]),at=D([\"xlink:href\",\"xml:id\",\"xlink:title\",\"xml:space\",\"xmlns:xlink\"]),es=P(/{{[\\w\\W]*|^[\\w\\W]*}}/g),ts=P(/<%[\\w\\W]*|^[\\w\\W]*%>/g),ns=P(/\\${[\\w\\W]*/g),rs=P(/^data-[\\-\\w.\\u00B7-\\uFFFF]+$/),is=P(/^aria-[\\-\\w]+$/),er=P(/^(?:(?:(?:f|ht)tps?|mailto|tel|callto|sms|cid|xmpp|matrix):|[^a-z]|[a-z+.\\-]+(?:[^a-z+.\\-:]|$))/i),ss=P(/^(?:\\w+script|data):/i),os=P(/[\\u0000-\\u0020\\u00A0\\u1680\\u180E\\u2000-\\u2029\\u205F\\u3000]/g),ls=P(/^html$/i),as=P(/^[a-z][.\\w]*(-[.\\w]+)+$/i),tr=P(/<[/\\w!]/g),nr=P(/<[/\\w]/g),cs=P(/<\\/no(script|embed|frames)/i),us=P(/\\/>/i),G={element:1,attribute:2,text:3,cdataSection:4,entityReference:5,entityNode:6,processingInstruction:7,comment:8,document:9,documentType:10,documentFragment:11,notation:12},or=[\"style\",\"script\",\"xmp\",\"iframe\",\"noembed\",\"noframes\",\"plaintext\",\"noscript\"],ps=D(_({},or)),hs=(function(){let t={};return me(or,e=>{t[e]=P(new RegExp(\"</\"+e+\"(?=[\\\\t\\\\n\\\\f\\\\r />])\",\"i\"))}),D(t)})(),fs=function(){return typeof window>\"u\"?null:window},ds=function(e,n){if(typeof e!=\"object\"||typeof e.createPolicy!=\"function\")return null;let i=null,s=\"data-tt-policy-suffix\";n&&n.hasAttribute(s)&&(i=n.getAttribute(s));let o=\"dompurify\"+(i?\"#\"+i:\"\");try{return e.createPolicy(o,{createHTML(c){return c},createScriptURL(c){return c}})}catch{return console.warn(\"TrustedTypes policy \"+o+\" could not be created.\"),null}},rr=function(){return{afterSanitizeAttributes:[],afterSanitizeElements:[],afterSanitizeShadowDOM:[],beforeSanitizeAttributes:[],beforeSanitizeElements:[],beforeSanitizeShadowDOM:[],uponSanitizeAttribute:[],uponSanitizeElement:[],uponSanitizeShadowNode:[]}},oe=function(e,n,i,s){return F(e,n)&&Re(e[n])?_(s.base?W(s.base):{},e[n],s.transform):i},Gt=function(e,n,i){let s=F(e,n)?e[n]:void 0;return s&&typeof s==\"object\"?W(s):i()};function lr(){let t=arguments.length>0&&arguments[0]!==void 0?arguments[0]:fs(),e=p=>lr(p);if(e.version=\"3.4.15\",e.removed=[],!t||!t.document||t.document.nodeType!==G.document||!t.Element)return e.isSupported=!1,e;let n=t.document,i=n,s=i.currentScript;t.DocumentFragment;let o=t.HTMLTemplateElement,c=t.Node,a=t.Element,f=t.NodeFilter,h=t.NamedNodeMap;h===void 0&&(t.NamedNodeMap||t.MozNamedAttrMap),t.HTMLFormElement;let k=t.DOMParser,m=t.trustedTypes,x=a.prototype,C=j(x,\"cloneNode\"),w=j(x,\"remove\"),B=j(x,\"removeAttributeNode\"),le=j(x,\"nextSibling\"),J=j(x,\"childNodes\"),ee=j(x,\"parentNode\"),He=j(x,\"shadowRoot\"),Le=j(x,\"attributes\"),Y=c&&c.prototype?j(c.prototype,\"nodeType\"):null,q=c&&c.prototype?j(c.prototype,\"nodeName\"):null,Ge=c&&c.prototype?j(c.prototype,\"ownerDocument\"):null,Oe=function(r){return Y?Y(r):r.nodeType},ct=function(r){return q?q(r):r.nodeName};if(typeof o==\"function\"){let p=n.createElement(\"template\");p.content&&p.content.ownerDocument&&(n=p.content.ownerDocument)}let $,ae=\"\",ut,jt=!1,Ie=0,Yt=function(){if(Ie>0)throw ge('A configured TRUSTED_TYPES_POLICY callback (createHTML or createScriptURL) must not call DOMPurify.sanitize, as that causes infinite recursion. Do not pass a policy whose callbacks wrap DOMPurify as TRUSTED_TYPES_POLICY; see the \"DOMPurify and Trusted Types\" section of the README.')},ke=function(r){Yt(),Ie++;try{return $.createHTML(r)}finally{Ie--}},cr=function(r){Yt(),Ie++;try{return $.createScriptURL(r)}finally{Ie--}},ur=function(){return jt||(ut=ds(m,s),jt=!0),ut},We=n,pt=We.implementation,Zt=We.createNodeIterator,pr=We.createDocumentFragment,hr=We.getElementsByTagName,fr=i.importNode,S=rr();e.isSupported=typeof ir==\"function\"&&typeof ee==\"function\"&&pt&&pt.createHTMLDocument!==void 0;let dr=es,gr=ts,mr=ns,kr=rs,br=is,xr=ss,Xt=os,Tr=as,Qt=er,E=null,ht=_({},[...Qn,...Ut,...Ft,...Bt,...Vn]),R=null,ft=_({},[...Kn,...Ht,...Jn,...at]),Q=Object.seal(Ee(null,{tagNameCheck:{writable:!0,configurable:!1,enumerable:!0,value:null},attributeNameCheck:{writable:!0,configurable:!1,enumerable:!0,value:null},allowCustomizedBuiltInElements:{writable:!0,configurable:!1,enumerable:!0,value:!1}})),De=null,Vt=null,ne=Object.seal(Ee(null,{tagCheck:{writable:!0,configurable:!1,enumerable:!0,value:null},attributeCheck:{writable:!0,configurable:!1,enumerable:!0,value:null}})),Kt=!0,dt=!0,Jt=!1,en=!0,re=!1,ce=!0,ue=!1,gt=!1,qe=null,je=null,mt=!1,be=!1,Ye=!1,Ze=!1,tn=!0,nn=!1,rn=\"user-content-\",kt=!0,bt=!1,xe={},Te=null,sn=_({},[\"annotation-xml\",\"audio\",\"colgroup\",\"desc\",\"foreignobject\",\"head\",\"iframe\",\"math\",\"mi\",\"mn\",\"mo\",\"ms\",\"mtext\",\"noembed\",\"noframes\",\"noscript\",\"plaintext\",\"script\",\"selectedcontent\",\"style\",\"svg\",\"template\",\"thead\",\"title\",\"video\",\"xmp\"]),on=null,ln=_({},[\"audio\",\"video\",\"img\",\"source\",\"image\",\"track\"]),an=null,cn=_({},[\"alt\",\"class\",\"for\",\"id\",\"label\",\"name\",\"pattern\",\"placeholder\",\"role\",\"summary\",\"title\",\"value\",\"style\",\"xmlns\"]),Xe=\"http://www.w3.org/1998/Math/MathML\",Qe=\"http://www.w3.org/2000/svg\",V=\"http://www.w3.org/1999/xhtml\",_e=V,xt=!1,Tt=null,_r=_({},[Xe,Qe,V],vt),un=D([\"mi\",\"mo\",\"mn\",\"ms\",\"mtext\"]),_t=_({},un),pn=D([\"annotation-xml\"]),wt=_({},pn),wr=_({},[\"title\",\"style\",\"font\",\"a\",\"script\"]),Pe=null,yr=[\"application/xhtml+xml\",\"text/html\"],Ar=\"text/html\",O=null,we=null,Sr=n.createElement(\"form\"),hn=function(r){return r instanceof RegExp||r instanceof Function},yt=function(){let r=arguments.length>0&&arguments[0]!==void 0?arguments[0]:{};if(we&&we===r)return;(!r||typeof r!=\"object\")&&(r={}),r=W(r),Pe=yr.indexOf(r.PARSER_MEDIA_TYPE)===-1?Ar:r.PARSER_MEDIA_TYPE,O=Pe===\"application/xhtml+xml\"?vt:Be,E=oe(r,\"ALLOWED_TAGS\",ht,{transform:O}),R=oe(r,\"ALLOWED_ATTR\",ft,{transform:O}),Tt=oe(r,\"ALLOWED_NAMESPACES\",_r,{transform:vt}),an=oe(r,\"ADD_URI_SAFE_ATTR\",cn,{transform:O,base:cn}),on=oe(r,\"ADD_DATA_URI_TAGS\",ln,{transform:O,base:ln}),Te=oe(r,\"FORBID_CONTENTS\",sn,{transform:O}),De=oe(r,\"FORBID_TAGS\",W({}),{transform:O}),Vt=oe(r,\"FORBID_ATTR\",W({}),{transform:O}),xe=F(r,\"USE_PROFILES\")?r.USE_PROFILES&&typeof r.USE_PROFILES==\"object\"?W(r.USE_PROFILES):r.USE_PROFILES:!1,Kt=r.ALLOW_ARIA_ATTR!==!1,dt=r.ALLOW_DATA_ATTR!==!1,Jt=r.ALLOW_UNKNOWN_PROTOCOLS||!1,en=r.ALLOW_SELF_CLOSE_IN_ATTR!==!1,re=r.SAFE_FOR_TEMPLATES||!1,ce=r.SAFE_FOR_XML!==!1,ue=r.WHOLE_DOCUMENT||!1,be=r.RETURN_DOM||!1,Ye=r.RETURN_DOM_FRAGMENT||!1,Ze=r.RETURN_TRUSTED_TYPE||!1,mt=r.FORCE_BODY||!1,tn=r.SANITIZE_DOM!==!1,nn=r.SANITIZE_NAMED_PROPS||!1,kt=r.KEEP_CONTENT!==!1,bt=r.IN_PLACE||!1,Qt=Vi(r.ALLOWED_URI_REGEXP)?r.ALLOWED_URI_REGEXP:er,_e=typeof r.NAMESPACE==\"string\"?r.NAMESPACE:V,_t=Gt(r,\"MATHML_TEXT_INTEGRATION_POINTS\",()=>_({},un)),wt=Gt(r,\"HTML_INTEGRATION_POINTS\",()=>_({},pn));let l=Gt(r,\"CUSTOM_ELEMENT_HANDLING\",()=>Ee(null));if(Q=Ee(null),F(l,\"tagNameCheck\")&&hn(l.tagNameCheck)&&(Q.tagNameCheck=l.tagNameCheck),F(l,\"attributeNameCheck\")&&hn(l.attributeNameCheck)&&(Q.attributeNameCheck=l.attributeNameCheck),F(l,\"allowCustomizedBuiltInElements\")&&typeof l.allowCustomizedBuiltInElements==\"boolean\"&&(Q.allowCustomizedBuiltInElements=l.allowCustomizedBuiltInElements),P(Q),re&&(dt=!1),Ye&&(be=!0),xe&&(E=_({},Vn),R=Ee(null),xe.html===!0&&(_(E,Qn),_(R,Kn)),xe.svg===!0&&(_(E,Ut),_(R,Ht),_(R,at)),xe.svgFilters===!0&&(_(E,Ft),_(R,Ht),_(R,at)),xe.mathMl===!0&&(_(E,Bt),_(R,Jn),_(R,at))),ne.tagCheck=null,ne.attributeCheck=null,F(r,\"ADD_TAGS\")&&(typeof r.ADD_TAGS==\"function\"?ne.tagCheck=r.ADD_TAGS:Re(r.ADD_TAGS)&&(E===ht&&(E=W(E)),_(E,r.ADD_TAGS,O))),F(r,\"ADD_ATTR\")&&(typeof r.ADD_ATTR==\"function\"?ne.attributeCheck=r.ADD_ATTR:Re(r.ADD_ATTR)&&(R===ft&&(R=W(R)),_(R,r.ADD_ATTR,O))),F(r,\"ADD_FORBID_CONTENTS\")&&Re(r.ADD_FORBID_CONTENTS)&&(Te===sn&&(Te=W(Te)),_(Te,r.ADD_FORBID_CONTENTS,O)),kt&&(E[\"#text\"]=!0),ue&&_(E,[\"html\",\"head\",\"body\"]),E.table&&(_(E,[\"tbody\"]),delete De.tbody),r.TRUSTED_TYPES_POLICY){if(typeof r.TRUSTED_TYPES_POLICY.createHTML!=\"function\")throw ge('TRUSTED_TYPES_POLICY configuration option must provide a \"createHTML\" hook.');if(typeof r.TRUSTED_TYPES_POLICY.createScriptURL!=\"function\")throw ge('TRUSTED_TYPES_POLICY configuration option must provide a \"createScriptURL\" hook.');let u=$;$=r.TRUSTED_TYPES_POLICY;try{ae=ke(\"\")}catch(d){throw $=u,d}}else r.TRUSTED_TYPES_POLICY===null?($=void 0,ae=\"\"):($===void 0&&($=ur()),$&&typeof ae==\"string\"&&(ae=ke(\"\")));D&&D(r),we=r},fn=_({},[...Ut,...Ft,...Ki]),dn=_({},[...Bt,...Ji]),Er=function(r,l,u){return l.namespaceURI===V?r===\"svg\":l.namespaceURI===Xe?r===\"svg\"&&(u===\"annotation-xml\"||_t[u]):!!fn[r]},Rr=function(r,l,u){return l.namespaceURI===V?r===\"math\":l.namespaceURI===Qe?r===\"math\"&&wt[u]:!!dn[r]},Lr=function(r,l,u){return l.namespaceURI===Qe&&!wt[u]||l.namespaceURI===Xe&&!_t[u]?!1:!dn[r]&&(wr[r]||!fn[r])},Or=function(r){let l=ee(r);(!l||!l.tagName)&&(l={namespaceURI:_e,tagName:\"template\"});let u=Be(r.tagName),d=Be(l.tagName);return Tt[r.namespaceURI]?r.namespaceURI===Qe?Er(u,l,d):r.namespaceURI===Xe?Rr(u,l,d):r.namespaceURI===V?Lr(u,l,d):!!(Pe===\"application/xhtml+xml\"&&Tt[r.namespaceURI]):!1},ie=function(r){ve(e.removed,{element:r});try{ee(r).removeChild(r)}catch{if(w(r),!ee(r))throw ge(\"a node selected for removal could not be detached from its tree and cannot be safely returned; refusing to sanitize in place\")}},gn=function(r,l,u){try{B(r,l)}catch{try{r.removeAttribute(u)}catch{}}},Ve=function(r){Ke(r);let l=J(r);if(l){let d=[];me(l,g=>{ve(d,g)}),me(d,g=>{try{w(g)}catch{}})}let u=Le(r);if(u)for(let d=u.length-1;d>=0;--d){let g=u[d],b=g&&g.name;typeof b==\"string\"&&gn(r,g,b)}},pe=function(r,l,u){if(!u)try{u=l.getAttributeNode(r)}catch{u=null}ve(e.removed,{attribute:u||null,from:l});try{u?B(l,u):l.removeAttribute(r)}catch{try{l.removeAttribute(r)}catch{}}if(r===\"is\")if(be||Ye)try{ie(l)}catch{}else try{l.setAttribute(r,\"\")}catch{}},Ir=function(r){let l=Le(r);if(l)for(let u=l.length-1;u>=0;--u){let d=l[u],g=d&&d.name;typeof g!=\"string\"||R[O(g)]||gn(r,d,g)}},Ke=function(r){let l=[r];for(;l.length>0;){let u=l.pop();Oe(u)===G.element&&Ir(u);let g=J(u);if(g)for(let b=g.length-1;b>=0;--b)l.push(g[b])}},mn=function(r,l){return ce?r===\"patchsrc\"?!0:r===\"for\"&&l!==\"label\"&&l!==\"output\":!1},Dr=function(r){if(!ce)return;let l=[r];for(;l.length>0;){let u=l.pop(),d=Oe(u);if(d===G.processingInstruction||d===G.comment&&z(nr,u.data)){try{w(u)}catch{}continue}if(d===G.element){let b=u,A=O(ct(u));try{b.hasAttribute&&b.hasAttribute(\"patchsrc\")&&b.removeAttribute(\"patchsrc\"),b.hasAttribute&&b.hasAttribute(\"for\")&&mn(\"for\",A)&&b.removeAttribute(\"for\")}catch{}}let g=J(u);if(g)for(let b=g.length-1;b>=0;--b)l.push(g[b])}},kn=function(r){let l=null,u=null;if(mt)r=\"<remove></remove>\"+r;else{let b=jn(r,/^[\\r\\n\\t ]+/);u=b&&b[0]}Pe===\"application/xhtml+xml\"&&_e===V&&(r='<html xmlns=\"http://www.w3.org/1999/xhtml\"><head></head><body>'+r+\"</body></html>\");let d=$?ke(r):r;if(_e===V)try{l=new k().parseFromString(d,Pe)}catch{}if(!l||!l.documentElement){l=pt.createDocument(_e,\"template\",null);try{l.documentElement.innerHTML=xt?ae:d}catch{}}let g=l.body||l.documentElement;return r&&u&&g.insertBefore(n.createTextNode(u),g.childNodes[0]||null),_e===V?hr.call(l,ue?\"html\":\"body\")[0]:ue?l.documentElement:g},bn=function(r){let l=Ge?Ge(r):r.ownerDocument;return Zt.call(l||r,r,f.SHOW_ELEMENT|f.SHOW_COMMENT|f.SHOW_TEXT|f.SHOW_PROCESSING_INSTRUCTION|f.SHOW_CDATA_SECTION,null)},Je=function(r){return r=Ue(r,dr,\" \"),r=Ue(r,gr,\" \"),r=Ue(r,mr,\" \"),r},At=function(r){var l;r.normalize();let u=Ge?Ge(r):r.ownerDocument,d=Zt.call(u||r,r,f.SHOW_TEXT|f.SHOW_COMMENT|f.SHOW_CDATA_SECTION|f.SHOW_PROCESSING_INSTRUCTION,null),g=d.nextNode();for(;g;)g.data=Je(g.data),g=d.nextNode();let b=(l=r.querySelectorAll)===null||l===void 0?void 0:l.call(r,\"template\");b&&me(b,A=>{ye(A.content)&&At(A.content)})},et=function(r){let l=q?q(r):null;return typeof l!=\"string\"||O(l)!==\"form\"?!1:typeof r.nodeName!=\"string\"||typeof r.textContent!=\"string\"||typeof r.removeChild!=\"function\"||r.attributes!==Le(r)||typeof r.removeAttribute!=\"function\"||typeof r.removeAttributeNode!=\"function\"||typeof r.getAttributeNode!=\"function\"||typeof r.setAttribute!=\"function\"||typeof r.namespaceURI!=\"string\"||typeof r.insertBefore!=\"function\"||typeof r.hasChildNodes!=\"function\"||r.nodeType!==Y(r)||r.childNodes!==J(r)},ye=function(r){if(!Y||typeof r!=\"object\"||r===null)return!1;try{return Y(r)===G.documentFragment}catch{return!1}},Ce=function(r){if(!Y||typeof r!=\"object\"||r===null)return!1;try{return typeof Y(r)==\"number\"}catch{return!1}};function K(p,r,l){p.length!==0&&me(p,u=>{u.call(e,r,l,we)})}let Pr=function(r,l){return!!(ce&&r.hasChildNodes()&&!Ce(r.firstElementChild)&&z(tr,r.textContent)&&z(tr,r.innerHTML)||ce&&r.namespaceURI===V&&ps[l]&&(Ce(r.firstElementChild)||typeof r.textContent==\"string\"&&z(hs[l],r.textContent))||r.nodeType===G.processingInstruction||ce&&r.nodeType===G.comment&&z(nr,r.data))},tt=function(r,l){if(r instanceof RegExp)return z(r,l);if(r instanceof Function){for(var u=arguments.length,d=new Array(u>2?u-2:0),g=2;g<u;g++)d[g-2]=arguments[g];return!!r(l,...d)}return!1},Cr=function(r,l,u){if(!De[l]&&yn(l)&&tt(Q.tagNameCheck,l))return!1;if(kt&&!Te[l]){let d=ee(r),g=J(r);if(g&&d){let b=g.length;for(let A=b-1;A>=0;--A){let L=r===u?C(g[A],!0):g[A];d.insertBefore(L,le(r))}}}return ie(r),!0},xn=function(r,l,u,d){return r.length===0?l:l===u||l===d?W(l):l},Tn=function(r,l){return r===l||ee(r)!==null?!1:(bt&&Ke(r),!0)},_n=function(r,l){if(K(S.beforeSanitizeElements,r,null),Tn(r,l))return!0;if(et(r))return ie(r),!0;let u=O(ct(r));if(E=xn(S.uponSanitizeElement,E,ht,qe),K(S.uponSanitizeElement,r,{tagName:u,allowedTags:E}),Tn(r,l))return!0;if(Pr(r,u))return ie(r),!0;if(De[u]||!(ne.tagCheck instanceof Function&&ne.tagCheck(u))&&!E[u]){let g=Cr(r,u,l);return g===!1&&K(S.afterSanitizeElements,r,null),g}if(Oe(r)===G.element&&!Or(r)||(u===\"noscript\"||u===\"noembed\"||u===\"noframes\")&&z(cs,r.innerHTML))return ie(r),!0;if(re&&r.nodeType===G.text){let g=Je(r.textContent);r.textContent!==g&&(ve(e.removed,{element:r.cloneNode()}),r.textContent=g)}return K(S.afterSanitizeElements,r,null),!1},wn=function(r,l,u){if(Vt[l]||mn(l,r)||tn&&(l===\"id\"||l===\"name\")&&(u in n||u in Sr))return!1;let d=R[l]||ne.attributeCheck instanceof Function&&ne.attributeCheck(l,r);return dt&&z(kr,l)||Kt&&z(br,l)?!0:d?an[l]||z(Qt,Ue(u,Xt,\"\"))||(l===\"src\"||l===\"xlink:href\"||l===\"href\")&&r!==\"script\"&&Yn(u,\"data:\")===0&&on[r]||Jt&&!z(xr,Ue(u,Xt,\"\"))?!0:!u:yn(r)&&tt(Q.tagNameCheck,r)&&tt(Q.attributeNameCheck,l,r)||l===\"is\"&&Q.allowCustomizedBuiltInElements&&tt(Q.tagNameCheck,u)},Nr=_({},[\"annotation-xml\",\"color-profile\",\"font-face\",\"font-face-format\",\"font-face-name\",\"font-face-src\",\"font-face-uri\",\"missing-glyph\"]),yn=function(r){return!Nr[Be(r)]&&z(Tr,r)},zr=function(r,l,u,d){if($&&typeof m==\"object\"&&typeof m.getAttributeType==\"function\"&&!u)switch(m.getAttributeType(r,l)){case\"TrustedHTML\":return ke(d);case\"TrustedScriptURL\":return cr(d)}return d},Mr=function(r,l,u,d){try{return u?r.setAttributeNS(u,l,d):r.setAttribute(l,d),et(r)?(ie(r),!1):!0}catch{return pe(l,r),!1}},An=function(r){K(S.beforeSanitizeAttributes,r,null);let l=r.attributes;if(!l||et(r))return;R=xn(S.uponSanitizeAttribute,R,ft,je);let u={attrName:\"\",attrValue:\"\",keepAttr:!0,allowedAttributes:R,forceKeepAttr:void 0},d=l.length,g=O(r.nodeName);for(;d--;){let b=l[d],A=b.name,L=b.namespaceURI,v=b.value,U=O(A),Et=v,M=A===\"value\"?Et:qi(Et),Sn=!1;if(u.attrName=U,u.attrValue=M,u.keepAttr=!0,u.forceKeepAttr=void 0,K(S.uponSanitizeAttribute,r,u),M=u.attrValue,nn&&(U===\"id\"||U===\"name\")&&Yn(M,rn)!==0&&(pe(A,r,b),M=rn+M,Sn=!0),ce&&z(/((--!?|])>)|<\\/(style|script|title|xmp|textarea|noscript|iframe|noembed|noframes)/i,M)){pe(A,r,b);continue}if(U===\"attributename\"&&jn(M,\"href\")){pe(A,r,b);continue}if(!u.forceKeepAttr){if(!u.keepAttr){pe(A,r,b);continue}if(!en&&z(us,M)){pe(A,r,b);continue}if(re&&(M=Je(M)),!wn(g,U,M)){pe(A,r,b);continue}M=zr(g,U,L,M),M!==Et&&Mr(r,A,L,M)&&Sn&&qn(e.removed)}}K(S.afterSanitizeAttributes,r,null)},nt=function(r){let l=null,u=bn(r);for(K(S.beforeSanitizeShadowDOM,r,null);l=u.nextNode();)if(K(S.uponSanitizeShadowNode,l,null),_n(l,r),An(l),ye(l.content)&&nt(l.content),Oe(l)===G.element){let d=He(l);ye(d)&&(St(d),nt(d))}K(S.afterSanitizeShadowDOM,r,null)},St=function(r){let l=[{node:r,shadow:null}];for(;l.length>0;){let u=l.pop();if(u.shadow){nt(u.shadow);continue}let d=u.node,b=Oe(d)===G.element,A=J(d);if(A)for(let L=A.length-1;L>=0;--L)l.push({node:A[L],shadow:null});if(b){let L=q?q(d):null;if(typeof L==\"string\"&&O(L)===\"template\"){let v=d.content;ye(v)&&l.push({node:v,shadow:null})}}if(b){let L=He(d);ye(L)&&l.push({node:null,shadow:L},{node:L,shadow:null})}}};return e.sanitize=function(p){let r=arguments.length>1&&arguments[1]!==void 0?arguments[1]:{},l=null,u=null,d=null,g=null;if(xt=!p,xt&&(p=\"<!-->\"),typeof p!=\"string\"&&!Ce(p)&&(p=Qi(p),typeof p!=\"string\"))throw ge(\"dirty is not a string, aborting\");if(!e.isSupported)return p;gt?(E=qe,R=je):yt(r),(S.uponSanitizeElement.length>0||S.uponSanitizeAttribute.length>0)&&(E=W(E)),S.uponSanitizeAttribute.length>0&&(R=W(R)),e.removed=[];let b=bt&&typeof p!=\"string\"&&Ce(p);if(b){Dr(p);let v=ct(p);if(typeof v==\"string\"){let U=O(v);if(!E[U]||De[U])throw Ve(p),ge(\"root node is forbidden and cannot be sanitized in-place\")}if(et(p))throw Ve(p),ge(\"root node is clobbered and cannot be sanitized in-place\");try{St(p)}catch(U){throw Ve(p),U}}else if(Ce(p))l=kn(\"<!---->\"),u=l.ownerDocument.importNode(p,!0),u.nodeType===G.element&&u.nodeName===\"BODY\"||u.nodeName===\"HTML\"?l=u:l.appendChild(u),St(l);else{if(!be&&!re&&!ue&&p.indexOf(\"<\")===-1)return $&&Ze?ke(p):p;if(l=kn(p),!l)return be?null:Ze?ae:\"\"}l&&mt&&ie(l.firstChild);let A=b?p:l;try{let v=bn(A);for(;d=v.nextNode();)_n(d,A),An(d),ye(d.content)&&nt(d.content)}catch(v){throw b&&(Ve(p),me(e.removed,U=>{U.element&&Ke(U.element)})),v}if(b)return me(e.removed,v=>{v.element&&Ke(v.element)}),re&&At(p),p;if(be){if(re&&At(l),Ye)for(g=pr.call(l.ownerDocument);l.firstChild;)g.appendChild(l.firstChild);else g=l;return(R.shadowroot||R.shadowrootmode)&&(g=fr.call(i,g,!0)),g}let L=ue?l.outerHTML:l.innerHTML;return ue&&E[\"!doctype\"]&&l.ownerDocument&&l.ownerDocument.doctype&&l.ownerDocument.doctype.name&&z(ls,l.ownerDocument.doctype.name)&&(L=\"<!DOCTYPE \"+l.ownerDocument.doctype.name+`>\n`+L),re&&(L=Je(L)),$&&Ze?ke(L):L},e.setConfig=function(){let p=arguments.length>0&&arguments[0]!==void 0?arguments[0]:{};yt(p),gt=!0,qe=E,je=R},e.clearConfig=function(){we=null,gt=!1,qe=null,je=null,$=ut,ae=\"\"},e.isValidAttribute=function(p,r,l){we||yt({});let u=O(p),d=O(r);return wn(u,d,l)},e.addHook=function(p,r){typeof r==\"function\"&&F(S,p)&&ve(S[p],r)},e.removeHook=function(p,r){if(F(S,p)){if(r!==void 0){let l=Gi(S[p],r);return l===-1?void 0:Wi(S[p],l,1)[0]}return qn(S[p])}},e.removeHooks=function(p){F(S,p)&&(S[p]=[])},e.removeAllHooks=function(){S=rr()},e}var ar=lr();window.renderNoteMarkdown=(t,e)=>{let n=y.parse(t,{gfm:!0,breaks:!0,async:!1});e.innerHTML=ar.sanitize(n,{ALLOWED_TAGS:[\"p\",\"br\",\"hr\",\"h1\",\"h2\",\"h3\",\"h4\",\"h5\",\"h6\",\"strong\",\"em\",\"del\",\"blockquote\",\"ul\",\"ol\",\"li\",\"pre\",\"code\",\"a\",\"table\",\"thead\",\"tbody\",\"tr\",\"th\",\"td\",\"input\"],ALLOWED_ATTR:[\"href\",\"title\",\"align\",\"type\",\"checked\",\"disabled\",\"start\"],ALLOW_DATA_ATTR:!1,ALLOW_ARIA_ATTR:!1}),e.querySelectorAll(\"a\").forEach(i=>{let s=i.getAttribute(\"href\")||\"\";/^(https?:\\/\\/|mailto:|#)/i.test(s)?(i.target=\"_blank\",i.rel=\"noopener noreferrer\"):i.removeAttribute(\"href\")}),e.querySelectorAll(\"input\").forEach(i=>{i.type=\"checkbox\",i.disabled=!0}),e.querySelectorAll(\"table\").forEach(i=>{let s=document.createElement(\"div\");s.className=\"markdown-table-scroll\",s.tabIndex=0,s.setAttribute(\"role\",\"region\"),s.setAttribute(\"aria-label\",\"\\u8868\\u683C\\uFF0C\\u53EF\\u6A2A\\u5411\\u6EDA\\u52A8\"),i.replaceWith(s),s.appendChild(i)})};})();\n";
// MARKDOWN_VENDOR_END


const publicContent = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#356b53"><title>note · 留一页给灵感</title>
<style>*{box-sizing:border-box}body{margin:0;background:#edf0e7;color:#283f34;font-family:'Segoe UI','Microsoft YaHei',sans-serif;min-height:100vh;padding:32px}main{max-width:1060px;margin:auto}header{display:flex;align-items:center;gap:12px;padding:12px 0;font:30px Georgia,serif}header span{display:grid;place-items:center;background:#356b53;color:#fffefa;width:40px;height:40px;border-radius:12px;font-style:italic}header small{font:11px sans-serif;letter-spacing:2px;color:#778176;margin-left:auto}.hero{margin-top:50px;padding:64px;border:1px solid #dde3d7;border-radius:24px;background:#fffefa;position:relative;overflow:hidden}.eyebrow{font-size:11px;letter-spacing:3px;color:#778176}h1{font-family:'Songti SC',SimSun,serif;font-size:clamp(32px,5vw,58px);line-height:1.5;font-weight:500;letter-spacing:3px;margin:24px 0}p{color:#768172;font-size:14px;line-height:2}.quote{margin:42px 0 0;padding:24px 0 0;border-top:1px solid #e2e6dc;font:italic 20px Georgia,serif;color:#356b53}.features{display:grid;grid-template-columns:repeat(3,1fr);gap:24px;margin:34px 0}.features article{padding:18px 6px}.features span{font:italic 22px Georgia,serif;color:#7b9b7f}.features h2{font-size:16px;font-weight:500;margin-top:18px}.features p{font-size:12px}footer{border-top:1px solid #d9dfd2;padding:20px 0;font-size:10px;letter-spacing:2px;color:#788373}@media(max-width:600px){body{padding:22px}.hero{margin-top:30px;padding:34px 26px}.features{grid-template-columns:1fr;gap:0}.features article{padding:12px 6px}.quote{font-size:16px}header small{font-size:9px}}</style></head>
<body><main><header><span>n</span>note<small>A QUIET PLACE FOR WORDS</small></header><section class="hero"><div class="eyebrow">LESS NOISE. MORE WORDS.</div><h1>让灵感落在纸上，<br>让日常慢慢生长。</h1><p>一段文字，收藏一个瞬间。<br>在忙碌的生活里，留一点空间给思考、阅读与创作。</p><div class="quote">Every little thought deserves a page.</div></section><section class="features"><article><span>01</span><h2>记录片刻</h2><p>把稍纵即逝的念头，写成值得珍藏的文字。</p></article><article><span>02</span><h2>整理思绪</h2><p>从一个想法开始，慢慢找到清晰的方向。</p></article><article><span>03</span><h2>专注创作</h2><p>让文字拥有自己的节奏，让故事自然发生。</p></article></section><footer>NOTE / 留一页给灵感</footer></main></body></html>`;

const htmlContent = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>note · 留一页给灵感</title>
    <meta name="theme-color" content="#356b53">
    <style>
        :root {
            --bg-primary: #fffefa; --bg-secondary: #f3f2ec; --text-main: #263c34;
            --text-muted: #747e75; --accent: #356b53; --accent-hover: #295640;
            --border: #e4e7dc; --danger: #b9574d; --nav-bg: #fafbf6;
            --soft: #e8eee3; --canvas: #e9ede3; --shadow: 0 14px 45px #213d3210;
        }
        body.dark {
            color-scheme: dark; --bg-primary: #202a25; --bg-secondary: #19231e;
            --text-main: #e5eadd; --text-muted: #a0afa1; --accent: #8ab49a;
            --accent-hover: #9ec8ae; --border: #34433a; --danger: #e09688;
            --nav-bg: #1b241f; --soft: #303f35; --canvas: #121b16; --shadow: 0 14px 45px #0002;
        }
        body.passion {
            --bg-primary: #fffaf7; --bg-secondary: #f6ede7; --text-main: #624239;
            --text-muted: #91756b; --accent: #a05c4e; --accent-hover: #884b3e;
            --border: #e9dcd3; --danger: #b74747; --nav-bg: #fcf5f0;
            --soft: #f0e1d7; --canvas: #eadbd0; --shadow: 0 14px 45px #62423910;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif; background: var(--canvas); color: var(--text-main); height: 100vh; height: 100dvh; overflow: hidden; font-size: 14px; -webkit-font-smoothing: antialiased; }
        button, input, textarea, select { font: inherit; }
        button { cursor: pointer; border: 1px solid transparent; background: var(--accent); color: var(--bg-primary); padding: 10px 16px; border-radius: 9px; font-size: 13px; font-weight: 600; transition: background .18s, transform .18s; display: inline-flex; align-items: center; justify-content: center; gap: 6px; }
        button:hover { background: var(--accent-hover); }
        button:active { transform: translateY(1px); }
        button:disabled { opacity: .6; cursor: wait; }
        button.btn-text { color: var(--accent); background: transparent; padding: 7px 10px; }
        button.btn-text:hover { background: var(--soft); }
        button.btn-danger { color: var(--danger); background: transparent; }
        button.btn-danger:hover { background: color-mix(in srgb, var(--danger) 10%, transparent); }
        :focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
        input, textarea, select { min-width: 0; background: var(--bg-primary); color: var(--text-main); border: 1px solid var(--border); padding: 11px 13px; border-radius: 9px; outline: none; }
        input:focus, textarea:focus, select:focus { border-color: var(--accent); }
        input::placeholder, textarea::placeholder { color: var(--text-muted); opacity: .8; }
        input[type=text] { width: 100%; }
        input[type=radio] { accent-color: var(--accent); }
        ::selection { background: var(--soft); color: var(--text-main); }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 8px; }
        .brand-mark { display: inline-flex; width: 35px; height: 35px; border-radius: 10px; align-items: center; justify-content: center; background: var(--accent); color: var(--bg-primary); font-family: Georgia, serif; font-size: 27px; font-style: italic; font-weight: normal; flex-shrink: 0; }
        .eyebrow { font-size: 10px; letter-spacing: 3px; text-transform: uppercase; font-weight: 600; color: var(--text-muted); }
        #login-screen { position: fixed; inset: 0; z-index: 1000; display: flex; align-items: center; justify-content: center; padding: 40px; background: var(--canvas); overflow-y: auto; }
        .login-shell { width: 1040px; max-width: 100%; min-height: 610px; background: var(--bg-primary); display: grid; grid-template-columns: 1.15fr 1fr; border: 1px solid var(--border); border-radius: 24px; box-shadow: 0 35px 100px #233d3214; overflow: hidden; }
        .login-story { background: var(--soft); padding: 42px 46px; position: relative; overflow: hidden; display: flex; flex-direction: column; }
        .story-brand { display: flex; align-items: center; gap: 12px; font-size: 19px; letter-spacing: 1px; font-weight: 600; }
        .login-story h1 { font-family: 'Songti SC', 'SimSun', Georgia, serif; font-size: 43px; line-height: 1.45; font-weight: 500; margin: 48px 0 15px; letter-spacing: 3px; z-index: 1; }
        .login-story > p { line-height: 1.9; color: var(--text-muted); z-index: 1; }
        .paper-art { position: relative; height: 200px; margin-top: 24px; }
        .paper-sheet { width: 190px; height: 185px; position: absolute; left: 90px; top: 12px; background: var(--bg-primary); border: 1px solid var(--border); border-radius: 3px; transform: rotate(-10deg); box-shadow: 0 15px 30px #233d3210; padding: 25px; }
        .paper-sheet.back { transform: rotate(9deg); left: 137px; top: 3px; background: var(--nav-bg); }
        .paper-sheet .paper-title { font-family: Georgia, serif; font-style: italic; font-size: 23px; margin-bottom: 18px; color: var(--accent); }
        .paper-line { height: 1px; background: var(--border); margin: 12px 0; }
        .paper-line.short { width: 65%; }
        .paper-seal { position: absolute; right: 28px; bottom: 10px; width: 57px; height: 57px; border-radius: 50%; background: var(--accent); color: var(--bg-primary); display: grid; place-items: center; font-size: 27px; transform: rotate(12deg); }
        .story-foot { margin-top: auto; padding-top: 24px; font-size: 10px; letter-spacing: 2px; color: var(--text-muted); }
        .login-box { align-self: center; width: 100%; padding: 54px 48px; }
        .login-box h2 { font-family: 'Songti SC', 'SimSun', serif; font-size: 32px; font-weight: 500; margin: 15px 0 12px; letter-spacing: 2px; }
        .login-description { color: var(--text-muted); line-height: 1.8; margin-bottom: 36px; }
        .login-box label { display: block; font-size: 12px; margin-bottom: 10px; font-weight: 600; }
        .login-box input { width: 100%; height: 49px; margin-bottom: 18px; background: var(--bg-secondary); }
        .login-box button { width: 100%; height: 48px; font-weight: 500; letter-spacing: 1px; }
        .login-hint { margin-top: 26px; padding-top: 22px; border-top: 1px solid var(--border); font-size: 11px; text-align: center; color: var(--text-muted); letter-spacing: 1px; }
        #login-err { font-size: 13px; line-height: 1.6; }
        #app { display: none; height: 100vh; height: 100dvh; flex-direction: column; padding: 22px; max-width: 1920px; margin: auto; }
        #app > header { flex-shrink: 0; min-height: 72px; padding: 15px 25px; background: var(--nav-bg); display: flex; justify-content: space-between; align-items: center; gap: 16px; border: 1px solid var(--border); border-radius: 16px 16px 0 0; }
        .header-brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
        .logo { display: flex; align-items: center; gap: 10px; font-family: Georgia, serif; font-size: 21px; letter-spacing: -.5px; }
        .logo .brand-mark { width: 31px; height: 31px; font-size: 21px; border-radius: 9px; }
        .logo small { font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif; font-size: 10px; font-weight: 400; letter-spacing: 2px; margin-left: 6px; padding-left: 14px; border-left: 1px solid var(--border); color: var(--text-muted); white-space: nowrap; }
        .controls { display: flex; align-items: center; gap: 9px; flex-shrink: 0; }
        .header-divider { width: 1px; height: 22px; background: var(--border); margin: 0 4px; }
        #save-status { font-size: 11px; color: var(--text-muted); max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        #manual-save-btn { padding: 9px 17px; }
        #theme-select { font-size: 12px; padding: 8px 10px; background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 9px; }
        #theme-select option { background: var(--bg-primary); color: var(--text-main); }
        #app > header .logout-button { color: var(--danger); background: transparent; border-color: transparent; }
        #app > header .logout-button:hover { background: color-mix(in srgb, var(--danger) 10%, transparent); border-color: transparent; }
        .main-container { display: flex; flex: 1; min-height: 0; position: relative; overflow: hidden; border: 1px solid var(--border); border-top: none; border-radius: 0 0 16px 16px; box-shadow: var(--shadow); background: var(--bg-primary); }
        .sidebar { width: 290px; flex-shrink: 0; background: var(--nav-bg); border-right: 1px solid var(--border); display: flex; flex-direction: column; min-height: 0; }
        .sidebar-heading { display: flex; justify-content: space-between; align-items: center; padding: 27px 23px 18px; }
        .sidebar-heading strong { font-size: 13px; letter-spacing: 1px; font-weight: 500; }
        #item-count { font-size: 10px; padding: 3px 8px; border-radius: 5px; background: var(--soft); color: var(--accent); }
        .tabs { display: flex; margin: 0 20px 16px; padding: 4px; background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 9px; gap: 3px; }
        button.tab { flex: 1; text-align: center; padding: 8px; color: var(--text-muted); background: transparent; font-weight: 500; font-size: 12px; border-radius: 6px; }
        button.tab.active { color: var(--accent); background: var(--bg-primary); box-shadow: 0 2px 5px #233d3209; }
        .search-box { position: relative; margin: 0 20px 12px; display: flex; align-items: center; gap: 7px; padding: 0 30px 0 11px; color: var(--text-muted); border: 1px solid var(--border); border-radius: 10px; background: var(--bg-secondary); transition: border-color .15s ease, box-shadow .15s ease; }
        .search-box input { width: 100%; padding: 9px 0; border: none; background: transparent; font-size: 12px; border-radius: 0; outline: none; box-shadow: none; appearance: none; -webkit-appearance: none; }
        .search-box input::-webkit-search-cancel-button, .search-box input::-webkit-search-decoration { display: none; }
        .search-box:focus-within { border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 14%, transparent); }
        .search-clear { position: absolute; right: 7px; top: 50%; transform: translateY(-50%); width: 18px; height: 18px; padding: 0; border: none; border-radius: 50%; background: transparent; color: var(--text-muted); font-size: 13px; line-height: 1; cursor: pointer; display: flex; align-items: center; justify-content: center; }
        .search-clear:hover { color: var(--text-main); background: var(--border); }
        .item-title mark, .item-preview mark { background: color-mix(in srgb, var(--accent) 32%, transparent); color: inherit; padding: 0 1px; border-radius: 2px; }
        .list-container { flex: 1; min-height: 0; overflow-y: auto; padding: 0 12px 15px; }
        .list-item { padding: 16px 13px 10px; margin-bottom: 5px; border-radius: 9px; border: 1px solid transparent; transition: background .15s; cursor: pointer; }
        .list-item:hover { background: var(--bg-secondary); }
        .list-item.active { background: var(--soft); border-color: color-mix(in srgb, var(--accent) 20%, var(--soft)); }
        .item-info { display: flex; align-items: center; gap: 8px; }
        .item-title { flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-size: 13px; font-weight: 600; }
        .item-preview { color: var(--text-muted); font-size: 11px; line-height: 1.9; white-space: nowrap; text-overflow: ellipsis; overflow: hidden; margin-top: 6px; }
        .item-actions { display: flex; justify-content: flex-end; gap: 5px; margin-top: 6px; }
        .item-actions button { padding: 2px 5px; font-size: 10px; font-weight: normal; color: var(--text-muted); }
        .list-empty { padding: 28px 12px; text-align: center; color: var(--text-muted); font-size: 12px; line-height: 2; }
        .pin-badge { flex-shrink: 0; font-size: 10px; background: color-mix(in srgb, var(--accent) 14%, transparent); color: var(--accent); padding: 1px 5px; border-radius: 4px; }
        .drag-handle { flex-shrink: 0; cursor: grab; color: var(--text-muted); padding: 0 1px; font-size: 13px; opacity: .5; user-select: none; }
        .drag-handle:hover { opacity: 1; }
        .list-item.drag-over { border: 1px dashed var(--accent); }
        .list-item.selected { background: var(--soft); border-color: color-mix(in srgb, var(--accent) 30%, var(--soft)); }
        .item-check { width: 16px; height: 16px; accent-color: var(--accent); flex-shrink: 0; }
        .batch-bar { display: none; flex-direction: column; gap: 5px; margin: 0 20px 10px; padding: 8px 10px; background: var(--soft); border-radius: 10px; font-size: 11px; }
        .batch-row { display: flex; flex-wrap: wrap; align-items: center; gap: 4px; }
        .batch-row .count { margin-right: auto; color: var(--text-muted); }
        .batch-bar button { padding: 4px 9px; font-size: 11px; font-weight: normal; }
        .list-toolbar { display: flex; align-items: center; gap: 6px; margin: 0 20px 14px; }
        .list-toolbar select { flex: 1; min-width: 0; padding: 8px 10px; font-size: 12px; border-radius: 10px; background: var(--bg-secondary); outline: none; box-shadow: none; appearance: none; -webkit-appearance: none; }
        .list-toolbar select:focus { border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 14%, transparent); }
        .toolbar-btn { padding: 8px 12px; font-size: 11px; font-weight: 500; border: 1px solid var(--border); border-radius: 10px; background: var(--bg-secondary); color: var(--text-main); white-space: nowrap; cursor: pointer; }
        .toolbar-btn:hover { border-color: var(--accent); color: var(--accent); }
        .item-created { font-size: 10px; color: var(--text-muted); margin-top: 3px; }
        .item-modified { font-size: 10px; color: var(--text-muted); margin-right: auto; align-self: center; }
        #toast-box { position: fixed; top: 16px; left: 50%; transform: translateX(-50%); z-index: 999; display: flex; flex-direction: column; gap: 8px; align-items: center; pointer-events: none; }
        .toast { background: var(--bg-primary); color: var(--text-main); border: 1px solid var(--border); border-left: 3px solid var(--accent); border-radius: 9px; padding: 10px 16px; font-size: 12px; box-shadow: var(--shadow); animation: toast-in .25s ease; max-width: min(460px, calc(100vw - 40px)); pointer-events: auto; }
        .toast-error { border-left-color: var(--danger); }
        .toast-out { opacity: 0; transform: translateY(-8px); transition: opacity .3s, transform .3s; }
        @keyframes toast-in { from { opacity: 0; transform: translateY(-10px); } }
        .add-btn-container { padding: 17px 20px; border-top: 1px solid var(--border); display: flex; }
        .add-btn-container button { width: 100%; background: transparent; color: var(--accent); border: 1px dashed color-mix(in srgb, var(--accent) 40%, var(--border)); font-size: 12px; font-weight: 500; }
        .add-btn-container button:hover { background: var(--soft); }
        .editor-area { flex: 1; min-width: 0; display: flex; flex-direction: column; position: relative; background: var(--bg-primary); }
        .editor-header { display: flex; align-items: center; justify-content: space-between; gap: 15px; padding: 18px 30px; min-height: 69px; border-bottom: 1px solid var(--border); }
        .editor-header .controls-right { display: flex; align-items: center; gap: 6px; flex-shrink: 0; }
        .editor-header button { font-size: 11px; }
        #note-title { padding: 10px 0; border: none; background: transparent; font-family: 'Songti SC', 'SimSun', serif; font-size: 24px !important; letter-spacing: 1px; min-width: 80px; }
        #chapter-title { border: none; background: transparent; font-size: 23px !important; padding: 10px 0 16px; font-family: 'Songti SC', 'SimSun', serif; }
        .editor-body { flex: 1; min-height: 0; min-width: 0; overflow-y: auto; padding: 30px clamp(24px, 5vw, 80px) 16px; display: flex; flex-direction: column; gap: 12px; }
        textarea.content-input { flex: 1; min-height: 160px; width: 100%; resize: none; font-size: 16px; line-height: 2.1; padding: 0; border: none; border-radius: 0; background: transparent; font-family: 'Songti SC', 'SimSun', Georgia, serif; letter-spacing: .3px; }
        textarea.content-input:focus { outline: none; }
        .note-typesetting { display: flex; align-items: center; flex-wrap: wrap; gap: 10px 18px; padding: 11px 30px; border-bottom: 1px solid var(--border); color: var(--text-muted); background: var(--nav-bg); font-size: 11px; flex-shrink: 0; }
        .note-typesetting label { display: inline-flex; align-items: center; gap: 7px; }
        .note-typesetting select { padding: 5px 7px; font-size: 11px; border-color: transparent; background: var(--bg-secondary); }
        #note-body { padding: 30px clamp(20px, 4vw, 60px) 18px; }
        #note-content { width: 100%; max-width: var(--note-width, 800px); margin: 0 auto; font-family: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif; font-size: var(--note-font-size, 17px); line-height: var(--note-line-height, 1.85); letter-spacing: .02em; padding: 4px 8px 40px; tab-size: 4; overflow-wrap: anywhere; white-space: pre-wrap; }
        #note-content:focus-visible { outline: 1px solid var(--border); outline-offset: 6px; border-radius: 3px; }
        #reader-content.note-reading { max-width: var(--note-width, 800px); font-family: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif; line-height: var(--note-line-height, 1.85); letter-spacing: .02em; }
        #reader-content.note-reading h2 { text-align: left; font-weight: 600; font-size: 1.55em; line-height: 1.5; margin-bottom: 30px; }
        .note-reading-text { white-space: pre-wrap; overflow-wrap: anywhere; tab-size: 4; }
        .markdown-tools { display: flex; flex-wrap: wrap; align-items: center; gap: 4px; margin-left: auto; }
        .markdown-tools button { font-size: 11px; padding: 5px 8px; }
        .markdown-tools button[aria-pressed=true] { background: var(--soft); color: var(--accent); }
        #note-body.mode-split { flex-direction: row; gap: 25px; }
        #note-body.mode-split > * { flex: 1; width: 0; min-width: 0; }
        #note-body.mode-split #note-content { padding-right: 15px; border-right: 1px solid var(--border); }
        #note-preview { display: none; width: 100%; max-width: var(--note-width, 800px); margin: 0 auto; overflow-y: auto; padding: 4px 8px 40px; font-size: var(--note-font-size, 17px); line-height: var(--note-line-height, 1.85); }
        #note-body.mode-preview #note-content { display: none; }
        #note-body.mode-preview #note-preview, #note-body.mode-split #note-preview { display: block; }
        .markdown-content { font-family: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif; overflow-wrap: anywhere; }
        .markdown-content > :first-child { margin-top: 0 !important; }
        .markdown-content h1, .markdown-content h2, .markdown-content h3, .markdown-content h4, .markdown-content h5, .markdown-content h6 { font-weight: 600 !important; line-height: 1.5 !important; text-align: left !important; margin: 1.4em 0 .65em !important; }
        .markdown-content h1 { font-size: 1.7em; } .markdown-content h2 { font-size: 1.4em !important; } .markdown-content h3 { font-size: 1.2em; }
        .markdown-content p { text-indent: 0 !important; text-align: left !important; margin: 0 0 1em !important; }
        .markdown-content ul, .markdown-content ol { padding-left: 1.6em; margin: 0 0 1em; }
        .markdown-content li { margin: .3em 0; } .markdown-content li > p { margin-bottom: .4em !important; }
        .markdown-content blockquote { border-left: 3px solid var(--accent); margin: 1em 0; padding: .7em 1em; background: #8881; opacity: .9; }
        .markdown-content blockquote p:last-child { margin-bottom: 0 !important; }
        .markdown-content pre { overflow-x: auto; padding: 16px; margin: 1em 0; background: #8881; border: 1px solid #8883; border-radius: 8px; white-space: pre; font-size: .85em; line-height: 1.65; }
        .markdown-content code { font-family: Consolas, 'Courier New', monospace; background: #8881; padding: .15em .35em; border-radius: 4px; }
        .markdown-content pre code { background: none; padding: 0; }
        .markdown-content a { color: var(--accent); text-underline-offset: 3px; }
        .markdown-content hr { border: 0; border-top: 1px solid #8884; margin: 1.6em 0; }
        .markdown-table-scroll { overflow-x: auto; max-width: 100%; margin: 1.2em 0; border: 1px solid #8884; border-radius: 8px; }
        .markdown-content table { border-collapse: collapse; width: 100%; font-size: .9em; }
        .markdown-content th, .markdown-content td { padding: 10px 14px; min-width: 100px; border-right: 1px solid #8883; border-bottom: 1px solid #8883; text-align: left; }
        .markdown-content th[align=center], .markdown-content td[align=center] { text-align: center; }
        .markdown-content th[align=right], .markdown-content td[align=right] { text-align: right; }
        .markdown-content th { font-weight: 600; background: #8881; } .markdown-content tr:nth-child(even) { background: #88808; }
        .markdown-content input[type=checkbox] { accent-color: var(--accent); margin-right: 6px; }
        .table-dialog { border: 1px solid var(--border); border-radius: 14px; padding: 26px; background: var(--bg-primary); color: var(--text-main); margin: auto; width: min(360px, calc(100% - 32px)); box-shadow: var(--shadow); }
        .table-dialog::backdrop { background: #14281e66; }
        .table-dialog h3 { margin-bottom: 10px; } .table-dialog p { color: var(--text-muted); font-size: 12px; margin-bottom: 20px; }
        .table-dialog label { display: flex; align-items: center; justify-content: space-between; margin: 12px 0; }
        .table-dialog input { width: 95px; } .table-dialog .dialog-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 20px; }
        .history-dialog { width: min(540px, calc(100% - 32px)); }
        .history-dialog[open] { display: flex; flex-direction: column; gap: 14px; }
        .table-dialog .create-type-option { justify-content: flex-start; gap: 8px; margin: 0; font-size: 13px; }
        .table-dialog .create-type-option input { width: auto; }
        #create-title-input { margin-top: 14px; }
        #rename-input { margin-top: 14px; }
        .confirm-dialog { width: min(380px, calc(100% - 32px)); }
        .confirm-dialog p { color: var(--text-main); font-size: 13px; margin-bottom: 18px; overflow-wrap: anywhere; }
        button.btn-danger-solid { background: var(--danger); color: #fff; border: 1px solid var(--danger); }
        button.btn-danger-solid:hover { background: var(--danger); color: #fff; filter: brightness(1.08); }
        .history-list { overflow-y: auto; display: flex; flex-direction: column; gap: 8px; min-height: 48px; max-height: 50vh; }
        .history-item { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 10px 12px; border: 1px solid var(--border); border-radius: 10px; background: var(--bg-secondary); font-size: 12px; }
        .history-item strong { font-size: 13px; }
        .history-item .history-size { color: var(--text-muted); font-size: 11px; }
        .history-meta { display: flex; flex-direction: column; gap: 2px; overflow-wrap: anywhere; }
        .writing-footer { flex-shrink: 0; display: flex; align-items: center; justify-content: space-between; gap: 10px; margin: 0 30px; padding: 14px 0; border-top: 1px solid var(--border); font-size: 10px; color: var(--text-muted); letter-spacing: .6px; }
        .novel-layout { display: flex; flex: 1; min-height: 0; min-width: 0; overflow: hidden; }
        .novel-sidebar { width: 235px; flex-shrink: 0; background: var(--nav-bg); border-right: 1px solid var(--border); overflow-y: auto; display: flex; flex-direction: column; }
        .novel-main { flex: 1; min-width: 0; display: flex; flex-direction: column; position: relative; }
        .novel-main .editor-header { padding: 15px 20px; flex-wrap: wrap; }
        .controls-left { display: flex; align-items: center; min-width: 0; }
        #novel-current-path { font-size: 11px; white-space: nowrap; text-overflow: ellipsis; overflow: hidden; max-width: 240px; }
        .volume-item { padding: 8px 12px; }
        .volume-header { display: flex; align-items: center; justify-content: space-between; gap: 5px; font-size: 12px; padding: 8px 0; color: var(--accent); }
        .volume-header > span { overflow-wrap: anywhere; }
        .volume-header > div { display: flex; flex-shrink: 0; }
        .volume-header button { padding: 4px; font-size: 10px; }
        .chapter-list { padding-left: 8px; }
        .chapter-item { display: flex; justify-content: space-between; gap: 8px; padding: 10px; font-size: 11px; color: var(--text-muted); cursor: pointer; border-radius: 7px; }
        .chapter-item > span { overflow-wrap: anywhere; }
        .chapter-item:hover, .chapter-item.active { background: var(--soft); color: var(--accent); }
        .crawler-box { display: none; flex-direction: column; gap: 10px; background: var(--bg-secondary); border-bottom: 1px solid var(--border); padding: 14px; font-size: 12px; }
        .crawler-box input, .crawler-box textarea { font-size: 11px; }
        .crawler-row { display: flex; gap: 10px; align-items: center; font-size: 11px; }
        .crawler-source-input { min-height: 90px; resize: vertical; width: 100%; }
        .progress-bar-container { display: none; width: 100%; height: 5px; background: var(--border); border-radius: 5px; overflow: hidden; }
        .progress-bar-inner { background: var(--accent); height: 100%; width: 0; transition: width .2s; }
        #empty-state { flex: 1; min-width: 0; display: flex; align-items: center; justify-content: center; padding: 40px; background: radial-gradient(ellipse at 50% 45%, var(--nav-bg), var(--bg-primary) 70%); }
        .empty-inner { max-width: 450px; text-align: center; }
        .empty-illustration { margin: 0 auto 30px; width: 100px; height: 116px; border: 1px solid var(--border); border-radius: 5px; transform: rotate(-6deg); background: var(--bg-primary); box-shadow: 10px 8px 0 var(--soft); padding: 24px 19px; }
        .empty-illustration svg { color: var(--accent); width: 25px; height: 25px; }
        .empty-illustration i { display: block; height: 1px; margin-top: 12px; background: var(--border); }
        .empty-inner h2 { font-size: 29px; font-family: 'Songti SC', 'SimSun', serif; font-weight: normal; margin: 15px 0; letter-spacing: 3px; }
        .empty-inner p { font-size: 12px; line-height: 2; color: var(--text-muted); }
        .empty-inner button { margin-top: 28px; padding: 11px 24px; font-weight: 500; }
        .empty-tip { margin-top: 42px; font-size: 10px; letter-spacing: 1px; color: var(--text-muted); }
        #reader-overlay { position: fixed; inset: 0; z-index: 3000; overflow: hidden; display: flex; flex-direction: column; }
        .reader-toolbar { position: absolute; top: 0; left: 0; width: 100%; padding: 14px 24px; display: flex; align-items: center; justify-content: center; gap: 12px; flex-wrap: wrap; z-index: 3001; transition: transform .2s; border-bottom: 1px solid #8882; }
        .reader-toolbar.hidden { transform: translateY(-100%); }
        .reader-toolbar .controls-group { display: flex; align-items: center; gap: 5px; background: #8881; padding: 3px 6px; border-radius: 8px; }
        .reader-content-wrapper { flex: 1; overflow-y: auto; padding: 100px 24px 70px; cursor: pointer; }
        .reader-content { max-width: 720px; margin: 0 auto; line-height: 2; font-family: 'Songti SC', 'SimSun', Georgia, serif; overflow-wrap: anywhere; }
        .reader-content h2 { text-align: center; margin-bottom: 50px; font-size: 1.7em; font-weight: normal; }
        .reader-content p { margin-bottom: 1.2em; text-indent: 2em; text-align: justify; }
        #reader-overlay.theme-paper { background: #fffdf6; color: #354136; }
        #reader-overlay.theme-paper .reader-toolbar { background: #fffdf6f5; }
        #reader-overlay.theme-sepia { background: #eee6d5; color: #61513e; }
        #reader-overlay.theme-sepia .reader-toolbar { background: #eee6d5f5; }
        #reader-overlay.theme-night { background: #19231e; color: #bfccbf; }
        #reader-overlay.theme-night .reader-toolbar { background: #19231ef5; }
        #reader-overlay.theme-night .btn-text { color: #bfccbf; }
        .mobile-toggle { display: none; }
        .sidebar-scrim { display: none; }
        @media (max-width: 1100px) { .logo small { display: none; } .sidebar { width: 250px; } .novel-sidebar { width: 205px; } .editor-header { padding: 16px 22px; } .editor-body { padding: 24px; } }
        @media (max-width: 768px) {
            #app { padding: 0; } #app > header { min-height: 65px; padding: 12px 14px; border-radius: 0; border: none; border-bottom: 1px solid var(--border); gap: 8px; }
            .logo { font-size: 18px; gap: 8px; } .logo .brand-mark { display: none; } .header-divider { display: none; }
            .controls { gap: 5px; } #save-status { display: none; } #manual-save-btn { padding: 8px 12px; font-size: 11px; } #theme-select { padding: 7px 4px; font-size: 12px; max-width: 96px; } .logout-button { padding: 7px !important; font-size: 11px; }
            .main-container { border: none; border-radius: 0; } .mobile-toggle { display: inline-flex; padding: 7px !important; font-size: 12px; }
            .search-box input { font-size: 16px; } .list-toolbar select { font-size: 16px; } .table-dialog input[type="text"] { font-size: 16px; }
            .item-actions button { padding: 7px 9px; font-size: 11px; } .batch-bar button { padding: 7px 10px; font-size: 12px; }
            .sidebar { position: absolute; top: 0; bottom: 0; left: 0; width: min(84%, 310px); z-index: 25; transform: translateX(-101%); transition: transform .2s; box-shadow: var(--shadow); }
            .sidebar:not(.show), .novel-sidebar:not(.show) { visibility: hidden; }
            .sidebar.show { transform: translateX(0); } .sidebar-scrim.show { display: block; position: absolute; inset: 0; border: none; border-radius: 0; background: #14281e55; z-index: 24; }
            .novel-sidebar { position: absolute; top: 0; bottom: 0; left: 0; width: min(80%, 270px); z-index: 20; transform: translateX(-101%); transition: transform .2s; box-shadow: var(--shadow); } .novel-sidebar.show { transform: translateX(0); }
            .editor-header { flex-wrap: wrap; gap: 5px; padding: 13px 20px; } #note-title { flex: 1; font-size: 21px !important; } .editor-header .controls-right { gap: 1px; } .editor-header button { font-size: 11px; padding: 8px; }
            .editor-body { padding: 22px 23px 10px; } textarea.content-input { font-size: 16px; line-height: 2; } .writing-footer { margin: 0 22px; } .writing-footer span:last-child { font-size: 9px; }
            .note-typesetting { padding: 9px 20px; gap: 8px 12px; font-size: 10px; }
            .note-typesetting label { gap: 4px; } .note-typesetting select { padding: 6px 4px; }
            #note-body { padding: 22px 20px 12px; } #note-content { padding: 0 2px 30px; }
            .markdown-tools { margin-left: 0; width: 100%; padding-top: 5px; border-top: 1px solid var(--border); }
            #note-body.mode-split { flex-direction: column; gap: 15px; }
            #note-body.mode-split > * { width: 100%; min-height: 180px; }
            #note-body.mode-split #note-content { border-right: none; border-bottom: 1px solid var(--border); padding-bottom: 15px; }
            #empty-state { padding: 30px 24px; } .empty-inner h2 { font-size: 25px; } .empty-tip { margin-top: 30px; }
            #login-screen { padding: 22px; } .login-shell { display: block; min-height: 0; max-width: 440px; border-radius: 18px; } .login-story { padding: 24px 28px; } .login-story h1 { font-size: 28px; margin: 25px 0 0; } .login-story > p, .paper-art, .story-foot { display: none; } .story-brand { font-size: 15px; } .login-box { padding: 30px 28px; } .login-box h2 { font-size: 27px; } .login-description { margin-bottom: 24px; font-size: 12px; } .login-hint { margin-top: 22px; }
            .reader-toolbar { padding: 10px; gap: 5px; } .reader-toolbar button { font-size: 11px; padding: 6px; } .reader-content-wrapper { padding-top: 125px; }
        }
        @media (max-width: 400px) {
            #app > header { padding: 10px; } .header-brand { gap: 6px; }
            .controls { gap: 4px; } #manual-save-btn { padding: 8px 9px; } #theme-select { max-width: 88px; padding: 7px 2px; } .logout-button { padding: 7px 6px !important; }
            .sidebar { width: 88%; } .batch-bar { margin: 0 14px 10px; } .list-toolbar { margin: 0 14px 14px; } .search-box { margin: 0 14px 12px; }
        }
        @media (prefers-reduced-motion: reduce) { *, *::before, *::after { transition: none !important; scroll-behavior: auto !important; } }

    </style>
</head>
<body>

    <div id="loading-overlay" style="display:none;position:fixed;inset:0;z-index:4000;background:var(--bg-secondary);align-items:center;justify-content:center;">正在同步云端数据...</div>

    <div id="login-screen">
        <div class="login-shell">
            <section class="login-story" aria-label="note 私人写作空间">
                <div class="story-brand"><span class="brand-mark" aria-hidden="true">n</span> note <span class="eyebrow">/ 私人写作空间</span></div>
                <h1>留一页空白，<br>给此刻的灵感。</h1>
                <p>随手记下的日常，慢慢写完的故事。<br>每一个想法，都值得被好好收藏。</p>
                <div class="paper-art" aria-hidden="true"><div class="paper-sheet back"></div><div class="paper-sheet"><div class="paper-title">A little thought.</div><div class="paper-line"></div><div class="paper-line"></div><div class="paper-line short"></div><div class="paper-line"></div></div><div class="paper-seal">✳</div></div>
                <div class="story-foot">LESS NOISE. MORE WORDS.</div>
            </section>
            <div class="login-box">
                <div class="eyebrow">YOUR QUIET CORNER</div>
                <h2>欢迎回来</h2>
                <p class="login-description">让思绪慢下来，接着上次的灵感继续写。</p>
                <label for="pwd-input">访问密码</label>
                <input type="password" id="pwd-input" placeholder="输入你的密码" autocomplete="current-password">
                <button onclick="checkPwd()">进入我的空间 <span aria-hidden="true">↗</span></button>
                <p id="login-err" role="alert" style="color:var(--danger);margin-top:12px;display:none;">密码错误</p>
                <div class="login-hint">私人收藏 · 云端同步 · 随时续写</div>
            </div>
        </div>
    </div>

    <div id="reader-overlay" class="theme-paper" style="display: none;">
        <div class="reader-toolbar hidden" id="reader-toolbar">
            <div class="controls-group">
                <button class="btn-text" onclick="changeReaderFontSize(-2)" style="font-weight:bold;">A-</button>
                <span id="reader-font-size-display" style="font-size:14px; margin:0 5px;">18px</span>
                <button class="btn-text" onclick="changeReaderFontSize(2)" style="font-weight:bold; font-size:16px;">A+</button>
            </div>
            <div class="controls-group">
                <button class="btn-text" onclick="changeReaderTheme('paper')">纸张</button>
                <button class="btn-text" onclick="changeReaderTheme('sepia')">护眼</button>
                <button class="btn-text" onclick="changeReaderTheme('night')">夜间</button>
            </div>
            <button class="btn-danger" onclick="toggleReadMode()" style="margin-left:auto;">退出阅读</button>
        </div>
        <div class="reader-content-wrapper" onclick="toggleReaderToolbar()">
            <div class="reader-content" id="reader-content"></div>
        </div>
    </div>

    <div id="app">
        <header>
            <div class="header-brand">
                <button class="btn-text mobile-toggle" onclick="toggleSidebar()" aria-label="打开或关闭作品列表" aria-controls="main-sidebar" aria-expanded="false" id="sidebar-toggle">☰</button>
                <div class="logo"><span class="brand-mark" aria-hidden="true">n</span><span class="logo-text">note</span><small>留一页给灵感</small></div>
            </div>
            <div class="controls">
                <span id="save-status" role="status" aria-live="polite">云端已同步</span>
                <button id="manual-save-btn" onclick="forceManualSave()">保存</button>
                <span class="header-divider" aria-hidden="true"></span>
                <button class="btn-text" onclick="openHistoryDialog()">历史</button>
                <select id="theme-select" aria-label="切换配色主题" onchange="changeTheme(this.value)">
                    <option value="light">暖纸 · 白昼</option>
                    <option value="dark">松影 · 夜色</option>
                    <option value="passion">陶土 · 暖调</option>
                </select>
                <span class="header-divider" aria-hidden="true"></span>
                <button onclick="logout()" class="btn-text logout-button">退出</button>
            </div>
        </header>

        <div class="main-container">
            <button class="sidebar-scrim" id="sidebar-scrim" onclick="closeSidebar()" aria-label="关闭作品列表" tabindex="-1"></button>
            <aside class="sidebar" id="main-sidebar" aria-label="作品列表">
                <div class="sidebar-heading"><strong>我的作品</strong><span id="item-count">0 篇</span></div>
                <div class="tabs">
                    <button class="tab active" id="tab-note" onclick="switchTab('note')" aria-pressed="true">随手记</button>
                    <button class="tab" id="tab-novel" onclick="switchTab('novel')" aria-pressed="false">故事集</button>
                </div>
                <label class="search-box" id="search-box-wrap"><span aria-hidden="true">⌕</span><input type="search" id="list-search" aria-label="搜索作品标题和正文" placeholder="搜索标题或正文…" oninput="renderList()" onkeydown="if (event.key === 'Escape') clearSearch()"><button type="button" class="search-clear" id="search-clear" aria-label="清空搜索" onclick="event.preventDefault(); event.stopPropagation(); clearSearch()" style="display:none;">×</button></label>
                <div class="list-toolbar" id="note-tools-bar">
                    <select id="note-sort" aria-label="随手记排序方式" title="排序方式" onchange="changeNoteSort(this.value)" style="display:none;">
                        <option value="modified">按修改时间（新 → 旧）</option>
                        <option value="modified-asc">按修改时间（旧 → 新）</option>
                        <option value="created">按创建时间（新 → 旧）</option>
                        <option value="created-asc">按创建时间（旧 → 新）</option>
                        <option value="title">按标题（A → Z）</option>
                        <option value="title-desc">按标题（Z → A）</option>
                        <option value="manual">手动排序（置顶优先 · 可拖拽）</option>
                    </select>
                    <button class="toolbar-btn" id="batch-toggle-btn" onclick="toggleBatchMode()" style="display:none;">批量管理</button>
                </div>
                <div class="batch-bar" id="batch-bar" style="display:none;">
                    <div class="batch-row">
                        <span class="count" id="batch-count">已选 0 篇</span>
                        <button class="btn-text" onclick="toggleBatchMode(false)">完成</button>
                    </div>
                    <div class="batch-row">
                        <button class="btn-text" onclick="batchSelectAll()">全选</button>
                        <button class="btn-text" onclick="batchSelectNone()">清空</button>
                        <button class="btn-text" onclick="batchInvert()">反选</button>
                        <button class="btn-text" onclick="batchPin(true)">置顶</button>
                        <button class="btn-text" onclick="batchPin(false)">取消置顶</button>
                        <button class="btn-text" onclick="batchMerge()">合并</button>
                        <button class="btn-text" onclick="batchExport()">导出</button>
                        <button class="btn-text btn-danger" onclick="batchDelete()">删除</button>
                    </div>
                </div>
                <div class="list-container" id="list-container"></div>
                <div class="add-btn-container">
                    <button onclick="openCreateDialog()">＋ 写下新的灵感</button>
                </div>
            </aside>

            <div class="editor-area" id="editor-area" style="display: none;">
                
                <div class="editor-header" id="note-header" style="display: none;">
                    <input type="text" id="note-title" placeholder="记事本标题" style="width: 60%; font-weight: bold; font-size: 18px;" oninput="autoSave()">
                    <div class="controls-right">
                        <button class="btn-text" onclick="toggleReadMode()" >沉浸阅读</button>
                        <button class="btn-text" onclick="exportNote()">导出 TXT</button>
                    </div>
                </div>

                <div class="novel-layout" id="novel-layout" style="display: none;">
                    <div class="novel-sidebar" id="novel-sidebar">
                        
                        <div id="novel-menu-header" style="padding: 10px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items:center; background: var(--bg-secondary);">
                            <span id="novel-menu-title" style="font-weight:bold; font-size:13px; color: var(--text-main);">结构配置</span>
                            <button class="btn-text" onclick="toggleCrawlerPanel()" style="font-size:12px; padding:2px 6px; background: rgba(230,162,60,0.15); color: #e6a23c; border-radius:3px;">🌐 采集配置</button>
                        </div>

                        <div class="crawler-box" id="crawler-box">
                            <strong>导入故事</strong>
                            <input type="text" id="crawl-url" placeholder="请输入目标网页网址(URL)">
                            <input type="text" id="crawl-blacklist" placeholder="自定义屏蔽词(逗号隔开)">
                            
                            <div class="crawler-row" onchange="handleCrawlTypeChange()">
                                <label><input type="radio" name="crawl-type" value="short" checked> 短篇(单页)</label>
                                <label><input type="radio" name="crawl-type" value="long"> 长篇(目录)</label>
                            </div>
                            
                            <textarea id="crawler-source" class="crawler-source-input" placeholder="【防爬备用】若单页/目录遇到防爬盾，请在此处直接粘贴HTML网页源代码（留空则走网络抓取）"></textarea>
                            
                            <button id="crawl-execute-btn" onclick="startCrawlNovel()" style="background:#e6a23c; width:100%;">开始清洗并导入</button>
                            <div class="progress-bar-container" id="crawl-progress-box">
                                <div class="progress-bar-inner" id="crawl-progress-bar"></div>
                            </div>
                            <span id="crawl-msg" style="font-size:11px; color:var(--text-muted);">从网页采集正文，或粘贴 HTML 导入。</span>
                        </div>

                        <div id="short-novel-msg" style="display:none; padding:15px; color:var(--text-muted); font-size:13px; text-align:center; line-height: 1.5;">
                            一篇故事，一气呵成。<br>在右侧开始写下你的短篇。
                        </div>

                        <div id="novel-toc-header" style="padding: 8px 10px; border-bottom: 1px solid var(--border); display: none; justify-content: space-between; align-items:center;">
                            <span style="font-size:13px; color:var(--text-muted);">目录树列表</span>
                            <button class="btn-text" onclick="addVolume()">+ 新建卷</button>
                        </div>
                        <div id="novel-toc" style="flex:1; overflow-y:auto;"></div>
                    </div>
                    
                    <div class="novel-main">
                        <div class="editor-header">
                            <div class="controls-left">
                                <button class="btn-text mobile-toggle" style="display:inline-block;" onclick="toggleNovelSidebar()">☰ 目录 / 导入</button>
                                <span id="novel-current-path" style="font-weight: bold; margin-left: 10px; color: var(--text-muted);">请选择章节</span>
                            </div>
                            <div class="controls-right">
                                <button class="btn-text" onclick="toggleReadMode()" >沉浸阅读</button>
                                <button class="btn-text" onclick="exportNovel()">导出 TXT</button>
                            </div>
                        </div>
                        <div class="editor-body">
                            <input type="text" id="chapter-title" placeholder="章节标题" style="font-weight: bold; font-size: 18px; display:none;" oninput="autoSave()">
                            <textarea class="content-input" id="main-content" placeholder="开始你的创作..." oninput="autoSave()"></textarea>
                        </div>
                    </div>
                </div>

                <div class="note-typesetting" id="note-typesetting" style="display:none;" aria-label="正文显示设置">
                    <label>字号<select id="note-font-size" onchange="setNoteTypography()"><option value="16">16</option><option value="17" selected>17</option><option value="18">18</option><option value="20">20</option><option value="22">22</option></select></label>
                    <label>行距<select id="note-line-height" onchange="setNoteTypography()"><option value="1.6">紧凑</option><option value="1.85" selected>舒适</option><option value="2.2">宽松</option></select></label>
                    <label>版型<select id="note-width" onchange="setNoteTypography()"><option value="640px">窄版</option><option value="800px">标准</option><option value="100%" selected>宽版</option></select></label>
                    <div class="markdown-tools" aria-label="Markdown 工具栏">
                        <button class="btn-text" id="md-edit" onclick="setNoteMode('edit')" aria-pressed="false">编辑</button>
                        <button class="btn-text" id="md-split" onclick="setNoteMode('split')" aria-pressed="true">对照</button>
                        <button class="btn-text" id="md-preview" onclick="setNoteMode('preview')" aria-pressed="false">预览</button>
                        <button class="btn-text" onclick="openTableDialog()">＋ 表格</button>
                        <button class="btn-text" onclick="exportNoteMarkdown()">导出 .md</button>
                    </div>
                </div>
                <div class="editor-body" id="note-body" style="display: none;">
                    <textarea class="content-input" id="note-content" aria-label="记事本正文（支持 Markdown）" placeholder="支持 Markdown：# 标题、**加粗**、- 列表，也可以插入表格…" wrap="soft" oninput="autoSave(); scheduleNotePreview()"></textarea>
                    <div id="note-preview" class="markdown-content" role="region" aria-label="Markdown 预览" tabindex="0"></div>
                </div>
                <div class="writing-footer"><span id="word-count" aria-live="polite">0 字</span><span>自动保存已开启 · 慢慢写，不着急</span></div>
            </div>
            
            <div id="empty-state">
                <div class="empty-inner">
                    <div class="empty-illustration" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M5 19l1-5L17 3l4 4L10 18zM14 6l4 4M4 21h16"/></svg><i></i><i></i></div>
                    <div class="eyebrow">A SPACE FOR YOUR THOUGHTS</div>
                    <h2>每一页，都是新的开始</h2>
                    <p>打开一篇旧作，或写下一个新念头。<br>生活的片刻、未完的故事，都可以从这里开始。</p>
                    <button onclick="openCreateDialog()">＋ 开始创作</button>
                    <div class="empty-tip">安心写作，内容会在停笔后自动保存</div>
                </div>
            </div>
        </div>
    </div>

    <dialog id="create-dialog" class="table-dialog" aria-labelledby="create-dialog-title">
        <h3 id="create-dialog-title">新建记事本</h3>
        <form method="dialog" onsubmit="return handleCreateSubmit(event)">
            <div id="create-type-row" style="display:none; flex-direction: column; gap: 10px; margin-top: 14px;">
                <label class="create-type-option"><input type="radio" name="new-novel-type" value="long" checked>长篇连载（分卷分章）</label>
                <label class="create-type-option"><input type="radio" name="new-novel-type" value="short">短篇小说（单篇正文）</label>
            </div>
            <input type="text" id="create-title-input" placeholder="标题" maxlength="100" style="width: 100%;" oninput="onCreateTitleInput()">
            <div class="dialog-actions">
                <button type="button" class="btn-text" onclick="closeCreateDialog()">取消</button>
                <button type="submit" id="create-confirm-btn" disabled>创建</button>
            </div>
        </form>
    </dialog>
    <dialog id="rename-dialog" class="table-dialog" aria-labelledby="rename-dialog-title">
        <h3 id="rename-dialog-title">重命名</h3>
        <form method="dialog" onsubmit="return handleRenameSubmit(event)">
            <input type="text" id="rename-input" placeholder="新标题" maxlength="100" style="width: 100%;">
            <div class="dialog-actions">
                <button type="button" class="btn-text" onclick="document.getElementById('rename-dialog').close()">取消</button>
                <button type="submit" id="rename-confirm-btn">确定</button>
            </div>
        </form>
    </dialog>
    <dialog id="confirm-dialog" class="table-dialog confirm-dialog" aria-labelledby="confirm-dialog-title">
        <h3 id="confirm-dialog-title">确认操作</h3>
        <p id="confirm-dialog-message"></p>
        <form method="dialog" class="dialog-actions">
            <button type="button" class="btn-text" onclick="document.getElementById('confirm-dialog').close('cancel')">取消</button>
            <button type="submit" id="confirm-dialog-ok" value="ok">确定</button>
        </form>
    </dialog>
    <dialog id="table-dialog" class="table-dialog" aria-labelledby="table-dialog-title">
        <form onsubmit="insertNoteTable(event)">
            <h3 id="table-dialog-title">插入表格</h3><p>插入后在编辑区填写内容，切换预览查看表格。</p>
            <label>列数<input id="table-columns" type="number" min="1" max="12" value="3" required></label>
            <label>数据行数<input id="table-rows" type="number" min="1" max="50" value="3" required></label>
            <div class="dialog-actions"><button type="button" class="btn-text" onclick="document.getElementById('table-dialog').close()">取消</button><button type="submit">插入表格</button></div>
        </form>
    </dialog>
    <dialog id="history-dialog" class="table-dialog history-dialog" aria-labelledby="history-dialog-title">
        <h3 id="history-dialog-title">本文修改历史</h3>
        <p>按当前打开的文章独立展示：只列出这篇文章实际发生变化的版本（底层快照自动保存约 10 分钟合并一份，最多 10 份）。回滚仅影响这一篇文章，当前内容会先自动留存，可再次回滚撤销。</p>
        <div id="history-list" class="history-list" aria-live="polite"></div>
        <div class="dialog-actions"><button type="button" onclick="document.getElementById('history-dialog').close()">关闭</button></div>
    </dialog>
    <script>
        ${markdownVendor}
        let appData = { novels: [], notes: [] };
        let currentTab = 'note'; 
        let activeNovelId = null, activeVolumeId = null, activeChapterId = null, activeNoteId = null;
        let saveTimeout = null; 
        let dataLoaded = false;
        let loginBusy = false;
        let readerFontSize = 18;
        let noteMode = 'split';
        let notePreviewTimer = null;
        let tableSelection = { start: 0, end: 0 };

        function refreshNotePreview() {
            clearTimeout(notePreviewTimer);
            window.renderNoteMarkdown(document.getElementById('note-content').value, document.getElementById('note-preview'));
        }
        function scheduleNotePreview() {
            clearTimeout(notePreviewTimer);
            if (noteMode !== 'edit') notePreviewTimer = setTimeout(refreshNotePreview, 180);
        }
        function setNoteMode(mode) {
            if (!['edit', 'split', 'preview'].includes(mode)) return;
            noteMode = mode;
            const body = document.getElementById('note-body');
            body.classList.toggle('mode-split', mode === 'split');
            body.classList.toggle('mode-preview', mode === 'preview');
            for (const name of ['edit', 'split', 'preview']) document.getElementById('md-' + name).setAttribute('aria-pressed', name === mode);
            if (mode !== 'edit') refreshNotePreview();
        }
        function openTableDialog() {
            const input = document.getElementById('note-content');
            tableSelection = { start: input.selectionStart, end: input.selectionEnd };
            document.getElementById('table-dialog').showModal();
        }
        function insertNoteTable(event) {
            event.preventDefault();
            const columns = Number(document.getElementById('table-columns').value);
            const rows = Number(document.getElementById('table-rows').value);
            if (!Number.isInteger(columns) || !Number.isInteger(rows) || columns < 1 || columns > 12 || rows < 1 || rows > 50) return;
            const row = cells => '| ' + cells.join(' | ') + ' |';
            const lines = [row(Array.from({ length: columns }, (_, i) => '列 ' + (i + 1))), row(Array(columns).fill('---'))];
            for (let i = 0; i < rows; i++) lines.push(row(Array(columns).fill('内容')));
            const input = document.getElementById('note-content');
            input.setRangeText('\\n\\n' + lines.join('\\n') + '\\n\\n', tableSelection.start, tableSelection.end, 'end');
            document.getElementById('table-dialog').close();
            setNoteMode('split');
            input.focus();
            autoSave();
        }
        function exportNoteMarkdown() {
            const note = appData.notes.find(n => n.id === activeNoteId);
            if (!note) return;
            syncCurrentFields();
            const blob = new Blob([note.content], { type: 'text/markdown;charset=utf-8' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            link.href = url; link.download = (note.title || '未命名') + '.md';
            document.body.appendChild(link); link.click(); link.remove();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
        }
        let historyNoteId = null;
        async function openHistoryDialog() {
            const list = document.getElementById('history-list');
            const dialog = document.getElementById('history-dialog');
            historyNoteId = activeNoteId;
            const note = appData.notes.find(n => n.id === historyNoteId);
            if (!note) { showToast('请先打开一篇文章再查看历史', 'error'); return; }
            list.innerHTML = '<div class="history-item">正在加载历史版本…</div>';
            dialog.showModal();
            try {
                const res = await apiFetch('/api/history');
                if (!res.ok) throw new Error('加载失败');
                const items = (await res.json()).items || [];
                if (!items.length) { list.innerHTML = '<div class="history-item">暂无历史版本。内容发生变化并保存后会自动留存快照。</div>'; return; }
                const versions = (await Promise.all(items.map(async item => {
                    const r = await apiFetch('/api/history-item?ts=' + encodeURIComponent(item.ts));
                    if (!r.ok) return null;
                    const snap = await r.json();
                    const snapNote = (Array.isArray(snap.notes) ? snap.notes : []).find(n => n.id === historyNoteId);
                    return snapNote ? { ts: item.ts, title: snapNote.title || '未命名', content: snapNote.content || '' } : null;
                }))).filter(Boolean);
                const filtered = [];
                versions.forEach(v => {
                    const prev = filtered[filtered.length - 1];
                    if (prev && prev.title === v.title && prev.content === v.content) return;
                    filtered.push(v);
                });
                list.innerHTML = '';
                if (!filtered.length) { list.innerHTML = '<div class="history-item">现存快照里没有这篇文章的版本（快照留存时它可能还不存在）。</div>'; return; }
                filtered.forEach(v => {
                    const row = document.createElement('div'); row.className = 'history-item';
                    const meta = document.createElement('div'); meta.className = 'history-meta';
                    const time = document.createElement('strong');
                    time.textContent = new Date(v.ts).toLocaleString('zh-CN', { hour12: false });
                    const preview = document.createElement('span'); preview.className = 'history-size';
                    preview.textContent = v.title + ' · ' + v.content.replace(/\\s+/g, '').length.toLocaleString() + ' 字';
                    const rollback = document.createElement('button'); rollback.className = 'btn-text'; rollback.textContent = '回滚此篇';
                    rollback.onclick = () => rollbackNoteVersion(v);
                    meta.append(time, preview); row.append(meta, rollback); list.appendChild(row);
                });
            } catch { list.innerHTML = '<div class="history-item">历史版本加载失败，请关闭后重试。</div>'; }
        }
        async function rollbackNoteVersion(version) {
            if (!await showConfirm('将把这篇文章的标题和正文回滚到所选版本；当前内容会先自动留存，可在「历史」中撤销。', { title: '回滚确认', okText: '回滚' })) return;
            const note = appData.notes.find(n => n.id === historyNoteId);
            if (!note) { showToast('文章不存在或已删除', 'error'); document.getElementById('history-dialog').close(); return; }
            note.title = version.title;
            note.content = version.content;
            note.updatedAt = Date.now();
            if (activeNoteId === historyNoteId) {
                document.getElementById('note-title').value = note.title;
                document.getElementById('note-content').value = note.content;
                scheduleNotePreview();
                updateWordCount();
            }
            renderList();
            document.getElementById('history-dialog').close();
            if (await immediateSave()) showToast('已回滚此篇。如需撤销，请再次打开「历史」选择最近的版本。');
            else showToast('本地已回滚，但同步云端失败，请检查网络后手动保存', 'error');
        }

        const genId = () => Date.now().toString(36) + Math.random().toString(36).substr(2);
        function showToast(message, type) {
            let box = document.getElementById('toast-box');
            if (!box) { box = document.createElement('div'); box.id = 'toast-box'; document.body.appendChild(box); }
            const toast = document.createElement('div');
            toast.className = 'toast' + (type === 'error' ? ' toast-error' : '');
            toast.textContent = message;
            box.appendChild(toast);
            setTimeout(() => { toast.classList.add('toast-out'); setTimeout(() => toast.remove(), 350); }, 2800);
        }
        function showConfirm(message, options) {
            const opts = options || {};
            return new Promise(resolve => {
                const dialog = document.getElementById('confirm-dialog');
                document.getElementById('confirm-dialog-title').textContent = opts.title || '确认操作';
                document.getElementById('confirm-dialog-message').textContent = message;
                const ok = document.getElementById('confirm-dialog-ok');
                ok.textContent = opts.okText || '确定';
                ok.classList.toggle('btn-danger-solid', !!opts.danger);
                let settled = false;
                dialog.onclose = () => {
                    if (settled) return;
                    settled = true;
                    resolve(dialog.returnValue === 'ok');
                };
                dialog.returnValue = '';
                dialog.showModal();
            });
        }

        function escapeHtml(value) {
            return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));
        }
        function privateApiUrl(path) {
            return window.location.pathname.replace(/\\/$/, '') + path;
        }
        async function apiFetch(url, options = {}) {
            const res = await fetch(privateApiUrl(url), { ...options, credentials: 'same-origin', headers: {
                ...options.headers, 'X-Requested-With': 'note-editor'
            }});
            if (res.status === 401) {
                document.getElementById('login-screen').style.display = 'flex';
                document.getElementById('app').style.display = 'none';
                document.getElementById('reader-overlay').style.display = 'none';
                clearTimeout(saveTimeout);
                const err = document.getElementById('login-err');
                err.textContent = '登录已失效，请重新登录';
                err.style.display = 'block';
            }
            return res;
        }
        window.onload = async () => {
            restoreNoteTypography();
            localStorage.removeItem('cloud_editor_auth');
            const theme = localStorage.getItem('cloud_editor_theme') || 'dark';
            document.getElementById('theme-select').value = theme;
            changeTheme(theme);
            setNoteMode(noteMode);
            document.getElementById('pwd-input').addEventListener('keydown', e => {
                if (e.key === 'Enter') checkPwd();
            });
            try {
                const res = await fetch(privateApiUrl('/api/session'), { credentials: 'same-origin' });
                if (res.ok) await showApp();
            } catch { /* 登录页面仍可使用 */ }
        };
        async function checkPwd() {
            if (loginBusy) return;
            const input = document.getElementById('pwd-input');
            const err = document.getElementById('login-err');
            const button = document.querySelector('.login-box button');
            loginBusy = true; button.disabled = true; err.style.display = 'none';
            try {
                const res = await apiFetch('/api/login', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: input.value })
                });
                const result = await res.json();
                if (!res.ok) throw new Error(result.error || '登录失败');
                input.value = '';
                await showApp();
            } catch (e) {
                err.textContent = e.message || '网络错误，请重试'; err.style.display = 'block';
            } finally { loginBusy = false; button.disabled = false; }
        }
        async function showApp() {
            if (!dataLoaded) {
                if (!await loadDataFromServer()) throw new Error('加载云端数据失败，请重试登录');
                dataLoaded = true;
                if (migrateNoteTimes()) saveDataToServer();
                document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
                document.getElementById('tab-note').classList.add('active');
                currentTab = 'note';
                renderList();
            }
            document.getElementById('login-screen').style.display = 'none';
            document.getElementById('app').style.display = 'flex';
        }
        async function logout() {
            if (!await showConfirm('当前内容会先保存到云端，退出后需重新登录。', { title: '退出登录', okText: '保存并退出' })) return;
            syncCurrentFields(); clearTimeout(saveTimeout);
            if (dataLoaded && !await saveDataToServer()) { showToast('保存失败，请重试后退出', 'error'); return; }
            try {
                const res = await apiFetch('/api/logout', { method: 'POST' });
                if (!res.ok) throw new Error('退出失败');
                window.location.reload();
            } catch { showToast('退出失败，请检查网络后重试', 'error'); }
        }

        const noteTypographyOptions = {
            'note-font-size': ['16', '17', '18', '20', '22'],
            'note-line-height': ['1.6', '1.85', '2.2'],
            'note-width': ['640px', '800px', '100%']
        };
        function setNoteTypography(persist = true) {
            const preferences = {};
            for (const [id, choices] of Object.entries(noteTypographyOptions)) {
                const value = document.getElementById(id).value;
                if (!choices.includes(value)) continue;
                preferences[id] = value;
                document.documentElement.style.setProperty('--' + id, id === 'note-font-size' ? value + 'px' : value);
            }
            if (persist) { try { localStorage.setItem('note_typography', JSON.stringify(preferences)); } catch {} }
        }
        function restoreNoteTypography() {
            try {
                const preferences = JSON.parse(localStorage.getItem('note_typography') || '{}');
                for (const [id, choices] of Object.entries(noteTypographyOptions)) {
                    if (choices.includes(preferences?.[id])) document.getElementById(id).value = preferences[id];
                }
            } catch {}
            setNoteTypography(false);
        }
        function changeTheme(theme) {
            document.body.className = theme;
            localStorage.setItem('cloud_editor_theme', theme);
        }

        async function loadDataFromServer() {
            document.getElementById('loading-overlay').style.display = 'flex';
            try {
                const res = await apiFetch('/api/get-data');
                if (res.ok) {
                    const loaded = await res.json();
                    if (!Array.isArray(loaded.notes) || !Array.isArray(loaded.novels)) throw new Error('云端数据结构错误');
                    appData = loaded;
                    if(!appData.novels) appData.novels = [];
                    if(!appData.notes) appData.notes = [];
                    return true;
                } else {
                    showToast('拉取云端数据失败，请检查密码或KV绑定', 'error');
                }
            } catch (e) {
                console.error(e);
                showToast('网络错误，无法连接到云端', 'error');
            } finally {
                document.getElementById('loading-overlay').style.display = 'none';
            }
            return false;
        }

        async function saveDataToServer(historyQuery = '') {
            if (!dataLoaded) return false;
            document.getElementById('save-status').innerText = '⏳ 正在同步到云端...';
            try {
                const res = await apiFetch('/api/save-data' + historyQuery, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(appData)
                });
                if (res.ok) {
                    document.getElementById('save-status').innerText = '☁️ 云端已同步';
                    return true;
                } else {
                    document.getElementById('save-status').innerText = '❌ 同步失败';
                    return false;
                }
            } catch (e) {
                document.getElementById('save-status').innerText = '❌ 网络故障，未同步';
                return false;
            }
        }

        async function forceManualSave() {
            syncCurrentFields();
            clearTimeout(saveTimeout);
            const success = await saveDataToServer('?history=force');
            if (success) {
                showToast('💾 云端数据保存成功！');
            } else {
                showToast('❌ 保存失败，请检查网络连接。', 'error');
            }
        }

        function syncCurrentFields() {
            if (currentTab === 'novel') {
                if (activeNovelId) {
                    const novel = appData.novels.find(n => n.id === activeNovelId);
                    if (novel) {
                        if (novel.type === 'short') {
                            novel.title = document.getElementById('chapter-title').value;
                            novel.content = document.getElementById('main-content').value;
                        } else if (activeVolumeId && activeChapterId) {
                            const vol = novel.volumes.find(v => v.id === activeVolumeId);
                            const chap = vol.chapters.find(c => c.id === activeChapterId);
                            if(chap) {
                                chap.title = document.getElementById('chapter-title').value;
                                chap.content = document.getElementById('main-content').value;
                            }
                        }
                    }
                }
            } else {
                if (activeNoteId) {
                    const note = appData.notes.find(n => n.id === activeNoteId);
                    if(note) {
                        note.title = document.getElementById('note-title').value;
                        note.content = document.getElementById('note-content').value;
                    }
                }
            }
        }

        function autoSave() {
            syncCurrentFields();
            touchActiveNote();
            updateWordCount();
            document.getElementById('save-status').innerText = '✍️ 正在输入...';
            clearTimeout(saveTimeout);
            saveTimeout = setTimeout(() => {
                saveDataToServer();
                if (currentTab === 'novel') {
                    const novel = appData.novels.find(n => n.id === activeNovelId);
                    if (novel && novel.type === 'short') renderList(); else renderNovelToc();
                } else {
                    renderList();
                }
            }, 2000); 
        }

        async function immediateSave() {
            clearTimeout(saveTimeout);
            await saveDataToServer();
        }

        function switchTab(tab) {
            document.getElementById('list-search').value = '';
            if (batchMode) toggleBatchMode(false);
            currentTab = tab;
            document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
            if(tab === 'novel') {
                document.getElementById('tab-novel').classList.add('active');
            } else {
                document.getElementById('tab-note').classList.add('active');
            }
            document.getElementById('editor-area').style.display = 'none';
            document.getElementById('empty-state').style.display = 'flex';
            closeSidebar();
            renderList();
        }

        // ================= 随手记：时间戳 / 置顶 / 排序 / 批量管理 =================
        let batchMode = false;
        let dragNoteId = null;
        const batchSelected = new Set();
        const NOTE_SORTERS = {
            'modified': (a, b) => (b.updatedAt || 0) - (a.updatedAt || 0),
            'modified-asc': (a, b) => (a.updatedAt || 0) - (b.updatedAt || 0),
            'created': (a, b) => (b.createdAt || 0) - (a.createdAt || 0),
            'created-asc': (a, b) => (a.createdAt || 0) - (b.createdAt || 0),
            'title': (a, b) => String(a.title || '').localeCompare(String(b.title || ''), 'zh-Hans-CN'),
            'title-desc': (a, b) => String(b.title || '').localeCompare(String(a.title || ''), 'zh-Hans-CN'),
            'manual': () => 0
        };
        let noteSort = localStorage.getItem('cloud_note_sort');
        if (!NOTE_SORTERS[noteSort]) noteSort = 'modified';
        function migrateNoteTimes() {
            let changed = false;
            const now = Date.now();
            (appData.notes || []).forEach(n => {
                if (!Number(n.createdAt)) { n.createdAt = now; changed = true; }
                if (!Number(n.updatedAt)) { n.updatedAt = Number(n.createdAt); changed = true; }
            });
            return changed;
        }
        function touchActiveNote() {
            if (currentTab !== 'note' || !activeNoteId) return;
            const note = appData.notes.find(n => n.id === activeNoteId);
            if (note) note.updatedAt = Date.now();
        }
        function formatStamp(ms) {
            if (!ms) return '—';
            const d = new Date(ms), now = new Date();
            const pad = v => String(v).padStart(2, '0');
            return (d.getFullYear() === now.getFullYear() ? '' : d.getFullYear() + '-') + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
        }
        function highlightMatch(escaped, query) {
            if (!query) return escaped;
            const pattern = escapeHtml(query).replace(/[.*+?^$\\{\\}()\\[\\]\\\\]/g, '\\$&');
            try { return escaped.replace(new RegExp(pattern, 'gi'), m => '<mark>' + m + '</mark>'); } catch { return escaped; }
        }
        function clearSearch() {
            const input = document.getElementById('list-search');
            if (!input.value) return;
            input.value = '';
            renderList();
            input.focus();
        }
        document.addEventListener('keydown', e => {
            if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K') && document.getElementById('login-screen').style.display === 'none' && document.getElementById('search-box-wrap').style.display !== 'none') {
                e.preventDefault();
                const input = document.getElementById('list-search');
                input.focus();
                input.select();
            }
        });
        function changeNoteSort(value) {
            noteSort = NOTE_SORTERS[value] ? value : 'modified';
            localStorage.setItem('cloud_note_sort', noteSort);
            document.getElementById('note-sort').value = noteSort;
            renderList();
        }
        function toggleBatchMode(force) {
            batchMode = force === undefined ? !batchMode : force;
            if (!batchMode) batchSelected.clear();
            document.getElementById('batch-bar').style.display = batchMode ? 'flex' : 'none';
            updateBatchCount();
            renderList();
        }
        function updateBatchCount() {
            const el = document.getElementById('batch-count');
            if (el) el.textContent = '已选 ' + batchSelected.size + ' / 共 ' + appData.notes.length + ' 篇';
        }
        function toggleBatchItem(id, checked) {
            if (checked) batchSelected.add(id); else batchSelected.delete(id);
            updateBatchCount();
        }
        function batchSelectAll() {
            const query = document.getElementById('list-search').value.trim().toLocaleLowerCase();
            appData.notes.forEach(n => { if (!query || (n.title + ' ' + itemText(n)).toLocaleLowerCase().includes(query)) batchSelected.add(n.id); });
            updateBatchCount();
            renderList();
        }
        async function batchPin(pinned) {
            if (!batchSelected.size) return;
            applyPinState([...batchSelected], pinned);
            renderList();
            await immediateSave();
        }
        async function batchDelete() {
            if (!batchSelected.size) return;
            if (!await showConfirm('选中的 ' + batchSelected.size + ' 篇删除后将无法恢复。', { title: '批量删除', okText: '删除 ' + batchSelected.size + ' 篇', danger: true })) return;
            const doomed = new Set(batchSelected);
            appData.notes = appData.notes.filter(n => !doomed.has(n.id));
            if (activeNoteId && doomed.has(activeNoteId) && !appData.notes.some(n => n.id === activeNoteId)) {
                activeNoteId = null;
                document.getElementById('editor-area').style.display = 'none';
                document.getElementById('empty-state').style.display = 'flex';
            }
            batchSelected.clear();
            updateBatchCount();
            renderList();
            await immediateSave();
        }
        function orderedSelectedNotes() {
            const sorter = NOTE_SORTERS[noteSort];
            return [...appData.notes].sort((a, b) => (!!b.pinned - !!a.pinned) || sorter(a, b)).filter(n => batchSelected.has(n.id));
        }
        function batchSelectNone() {
            batchSelected.clear();
            updateBatchCount();
            renderList();
        }
        function batchInvert() {
            const query = document.getElementById('list-search').value.trim().toLocaleLowerCase();
            appData.notes.forEach(n => {
                const hit = !query || (n.title + ' ' + itemText(n)).toLocaleLowerCase().includes(query);
                if (!hit) return;
                if (batchSelected.has(n.id)) batchSelected.delete(n.id); else batchSelected.add(n.id);
            });
            updateBatchCount();
            renderList();
        }
        async function batchMerge() {
            const picked = orderedSelectedNotes();
            if (picked.length < 2) { showToast('请至少选中两篇再合并', 'error'); return; }
            if (!await showConfirm('将选中的 ' + picked.length + ' 篇按当前列表顺序合并为一篇新笔记，原笔记保留。', { title: '批量合并', okText: '合并' })) return;
            const now = Date.now();
            const merged = {
                id: genId(),
                title: '合并笔记 ' + new Date(now).toLocaleDateString('zh-CN'),
                content: picked.map(n => '# ' + (n.title || '未命名') + '\\n\\n' + (n.content || '')).join('\\n\\n---\\n\\n'),
                createdAt: now,
                updatedAt: now
            };
            appData.notes.unshift(merged);
            toggleBatchMode(false);
            openItem(merged.id);
            await immediateSave();
        }
        function batchExport() {
            const picked = orderedSelectedNotes();
            if (!picked.length) { showToast('请先勾选要导出的文章', 'error'); return; }
            const md = picked.map(n => '# ' + (n.title || '未命名') + '\\n\\n' + (n.content || '')).join('\\n\\n---\\n\\n');
            const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            link.href = url;
            link.download = '随手记导出-' + new Date().toISOString().slice(0, 10) + '.md';
            document.body.appendChild(link); link.click(); link.remove();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
        }
        function applyPinState(ids, pinned) {
            const moved = appData.notes.filter(n => ids.includes(n.id));
            moved.forEach(n => { if (pinned) n.pinned = true; else delete n.pinned; });
            const rest = appData.notes.filter(n => !ids.includes(n.id));
            appData.notes = pinned
                ? [...moved, ...rest.filter(n => n.pinned), ...rest.filter(n => !n.pinned)]
                : [...rest.filter(n => n.pinned), ...moved, ...rest.filter(n => !n.pinned)];
        }
        async function toggleNotePin(id) {
            const note = appData.notes.find(n => n.id === id);
            if (!note) return;
            applyPinState([id], !note.pinned);
            renderList();
            await immediateSave();
        }
        function reorderNote(dragId, dropId) {
            const arr = appData.notes;
            const from = arr.findIndex(n => n.id === dragId), to = arr.findIndex(n => n.id === dropId);
            if (from < 0 || to < 0 || from === to) return;
            const [moved] = arr.splice(from, 1);
            arr.splice(to, 0, moved);
        }
        function moveNote(id, dir) {
            const arr = appData.notes;
            const idx = arr.findIndex(n => n.id === id);
            if (idx < 0) return;
            let j = idx + dir;
            while (j >= 0 && j < arr.length && !!arr[j].pinned !== !!arr[idx].pinned) j += dir;
            if (j < 0 || j >= arr.length) return;
            [arr[idx], arr[j]] = [arr[j], arr[idx]];
            renderList();
            autoSave();
        }
        function renderList() {
            const container = document.getElementById('list-container');
            container.innerHTML = '';
            const isNote = currentTab === 'note';
            const list = isNote ? appData.notes : appData.novels;
            const query = document.getElementById('list-search').value.trim().toLocaleLowerCase();
            let visible = list.filter(item => !query || (item.title + ' ' + itemText(item)).toLocaleLowerCase().includes(query));
            const batching = batchMode && isNote;
            if (isNote) visible.sort((a, b) => (!!b.pinned - !!a.pinned) || NOTE_SORTERS[noteSort](a, b));
            document.getElementById('search-clear').style.display = document.getElementById('list-search').value ? '' : 'none';
            document.getElementById('item-count').textContent = query ? '匹配 ' + visible.length + ' / ' + list.length + ' 篇' : list.length + ' 篇';
            document.getElementById('tab-note').setAttribute('aria-pressed', isNote);
            document.getElementById('tab-novel').setAttribute('aria-pressed', currentTab === 'novel');
            document.getElementById('batch-toggle-btn').style.display = isNote && !batchMode ? '' : 'none';
            document.getElementById('note-tools-bar').style.display = isNote ? '' : 'none';
            const sortSelect = document.getElementById('note-sort');
            sortSelect.style.display = isNote ? '' : 'none';
            if (sortSelect.value !== noteSort) sortSelect.value = noteSort;
            if (!visible.length) {
                const empty = document.createElement('p'); empty.className = 'list-empty';
                empty.textContent = query ? '没有找到匹配的作品，换个关键词试试。' : '这里还很安静，写下第一篇吧。';
                container.appendChild(empty);
            }
            visible.forEach(item => {
                const div = document.createElement('div');
                div.className = 'list-item' + ((isNote ? activeNoteId : activeNovelId) === item.id ? ' active' : '') + (batchSelected.has(item.id) ? ' selected' : '');
                div.tabIndex = 0;
                div.setAttribute('aria-label', (batching ? '选择：' : '打开：') + (item.title || '未命名') + (item.pinned ? '（置顶）' : ''));
                const activate = () => batching ? toggleBatchItem(item.id, !batchSelected.has(item.id)) : openItem(item.id);
                div.onkeydown = e => { if (e.target === div && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); div.click(); } };
                const infoDiv = document.createElement('div');
                infoDiv.className = 'item-info';
                if (batching) {
                    const check = document.createElement('input');
                    check.type = 'checkbox'; check.className = 'item-check';
                    check.checked = batchSelected.has(item.id);
                    check.setAttribute('aria-label', '选中：' + (item.title || '未命名'));
                    check.onclick = e => e.stopPropagation();
                    check.onchange = () => toggleBatchItem(item.id, check.checked);
                    infoDiv.appendChild(check);
                }
                const tagStr = (currentTab === 'novel' && item.type === 'short') ? ' <span style="font-size:11px; background:rgba(64,158,255,0.15); color:var(--accent); padding:1px 4px; border-radius:3px;">短篇</span>' : '';
                infoDiv.innerHTML = '<span class="item-title">' + highlightMatch(escapeHtml(item.title || '未命名'), query) + tagStr + '</span>' + (isNote && item.pinned ? '<span class="pin-badge">置顶</span>' : '');
                if (isNote && !batching && noteSort === 'manual') {
                    const handle = document.createElement('span');
                    handle.className = 'drag-handle'; handle.textContent = '⠿'; handle.title = '拖动排序';
                    handle.setAttribute('aria-hidden', 'true');
                    handle.ondragstart = e => { dragNoteId = item.id; e.dataTransfer.effectAllowed = 'move'; try { e.dataTransfer.setData('text/plain', item.id); } catch {} };
                    handle.ondragend = () => { dragNoteId = null; container.querySelectorAll('.drag-over,.dragging').forEach(el => el.classList.remove('drag-over', 'dragging')); };
                    infoDiv.appendChild(handle);
                    div.ondragover = e => {
                        const src = appData.notes.find(n => n.id === dragNoteId);
                        if (!src || dragNoteId === item.id || !!src.pinned !== !!item.pinned) return;
                        e.preventDefault();
                        e.dataTransfer.dropEffect = 'move';
                        div.classList.add('drag-over');
                    };
                    div.ondragleave = () => div.classList.remove('drag-over');
                    div.ondrop = e => {
                        e.preventDefault();
                        div.classList.remove('drag-over');
                        if (dragNoteId && dragNoteId !== item.id) { reorderNote(dragNoteId, item.id); renderList(); autoSave(); }
                    };
                }
                const actionsDiv = document.createElement('div');
                actionsDiv.className = 'item-actions';
                if (batching && noteSort === 'manual') {
                    const up = document.createElement('button');
                    up.className = 'btn-text'; up.innerText = '↑'; up.title = '上移'; up.setAttribute('aria-label', '上移：' + (item.title || '未命名'));
                    up.onclick = e => { e.stopPropagation(); moveNote(item.id, -1); };
                    const down = document.createElement('button');
                    down.className = 'btn-text'; down.innerText = '↓'; down.title = '下移'; down.setAttribute('aria-label', '下移：' + (item.title || '未命名'));
                    down.onclick = e => { e.stopPropagation(); moveNote(item.id, 1); };
                    actionsDiv.appendChild(up);
                    actionsDiv.appendChild(down);
                } else if (isNote && !batching) {
                    const pinBtn = document.createElement('button');
                    pinBtn.className = 'btn-text';
                    pinBtn.innerText = item.pinned ? '取消置顶' : '置顶';
                    pinBtn.onclick = e => { e.stopPropagation(); toggleNotePin(item.id); };
                    actionsDiv.appendChild(pinBtn);
                }
                const renameBtn = document.createElement('button');
                renameBtn.className = 'btn-text';
                renameBtn.innerText = '改名';
                renameBtn.onclick = e => renameItem(item.id, e);
                const deleteBtn = document.createElement('button');
                deleteBtn.className = 'btn-text btn-danger';
                deleteBtn.style.padding = '2px 6px';
                deleteBtn.innerText = '删除';
                deleteBtn.onclick = e => deleteItem(item.id, e);
                actionsDiv.appendChild(renameBtn);
                actionsDiv.appendChild(deleteBtn);
                if (isNote) {
                    const modified = document.createElement('span');
                    modified.className = 'item-modified';
                    modified.textContent = '修改 ' + formatStamp(item.updatedAt);
                    actionsDiv.insertBefore(modified, actionsDiv.firstChild);
                }
                div.appendChild(infoDiv);
                if (isNote) {
                    const created = document.createElement('div');
                    created.className = 'item-created';
                    created.textContent = '创建 ' + formatStamp(item.createdAt);
                    div.appendChild(created);
                }
                const preview = document.createElement('div'); preview.className = 'item-preview';
                const previewText = itemText(item).replace(/\\s+/g, ' ').slice(0, 70);
                preview.innerHTML = previewText ? highlightMatch(escapeHtml(previewText), query) : '还没有正文，等待你的第一句话。';
                div.appendChild(preview);
                div.appendChild(actionsDiv);
                div.onclick = () => {
                    const on = !batchSelected.has(item.id);
                    activate();
                    if (batching) { div.classList.toggle('selected', on); const check = infoDiv.querySelector('.item-check'); if (check) check.checked = on; }
                };
                container.appendChild(div);
            });
        }

        function renameItem(id, event) {
            event.stopPropagation();
            const list = currentTab === 'novel' ? appData.novels : appData.notes;
            const item = list.find(i => i.id === id);
            if (!item) return;
            openRenameDialog(id, item.title);
        }

        let createMode = 'note';
        function openCreateDialog() {
            document.getElementById('list-search').value = '';
            createMode = currentTab;
            const isNovel = createMode === 'novel';
            document.getElementById('create-dialog-title').textContent = isNovel ? '新建小说' : '新建记事本';
            document.getElementById('create-type-row').style.display = isNovel ? 'flex' : 'none';
            const input = document.getElementById('create-title-input');
            input.value = '';
            onCreateTitleInput();
            document.getElementById('create-dialog').showModal();
            setTimeout(() => input.focus(), 60);
        }
        function closeCreateDialog() {
            document.getElementById('create-dialog').close();
        }
        function onCreateTitleInput() {
            document.getElementById('create-confirm-btn').disabled = !document.getElementById('create-title-input').value.trim();
        }
        function handleCreateSubmit(event) {
            const btn = document.getElementById('create-confirm-btn');
            const title = document.getElementById('create-title-input').value.trim();
            if (btn.disabled || !title) { event.preventDefault(); return false; }
            const newItem = { id: genId(), title: title };
            if (createMode === 'novel') {
                const type = document.querySelector('input[name="new-novel-type"]:checked').value;
                if (type === 'short') {
                    newItem.type = 'short';
                    newItem.content = '';
                } else {
                    newItem.type = 'long';
                    newItem.volumes = [];
                }
                appData.novels.unshift(newItem);
            } else {
                newItem.content = '';
                newItem.createdAt = Date.now();
                newItem.updatedAt = Date.now();
                appData.notes.unshift(newItem);
            }
            renderList();
            openItem(newItem.id);
            immediateSave();
            return true;
        }
        let renameTargetId = null;
        function openRenameDialog(id, current) {
            renameTargetId = id;
            const input = document.getElementById('rename-input');
            input.value = current || '';
            document.getElementById('rename-dialog').showModal();
            setTimeout(() => { input.focus(); input.select(); }, 60);
        }
        function handleRenameSubmit(event) {
            const value = document.getElementById('rename-input').value.trim();
            if (!value) { event.preventDefault(); return false; }
            const list = currentTab === 'novel' ? appData.novels : appData.notes;
            const item = list.find(i => i.id === renameTargetId);
            if (item) {
                item.title = value;
                if (currentTab === 'note') item.updatedAt = Date.now();
                if (currentTab === 'note' && activeNoteId === renameTargetId) document.getElementById('note-title').value = item.title;
                if (currentTab === 'novel' && activeNovelId === renameTargetId && item.type === 'short') document.getElementById('chapter-title').value = item.title;
                renderList();
                immediateSave();
            }
            return true;
        }

        async function deleteItem(id, event) {
            event.stopPropagation();
            if (!await showConfirm('删除后数据将从云端永久抹去，无法恢复。', { title: '删除确认', okText: '删除', danger: true })) return;

            if (currentTab === 'novel') {
                appData.novels = appData.novels.filter(n => n.id !== id);
                if (activeNovelId === id) document.getElementById('editor-area').style.display = 'none';
            } else {
                appData.notes = appData.notes.filter(n => n.id !== id);
                if (activeNoteId === id) document.getElementById('editor-area').style.display = 'none';
            }
            renderList();
            document.getElementById('empty-state').style.display = 'flex';
            await immediateSave();
        }

        function openItem(id) {
            
            document.getElementById('empty-state').style.display = 'none';
            document.getElementById('editor-area').style.display = 'flex';
            closeSidebar();

            if (currentTab === 'novel') {
                activeNovelId = id; 
                const novel = appData.novels.find(n => n.id === id);
                if(!novel.type) novel.type = 'long'; 

                document.getElementById('note-header').style.display = 'none';
                document.getElementById('note-body').style.display = 'none';
                document.getElementById('note-typesetting').style.display = 'none';
                document.getElementById('novel-layout').style.display = 'flex';
                document.getElementById('crawler-box').style.display = 'none'; 

                if (novel.type === 'short') {
                    document.getElementById('short-novel-msg').style.display = 'block';
                    document.getElementById('novel-toc-header').style.display = 'none';
                    document.getElementById('novel-toc').style.display = 'none';

                    document.getElementById('novel-current-path').innerText = '独立短篇模式';
                    
                    const titleInput = document.getElementById('chapter-title');
                    titleInput.style.display = 'block';
                    titleInput.value = novel.title || '';
                    titleInput.placeholder = "短篇小说标题";

                    const contentArea = document.getElementById('main-content');
                    contentArea.disabled = false;
                    contentArea.value = novel.content || '';
                    contentArea.placeholder = "开始输入短篇小说的正文，或者点击左侧[🌐 采集配置]展开采集器录入...";

                    document.querySelector('input[name="crawl-type"][value="short"]').checked = true;
                    handleCrawlTypeChange();
                } else {
                    document.getElementById('short-novel-msg').style.display = 'none';
                    document.getElementById('novel-toc-header').style.display = 'flex';
                    document.getElementById('novel-toc').style.display = 'block';
                    
                    activeVolumeId = null; activeChapterId = null;
                    document.getElementById('chapter-title').style.display = 'none';
                    
                    const mainContent = document.getElementById('main-content');
                    mainContent.value = '';
                    mainContent.disabled = true; 
                    mainContent.placeholder = '请在左侧目录树中选择章节。如需批量采集长篇，请点击上方[🌐 采集配置]按钮。';
                    
                    document.getElementById('novel-current-path').innerText = '请选择章节';
                    renderNovelToc();
                }
            } else {
                activeNoteId = id;
                const note = appData.notes.find(n => n.id === id);
                document.getElementById('novel-layout').style.display = 'none';
                document.getElementById('note-header').style.display = 'flex';
                document.getElementById('note-body').style.display = 'flex';
                document.getElementById('note-typesetting').style.display = 'flex';
                document.getElementById('note-title').value = note.title;
                document.getElementById('note-content').value = note.content;
                setNoteMode(noteMode);
            }
            renderList();
            updateWordCount();
        }

        function toggleCrawlerPanel() {
            const box = document.getElementById('crawler-box');
            if(box.style.display === 'none' || box.style.display === '') {
                box.style.display = 'flex';
            } else {
                box.style.display = 'none';
            }
        }

        function handleCrawlTypeChange() {
            const type = document.querySelector('input[name="crawl-type"]:checked').value;
            const srcArea = document.getElementById('crawler-source');
            if(type === 'short') {
                srcArea.placeholder = "【防爬备用】若单页遇到防爬盾，请直接在此处粘贴该短篇小说的网页HTML源代码（留空则走网络抓取）";
            } else {
                srcArea.placeholder = "【防爬备用】若目录页遇到防爬盾，请直接在此处粘贴目录页HTML网页源码（留空则走网络抓取）";
            }
        }

        // ================= 长篇小说专用树状目录 =================
        function renderNovelToc() {
            const novel = appData.novels.find(n => n.id === activeNovelId);
            const toc = document.getElementById('novel-toc');
            toc.innerHTML = '';
            if(!novel || novel.type === 'short') return;
            
            if(!novel.volumes) novel.volumes = [];
            novel.volumes.forEach(vol => {
                const volDiv = document.createElement('div');
                volDiv.className = 'volume-item';
                const volHeader = document.createElement('div');
                volHeader.className = 'volume-header';
                volHeader.innerHTML = '<span>📖 ' + escapeHtml(vol.title) + '</span><div><button class="btn-text">改</button><button class="btn-text">+章</button></div>';
                const volumeButtons = volHeader.querySelectorAll('button');
                volumeButtons[0].onclick = event => editVolume(vol.id, event);
                volumeButtons[1].onclick = event => addChapter(vol.id, event);
                volDiv.appendChild(volHeader);
                
                const chapList = document.createElement('div');
                chapList.className = 'chapter-list';
                vol.chapters.forEach(chap => {
                    const chapItem = document.createElement('div');
                    chapItem.className = 'chapter-item' + (activeChapterId === chap.id ? ' active' : '');
                    chapItem.innerHTML = '<span>📄 ' + escapeHtml(chap.title) + '</span><button class="btn-text btn-danger" style="padding:0;">删</button>';
                    chapItem.querySelector('button').onclick = event => deleteChapter(vol.id, chap.id, event);
                    chapItem.onclick = () => openChapter(vol.id, chap.id);
                    chapList.appendChild(chapItem);
                });
                volDiv.appendChild(chapList);
                toc.appendChild(volDiv);
            });
        }

        async function addVolume() {
            const title = prompt('请输入新卷的名称（如：第一卷 少年远行）：');
            if (!title) return;
            const novel = appData.novels.find(n => n.id === activeNovelId);
            novel.volumes.push({ id: genId(), title: title, chapters: [] });
            renderNovelToc();
            await immediateSave();
        }

        async function editVolume(volId, event) {
            event.stopPropagation();
            const novel = appData.novels.find(n => n.id === activeNovelId);
            const vol = novel.volumes.find(v => v.id === volId);
            const newTitle = prompt('修改卷名：', vol.title);
            if (newTitle) {
                vol.title = newTitle;
                renderNovelToc();
                await immediateSave();
            }
        }

        async function addChapter(volId, event) {
            event.stopPropagation();
            const title = prompt('请输入新章节名称（如：第一章 觉醒）：');
            if (!title) return;
            const novel = appData.novels.find(n => n.id === activeNovelId);
            const vol = novel.volumes.find(v => v.id === volId);
            const newChap = { id: genId(), title: title, content: '' };
            vol.chapters.push(newChap);
            renderNovelToc();
            openChapter(volId, newChap.id);
            await immediateSave();
        }

        async function deleteChapter(volId, chapId, event) {
            event.stopPropagation();
            if (!await showConfirm('章节内容删除后将无法恢复。', { title: '删除章节', okText: '删除', danger: true })) return;
            const novel = appData.novels.find(n => n.id === activeNovelId);
            const vol = novel.volumes.find(v => v.id === volId);
            vol.chapters = vol.chapters.filter(c => c.id !== chapId);
            if (activeChapterId === chapId) {
                const mainContent = document.getElementById('main-content');
                mainContent.value = '';
                mainContent.disabled = true;
                document.getElementById('chapter-title').style.display = 'none';
                activeChapterId = null;
            }
            renderNovelToc();
            await immediateSave();
        }

        function openChapter(volId, chapId) {
            activeVolumeId = volId; activeChapterId = chapId;
            const novel = appData.novels.find(n => n.id === activeNovelId);
            const vol = novel.volumes.find(v => v.id === volId);
            const chap = vol.chapters.find(c => c.id === chapId);
            
            document.getElementById('novel-current-path').innerText = vol.title + ' > ' + chap.title;
            const titleInput = document.getElementById('chapter-title');
            titleInput.style.display = 'block';
            titleInput.value = chap.title;
            
            const contentArea = document.getElementById('main-content');
            contentArea.disabled = false;
            contentArea.value = chap.content;
            updateWordCount();
            
            document.getElementById('novel-sidebar').classList.remove('show');
            renderNovelToc();
        }

        // ================= 全新独立沉浸阅读器逻辑 =================
        function toggleReadMode() {
            const overlay = document.getElementById('reader-overlay');
            const isEntering = overlay.style.display === 'none';
            
            if (isEntering) {
                let title = '', text = '';
                if (currentTab === 'novel') {
                    const novel = appData.novels.find(n => n.id === activeNovelId);
                    if (novel.type === 'short') {
                        title = document.getElementById('chapter-title').value || '独立短篇';
                        text = document.getElementById('main-content').value;
                    } else {
                        if (!activeChapterId) { showToast('请在左侧目录树选择对应章节再开启沉浸阅读。', 'error'); return; }
                        title = document.getElementById('chapter-title').value || '未命名章节';
                        text = document.getElementById('main-content').value;
                    }
                } else {
                    if (!activeNoteId) { showToast('请打开一篇记事本。', 'error'); return; }
                    title = document.getElementById('note-title').value || '记事本阅读';
                    text = document.getElementById('note-content').value;
                }

                if (!text.trim() && !title.trim()) { showToast('当前文本空空如也~'); return; }

                const formattedHtml = text.split('\\n').map(line => {
                    const trimmed = line.trim();
                    return trimmed ? '<p>' + escapeHtml(trimmed) + '</p>' : '<br/>';
                }).join('');

                const contentBox = document.getElementById('reader-content');
                contentBox.classList.toggle('note-reading', currentTab === 'note');
                if (currentTab === 'note') {
                    const heading = document.createElement('h2');
                    heading.textContent = title;
                    const body = document.createElement('div');
                    body.className = 'markdown-content';
                    window.renderNoteMarkdown(text, body);
                    contentBox.replaceChildren(heading, body);
                    readerFontSize = Number(document.getElementById('note-font-size').value);
                } else {
                    contentBox.innerHTML = '<h2>' + escapeHtml(title) + '</h2>' + formattedHtml;
                }
                contentBox.style.fontSize = readerFontSize + 'px';
                document.getElementById('reader-font-size-display').textContent = readerFontSize + 'px';
                
                changeReaderTheme({ light: 'paper', dark: 'night', passion: 'sepia' }[document.body.className] || 'paper');
                document.getElementById('reader-toolbar').classList.remove('hidden');
                overlay.style.display = 'flex';
            } else {
                overlay.style.display = 'none';
            }
        }

        function toggleReaderToolbar() { document.getElementById('reader-toolbar').classList.toggle('hidden'); }
        function changeReaderFontSize(delta) {
            readerFontSize += delta;
            if (readerFontSize < 14) readerFontSize = 14;
            if (readerFontSize > 36) readerFontSize = 36;
            document.getElementById('reader-content').style.fontSize = readerFontSize + 'px';
            document.getElementById('reader-font-size-display').innerText = readerFontSize + 'px';
        }
        function changeReaderTheme(theme) { document.getElementById('reader-overlay').className = 'theme-' + theme; }

        // ================= 网文强力净化无损采集引擎 =================
        function updateCrawlProgress(current, total) {
            const container = document.getElementById('crawl-progress-box');
            const inner = document.getElementById('crawl-progress-bar');
            if(total === 0) { container.style.display = 'none'; return; }
            container.style.display = 'block';
            inner.style.width = Math.round((current / total) * 100) + '%';
        }

        function cleanAndExtractContent(doc, currentUrl) {
            // 正文页去噪清理
            const excludes = doc.querySelectorAll('script, style, iframe, a, .ads, .sidebar, footer, header, nav, .footer, .header, .sidebar_right');
            excludes.forEach(el => el.remove());
            const selectors = ['#content', '#content_text', '.content', '.post-content', '.book-content', '#txt', '#article', 'article', '.novel-content', '#chapterContent', '.showtxt', '.read-content', '.chapter-content'];
            for (let s of selectors) {
                let el = doc.querySelector(s);
                if (el && el.innerText.trim().length > 100) { return formatTextRaw(el.innerHTML, currentUrl); }
            }
            let maxLen = 0, bestEl = doc.body;
            doc.querySelectorAll('div').forEach(div => {
                if(div.innerText.length > maxLen) { maxLen = div.innerText.length; bestEl = div; }
            });
            return formatTextRaw(bestEl.innerHTML, currentUrl);
        }

        function formatTextRaw(html, currentUrl) {
            let t = html.replace(/<br\\s*\\/?>/gi, '\\n').replace(/<\\/p>/gi, '\\n').replace(/<[^>]+>/g, ''); 
            t = t.replace(/&nbsp;/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
            
            let blacklist = [];
            if (currentUrl) {
                blacklist.push(currentUrl); 
                try {
                    const urlObj = new URL(currentUrl);
                    blacklist.push(urlObj.hostname); 
                    blacklist.push(urlObj.host);     
                    const parts = urlObj.hostname.split('.');
                    if (parts.length >= 2) blacklist.push(parts.slice(-2).join('.')); 
                } catch(e){}
            }
            const userBlacklist = document.getElementById('crawl-blacklist').value.trim();
            if (userBlacklist) {
                userBlacklist.split(/[,，]/).forEach(word => { if (word.trim()) blacklist.push(word.trim()); });
            }
            
            // 【V5.4 修复】改用纯文本内置取代破坏性的 RegExp，完美避开特定特殊符号导致的运行崩溃问题
            blacklist.forEach(word => {
                if (word && word.trim().length > 0) {
                    const w = word.trim();
                    t = t.replaceAll(w, '');
                    t = t.replaceAll(w.toLowerCase(), '');
                    t = t.replaceAll(w.toUpperCase(), '');
                }
            });
            return t.split('\\n').map(line => line.trim()).filter(line => line.length > 0).join('\\n\\n');
        }

        async function startCrawlNovel() {
            const urlInput = document.getElementById('crawl-url').value.trim();
            const type = document.querySelector('input[name="crawl-type"]:checked').value;
            const sourceCode = document.getElementById('crawler-source').value.trim();
            const msgEl = document.getElementById('crawl-msg');

            const novel = appData.novels.find(n => n.id === activeNovelId);
            if (!novel) { showToast('请确保处于小说编辑面板中。', 'error'); return; }

            if (sourceCode.length > 100) {
                const parser = new DOMParser();
                const localDoc = parser.parseFromString(sourceCode, 'text/html');
                document.getElementById('crawler-source').value = ''; 

                if (type === 'short') {
                    msgEl.innerText = '🧩 正在离线解构单页HTML正文...';
                    msgEl.style.color = '#e6a23c';

                    let title = localDoc.querySelector('h1')?.innerText || localDoc.querySelector('title')?.innerText || '离线洗净短篇';
                    title = title.replace(/_小说.*/, '').trim();
                    const content = cleanAndExtractContent(localDoc, urlInput);

                    novel.type = 'short';
                    novel.title = title;
                    novel.content = content;

                    document.getElementById('chapter-title').value = title;
                    document.getElementById('main-content').value = content;

                    msgEl.innerText = '🎉 源码清洗完成！已直接填入当前正文';
                    msgEl.style.color = '#67c23a';
                    
                    renderList();
                    await immediateSave();
                } else {
                    if (!urlInput) { showToast('长篇离线模式必须填写原目录网址以推算跳转关系。', 'error'); return; }
                    msgEl.innerText = '🧩 正在分析目录源码超链接...';
                    parseAndCrawlLongNovel(localDoc, urlInput);
                }
                return;
            }

            if (!urlInput) { showToast('请填写有效网址或直接在下方框内粘贴网页源码！', 'error'); return; }
            msgEl.innerText = '⏳ 正在通过云端API中转页面...';
            msgEl.style.color = 'var(--accent)';
            updateCrawlProgress(0, 0);

            try {
                const proxyUrl = '/api/proxy?url=' + encodeURIComponent(urlInput);
                const response = await apiFetch(proxyUrl);
                if (!response.ok) throw new Error('网络连接被目标小说站封锁');
                const htmlText = await response.text();

                const parser = new DOMParser();
                const targetDoc = parser.parseFromString(htmlText, 'text/html');

                if (type === 'short') {
                    let title = targetDoc.querySelector('h1')?.innerText || targetDoc.querySelector('title')?.innerText || '单页短篇';
                    title = title.replace(/_小说.*/, '').trim();
                    const content = cleanAndExtractContent(targetDoc, urlInput);

                    novel.type = 'short';
                    novel.title = title;
                    novel.content = content;

                    document.getElementById('chapter-title').value = title;
                    document.getElementById('main-content').value = content;

                    msgEl.innerText = '✅ 线上短篇抓取纯净灌入成功！';
                    msgEl.style.color = '#67c23a';
                    
                    renderList();
                    await immediateSave();
                } else {
                    parseAndCrawlLongNovel(targetDoc, urlInput);
                }
            } catch (e) {
                msgEl.innerText = '❌ 抓取失败: ' + e.message + ' (建议走HTML源码离线清洗方案)';
                msgEl.style.color = 'var(--danger)';
            }
        }

        async function parseAndCrawlLongNovel(targetDoc, indexUrl) {
            const msgEl = document.getElementById('crawl-msg');
            
            // 【V5.4 关键修复】绝对不在目录页进行大规模 DOM 树节点删除，避免误删目录结构容器包裹层
            // 仅仅剔除不包含有效超链接的无用脚本块
            targetDoc.querySelectorAll('script, style, iframe').forEach(el => el.remove());

            const links = targetDoc.querySelectorAll('a');
            const chapterTasks = [];

            const urlObj = new URL(indexUrl);
            const baseUrl = urlObj.origin + urlObj.pathname.substring(0, urlObj.pathname.lastIndexOf('/') + 1);

            // 导航常用高频排除词
            const navKeywords = ['首页', '书架', '排行', '分类', '完本', '新书', '充值', '客户端', '上一页', '下一页', '目录', '返回', '作者', '简介', '登录', '注册', '书库', '反馈', '帮助', '手机版', '书评', '加入书架', '设置', '搜索'];

            links.forEach(a => {
                const href = a.getAttribute('href');
                const title = a.innerText.trim();
                
                if (!href || !title || href.startsWith('javascript') || href.startsWith('#') || title.length > 60) return;

                // 检验拦截导航专有短语
                const hasNavKeyword = navKeywords.some(k => title.includes(k));
                if (hasNavKeyword) return;

                // 【V5.4 关键修复】对 \\d 进行底层反斜杠双重转义，确保编译成原生 JS 时保留完整的数字提取器规则
                const isChapterTitle = (
                    title.includes('章') || 
                    title.includes('节') || 
                    title.includes('回') || 
                    title.includes('卷') ||
                    title.includes('集') ||
                    title.includes('番外') ||
                    title.includes('序言') ||
                    title.includes('尾声') ||
                    title.includes('楔子') ||
                    title.includes('前言') ||
                    /^第?[一二三四五六七八九十百千万零\\d]+/.test(title) || 
                    /^\\d+/.test(title)
                );

                if (isChapterTitle) {
                    let absoluteUrl = href;
                    if (!href.startsWith('http')) {
                        if (href.startsWith('/')) { absoluteUrl = urlObj.origin + href; } else { absoluteUrl = baseUrl + href; }
                    }
                    if(!chapterTasks.some(t => t.url === absoluteUrl)) { chapterTasks.push({ title: title, url: absoluteUrl }); }
                }
            });

            if (chapterTasks.length === 0) {
                msgEl.innerText = '❌ 未能检测到有效章节链接，请检查贴入的源码是否完整。';
                msgEl.style.color = 'var(--danger)';
                return;
            }

            if (!await showConfirm('共识别出 ' + chapterTasks.length + ' 个纯净章节链接，是否立即开始自动排队同步正文？', { title: '开始采集', okText: '开始同步' })) {
                msgEl.innerText = '采集已中止。'; return;
            }

            const novel = appData.novels.find(n => n.id === activeNovelId);
            novel.type = 'long'; 
            if(!novel.volumes) novel.volumes = [];
            const volId = genId();
            const newVol = { id: volId, title: '强滤同步卷-' + new Date().toLocaleDateString(), chapters: [] };
            novel.volumes.push(newVol);
            
            document.getElementById('short-novel-msg').style.display = 'none';
            document.getElementById('novel-toc-header').style.display = 'flex';
            document.getElementById('novel-toc').style.display = 'block';
            renderNovelToc();

            let successCount = 0;
            for (let i = 0; i < chapterTasks.length; i++) {
                const task = chapterTasks[i];
                msgEl.innerText = '⏳ 正在拉取 (' + (i + 1) + '/' + chapterTasks.length + '): ' + task.title;
                updateCrawlProgress(i + 1, chapterTasks.length);

                try {
                    const proxyUrl = '/api/proxy?url=' + encodeURIComponent(task.url);
                    const res = await apiFetch(proxyUrl);
                    if(res.ok) {
                        const html = await res.text();
                        const p = new DOMParser();
                        const cDoc = p.parseFromString(html, 'text/html');
                        const text = cleanAndExtractContent(cDoc, task.url);
                        newVol.chapters.push({ id: genId(), title: task.title, content: text });
                        successCount++;
                    }
                } catch(err) {
                    newVol.chapters.push({ id: genId(), title: task.title + '(缺失)', content: '同步超时。' });
                }
                if (i % 5 === 0) { saveDataToServer(); renderNovelToc(); }
                await new Promise(r => setTimeout(r, 450));
            }

            msgEl.innerText = '🎉 稳定版解构完成！成功拉取 ' + successCount + '/' + chapterTasks.length + ' 章。';
            msgEl.style.color = '#67c23a';
            updateCrawlProgress(0, 0);
            renderNovelToc();
            await immediateSave();
        }

        // ================= 通用辅助及移动端交互 =================
        function itemText(item) {
            return item.content || (item.volumes || []).flatMap(v => (v.chapters || []).map(c => c.content || '')).join(' ');
        }
        function updateWordCount() {
            const text = document.getElementById(currentTab === 'note' ? 'note-content' : 'main-content').value;
            document.getElementById('word-count').textContent = text.replace(/\\s/g, '').length.toLocaleString() + ' 字';
        }
        function closeSidebar() {
            document.getElementById('main-sidebar').classList.remove('show');
            document.getElementById('sidebar-scrim').classList.remove('show');
            document.getElementById('sidebar-toggle').setAttribute('aria-expanded', 'false');
        }
        function toggleSidebar() {
            const open = document.getElementById('main-sidebar').classList.toggle('show');
            document.getElementById('sidebar-scrim').classList.toggle('show', open);
            document.getElementById('sidebar-toggle').setAttribute('aria-expanded', String(open));
        }
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') { closeSidebar(); document.getElementById('novel-sidebar').classList.remove('show'); }
        });
        function toggleNovelSidebar() { document.getElementById('novel-sidebar').classList.toggle('show'); }

        function downloadTxt(filename, text) {
            const formattedText = text.replace(/\\n/g, '\\r\\n');
            const blob = new Blob([formattedText], { type: 'text/plain;charset=utf-8' });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = filename + '.txt';
            link.click();
            URL.revokeObjectURL(link.href);
        }

        function exportNote() {
            const note = appData.notes.find(n => n.id === activeNoteId);
            if (!note) return;
            downloadTxt(note.title, note.title + '\\n\\n' + note.content);
        }

        function exportNovel() {
            const novel = appData.novels.find(n => n.id === activeNovelId);
            if (!novel) return;
            let text = '';
            if(novel.type === 'short') {
                text = '《' + novel.title + '》\\n\\n' + (novel.content || '');
            } else {
                text = '《' + novel.title + '》\\n\\n';
                if(novel.volumes) {
                    novel.volumes.forEach(vol => {
                        text += '【' + vol.title + '】\\n\\n';
                        vol.chapters.forEach(chap => {
                            text += '  ' + chap.title + '\\n\\n' + chap.content + '\\n\\n\\n';
                        });
                    });
                }
            }
            downloadTxt(novel.title, text);
        }
    </script>
</body>
</html>
`;
