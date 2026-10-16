//! Local-only browser UI for deliberately narrow, authorised Web posture checks.
//!
//! It binds exclusively to 127.0.0.1, persists nothing, and exposes no API to
//! other hosts. A scan request requires an operator acknowledgement and then
//! invokes the same bounded checks as `--modules wordpress`.

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::modules::{web::scan_target as scan_web_target, wordpress::scan_site_root};

const MAX_REQUEST_BYTES: usize = 8 * 1024;

const PAGE: &str = r##"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>diego | Web posture check</title>
<style>
:root{color-scheme:dark;--bg:#101725;--panel:#19243a;--line:#33435e;--ink:#eff5ff;--muted:#afbdd1;--accent:#67d4b5;--warn:#f6c85f}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top right,#203b58,transparent 34rem),var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}.wrap{max-width:920px;margin:auto;padding:48px 20px 80px}header{margin-bottom:32px}.bar{display:flex;justify-content:space-between;gap:16px;align-items:center}.eyebrow{color:var(--accent);font-weight:700;letter-spacing:.08em;font-size:.8rem;text-transform:uppercase}.language{display:flex;gap:8px;align-items:center;color:var(--muted);font-size:.9rem}.language select{width:auto;padding:7px 10px}h1{font-size:clamp(2rem,5vw,3.4rem);line-height:1.1;margin:.35rem 0 1rem}h2{font-size:1.15rem;margin:0 0 12px}.lead,.muted{color:var(--muted)}.panel{background:color-mix(in srgb,var(--panel) 92%,black);border:1px solid var(--line);border-radius:16px;padding:24px;margin:16px 0;box-shadow:0 16px 40px #0003}label{display:block;font-weight:700;margin:16px 0 6px}input[type=url],select{width:100%;padding:13px;border:1px solid var(--line);border-radius:9px;background:#0d1421;color:var(--ink);font:inherit}.consent{display:flex;gap:10px;align-items:flex-start;font-weight:400;margin:18px 0}.consent input{margin-top:5px;accent-color:var(--accent)}button{appearance:none;border:0;border-radius:9px;background:var(--accent);color:#082019;font:700 1rem system-ui;padding:12px 18px;cursor:pointer}button:disabled{cursor:not-allowed;opacity:.55}.boundary{border-left:3px solid var(--warn);padding-left:13px;color:var(--muted);font-size:.93rem}.status{min-height:1.6em;color:var(--muted);margin:14px 0 0}.result{margin-top:24px}.summary{display:flex;flex-wrap:wrap;gap:10px;margin:12px 0 16px}.count{border:1px solid var(--line);padding:7px 11px;border-radius:999px;font-weight:700}.finding{border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:10px;padding:16px;margin:10px 0;background:#111b2b}.finding.medium{border-left-color:var(--warn)}.finding.low{border-left-color:#7cb8f5}.finding.info{border-left-color:var(--accent)}.finding h3{font-size:1.02rem;margin:0 0 5px}.badge{font-size:.75rem;font-weight:800;letter-spacing:.04em}.evidence{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;color:var(--muted);margin-top:10px}.actions{margin:10px 0 0;padding-left:20px}.download{margin-top:16px;background:transparent;border:1px solid var(--accent);color:var(--accent)}noscript{color:var(--warn)}@media(max-width:520px){.bar{align-items:flex-start;flex-direction:column}.wrap{padding-top:28px}}</style></head>
<body><main class="wrap"><header><div class="bar"><div class="eyebrow" data-i18n="eyebrow">localhost only · read-only</div><label class="language" for="language"><span data-i18n="language">Language</span><select id="language"><option value="en">English</option><option value="ja">日本語</option><option value="zh-CN">简体中文</option><option value="zh-TW">繁體中文</option></select></label></div><h1 data-i18n="title">Web posture check</h1><p class="lead" data-i18n="lead">Review a small number of public responses and present configuration exposure clearly.</p></header>
<section class="panel" aria-labelledby="start"><h2 id="start" data-i18n="targetSite">Target site</h2><p class="boundary" data-i18n="boundary">Only assess sites you own or are explicitly authorised to assess. No crawling, path discovery, login, user or plugin enumeration, CVE testing, or POST requests are performed.</p><form id="scan-form"><label for="scan-type" data-i18n="scanType">Check type</label><select id="scan-type" name="scan-type"><option value="web">Web server headers</option><option value="wordpress">WordPress public exposure</option></select><label for="target" data-i18n="url">URL</label><input id="target" name="target" type="url" placeholder="https://example.com/" required pattern="https?://.+"><label class="consent"><input id="authorised" type="checkbox" required><span data-i18n="authorised">I am authorised to assess this site.</span></label><button id="submit" type="submit" data-i18n="submit">Check public posture</button></form><div class="status" id="status" role="status" aria-live="polite"></div></section>
<section class="panel result" id="result" hidden aria-labelledby="result-title"><h2 id="result-title" data-i18n="results">Results</h2><div id="summary" class="summary"></div><div id="findings"></div><button id="download" class="download" type="button" data-i18n="download">Download JSON</button></section>
<section class="panel"><h2 data-i18n="scopeTitle">Request boundary</h2><p class="muted" data-i18n="scope">The Web check sends one HEAD request to the URL, with one range-limited GET fallback. The WordPress check reads at most 64 KiB from the site root and sends HEAD requests only to xmlrpc.php, wp-json/, and readme.html. Redirects are not followed; results remain only in this browser view.</p></section><noscript>JavaScript is required for this UI.</noscript></main>
<script>
const translations={en:{title:'Web posture check',eyebrow:'localhost only · read-only',language:'Language',lead:'Review a small number of public responses and present configuration exposure clearly.',targetSite:'Target site',boundary:'Only assess sites you own or are explicitly authorised to assess. No crawling, path discovery, login, user or plugin enumeration, CVE testing, or POST requests are performed.',scanType:'Check type',types:{web:'Web server headers',wordpress:'WordPress public exposure'},url:'URL',authorised:'I am authorised to assess this site.',submit:'Check public posture',results:'Results',download:'Download JSON',scopeTitle:'Request boundary',scope:'The Web check sends one HEAD request to the URL, with one range-limited GET fallback. The WordPress check reads at most 64 KiB from the site root and sends HEAD requests only to xmlrpc.php, wp-json/, and readme.html. Redirects are not followed; results remain only in this browser view.',checking:'Checking public posture…',complete:'Completed: {count} finding(s)',error:'Error: {message}',noFindings:'No findings.',recommended:'Recommended action',needAuthorisation:'Authorisation acknowledgement is required.',severities:{CRITICAL:'Critical',HIGH:'High',MEDIUM:'Medium',LOW:'Low',INFO:'Info'},errors:{'authorisation acknowledgement is required':'Authorisation acknowledgement is required','invalid JSON request':'Invalid local request','application/json is required':'Invalid local request'}},ja:{title:'外部 Web ポスチャ確認',eyebrow:'localhost only · read-only',language:'言語',lead:'公開レスポンスだけを少数回確認し、設定上の露出を読みやすく表示します。',targetSite:'対象サイト',boundary:'所有している、または明示的な診断許可のあるサイトだけを指定してください。クロール、パス探索、ログイン、ユーザー／プラグイン列挙、CVE 検証、対象への POST は行いません。',scanType:'診断の種類',types:{web:'Web サーバーのヘッダー設定',wordpress:'WordPress の公開設定'},url:'URL',authorised:'私はこのサイトの診断を行う権限を持っています。',submit:'公開設定を確認する',results:'確認結果',download:'JSON を保存',scopeTitle:'確認する範囲',scope:'Web 診断は指定 URL への HEAD 1 回（未対応時は範囲指定 GET 1 回）だけです。WordPress 診断はサイトルートの最大 64 KiB と、xmlrpc.php、wp-json/、readme.html の HEAD 応答だけを確認します。リダイレクトは追跡せず、結果はこのブラウザ表示中にだけ保持されます。',checking:'公開設定を確認しています…',complete:'完了: {count} 件の結果',error:'エラー: {message}',noFindings:'Finding はありません。',recommended:'推奨対応',needAuthorisation:'診断権限の確認が必要です。',severities:{CRITICAL:'重大',HIGH:'高',MEDIUM:'中',LOW:'低',INFO:'情報'},errors:{'authorisation acknowledgement is required':'診断権限の確認が必要です。','invalid JSON request':'ローカル要求が正しくありません。','application/json is required':'ローカル要求が正しくありません。'}},'zh-CN':{title:'Web 安全配置检查',eyebrow:'仅限本机 · 只读',language:'语言',lead:'以少量公开响应检查配置暴露，并清晰显示结果。',targetSite:'目标站点',boundary:'仅检查你拥有或已明确获授权的站点。不执行爬取、路径发现、登录、用户或插件枚举、CVE 验证或 POST 请求。',scanType:'检查类型',types:{web:'Web 服务器响应头',wordpress:'WordPress 公开暴露'},url:'URL',authorised:'我有权检查此站点。',submit:'检查公开配置',results:'检查结果',download:'下载 JSON',scopeTitle:'请求边界',scope:'Web 检查只向指定 URL 发送一次 HEAD 请求；仅在不支持时发送一次限范围 GET。WordPress 检查最多读取站点根目录 64 KiB，并且只对 xmlrpc.php、wp-json/ 和 readme.html 发送 HEAD 请求。不跟随重定向；结果仅在当前浏览器视图中保留。',checking:'正在检查公开配置…',complete:'完成：{count} 项结果',error:'错误：{message}',noFindings:'没有发现项。',recommended:'建议操作',needAuthorisation:'需要确认诊断授权。',severities:{CRITICAL:'严重',HIGH:'高',MEDIUM:'中',LOW:'低',INFO:'信息'},errors:{'authorisation acknowledgement is required':'需要确认诊断授权。','invalid JSON request':'本地请求无效。','application/json is required':'本地请求无效。'}},'zh-TW':{title:'Web 安全設定檢查',eyebrow:'僅限本機 · 唯讀',language:'語言',lead:'以少量公開回應檢查設定暴露，並清楚顯示結果。',targetSite:'目標網站',boundary:'只檢查你擁有或已明確獲授權的網站。不執行爬取、路徑探索、登入、使用者或外掛列舉、CVE 驗證或 POST 請求。',scanType:'檢查類型',types:{web:'Web 伺服器回應標頭',wordpress:'WordPress 公開暴露'},url:'URL',authorised:'我有權檢查此網站。',submit:'檢查公開設定',results:'檢查結果',download:'下載 JSON',scopeTitle:'請求界限',scope:'Web 檢查只向指定 URL 傳送一次 HEAD 請求；僅在不支援時傳送一次限範圍 GET。WordPress 檢查最多讀取網站根目錄 64 KiB，並且只對 xmlrpc.php、wp-json/ 和 readme.html 傳送 HEAD 請求。不追蹤重新導向；結果只在目前瀏覽器檢視中保留。',checking:'正在檢查公開設定…',complete:'完成：{count} 項結果',error:'錯誤：{message}',noFindings:'沒有發現項目。',recommended:'建議操作',needAuthorisation:'需要確認診斷授權。',severities:{CRITICAL:'嚴重',HIGH:'高',MEDIUM:'中',LOW:'低',INFO:'資訊'},errors:{'authorisation acknowledgement is required':'需要確認診斷授權。','invalid JSON request':'本機請求無效。','application/json is required':'本機請求無效。'}}};
let current='en',lastReport=null;const $=id=>document.getElementById(id);const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));const text=key=>key.split('.').reduce((value,part)=>value&&value[part],translations[current])||key;const withCount=(key,count)=>text(key).replace('{count}',count);const localError=message=>translations[current].errors[message]||message;
function applyLanguage(locale){current=translations[locale]?locale:'en';$('language').value=current;document.documentElement.lang=current;document.title=`diego | ${text('title')}`;document.querySelectorAll('[data-i18n]').forEach(node=>node.textContent=text(node.dataset.i18n));for(const option of $('scan-type').options)option.textContent=text(`types.${option.value}`);if(lastReport)render(lastReport)}
function render(report){lastReport=report;$('result').hidden=false;$('summary').innerHTML=Object.entries(report.summary).filter(([,count])=>count).map(([severity,count])=>`<span class="count">${esc(text(`severities.${severity}`))}: ${count}</span>`).join('')||`<span class="muted">${esc(text('noFindings'))}</span>`;$('findings').innerHTML=report.findings.map(f=>`<article class="finding ${String(f.severity).toLowerCase()}"><div class="badge">${esc(text(`severities.${f.severity}`))} · ${esc(f.confidence)}</div><h3>${esc(f.title)}</h3><p>${esc(f.description)}</p>${f.remediation_steps.length?`<strong>${esc(text('recommended'))}</strong><ul class="actions">${f.remediation_steps.map(step=>`<li>${esc(step)}</li>`).join('')}</ul>`:''}<pre class="evidence">${esc(JSON.stringify(f.evidence,null,2))}</pre></article>`).join('')}
$('language').addEventListener('change',event=>applyLanguage(event.target.value));$('scan-form').addEventListener('submit',async event=>{event.preventDefault();const target=$('target').value.trim(),scan_type=$('scan-type').value,submit=$('submit');if(!$('authorised').checked){$('status').textContent=text('needAuthorisation');return}submit.disabled=true;$('status').textContent=text('checking');$('result').hidden=true;try{const response=await fetch('/api/scan',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({target,scan_type,authorised:true})});const data=await response.json();if(!response.ok)throw new Error(localError(data.error||'invalid JSON request'));render(data);$('status').textContent=withCount('complete',data.findings.length)}catch(error){$('status').textContent=text('error').replace('{message}',error.message)}finally{submit.disabled=false}});$('download').addEventListener('click',()=>{if(!lastReport)return;const link=document.createElement('a');link.href=URL.createObjectURL(new Blob([JSON.stringify(lastReport,null,2)],{type:'application/json'}));link.download='diego-report.json';link.click();URL.revokeObjectURL(link.href)});applyLanguage(current);
</script></body></html>"##;

#[derive(Deserialize)]
struct ScanRequest {
    target: String,
    scan_type: ScanType,
    authorised: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ScanType {
    Web,
    WordPress,
}

/// Serve the UI on loopback only. Ctrl-C terminates the process; scans are not
/// queued or stored.
pub async fn serve(port: u16) -> anyhow::Result<()> {
    if port == 0 {
        anyhow::bail!("--web-ui-port must be between 1 and 65535");
    }
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("[+] diego Web UI: http://127.0.0.1:{port}/ (localhost only; Ctrl-C to stop)");
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(error) = handle(stream).await {
                eprintln!("[!] web UI request failed: {error}");
            }
        });
    }
}

async fn handle(mut stream: TcpStream) -> anyhow::Result<()> {
    let Some((method, path, headers, body)) = read_request(&mut stream).await? else {
        return Ok(());
    };
    let (status, content_type, response) = match (method.as_str(), path.as_str()) {
        ("GET", "/") => ("200 OK", "text/html; charset=utf-8", PAGE.to_string()),
        ("POST", "/api/scan") => scan_response(headers, body).await,
        _ => error_response("404 Not Found", "not found"),
    };
    write_response(&mut stream, status, content_type, &response).await
}

async fn scan_response(
    headers: HashMap<String, String>,
    body: Vec<u8>,
) -> (&'static str, &'static str, String) {
    if headers
        .get("content-type")
        .is_none_or(|value| !value.starts_with("application/json"))
    {
        return error_response("415 Unsupported Media Type", "application/json is required");
    }
    let request: ScanRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return error_response("400 Bad Request", "invalid JSON request"),
    };
    if !request.authorised {
        return error_response(
            "400 Bad Request",
            "authorisation acknowledgement is required",
        );
    }
    let (module, findings) = match request.scan_type {
        ScanType::Web => ("web", scan_web_target(request.target.trim(), 10).await),
        ScanType::WordPress => ("wordpress", scan_site_root(request.target.trim(), 10).await),
    };
    let summary = findings.iter().fold(
        json!({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}),
        |mut summary, finding| {
            let key = finding.severity.to_string();
            summary[&key] = json!(summary[&key].as_u64().unwrap_or(0) + 1);
            summary
        },
    );
    (
        "200 OK",
        "application/json; charset=utf-8",
        json!({"target": request.target, "module": module, "findings": findings, "summary": summary}).to_string(),
    )
}

fn error_response(status: &'static str, message: &str) -> (&'static str, &'static str, String) {
    (
        status,
        "application/json; charset=utf-8",
        json!({"error": message}).to_string(),
    )
}

async fn read_request(
    stream: &mut TcpStream,
) -> anyhow::Result<Option<(String, String, HashMap<String, String>, Vec<u8>)>> {
    let mut data = Vec::new();
    let mut buf = [0_u8; 1024];
    let header_end = loop {
        if data.len() >= MAX_REQUEST_BYTES {
            anyhow::bail!("request exceeds local UI limit");
        }
        let read = stream.read(&mut buf).await?;
        if read == 0 {
            return Ok(None);
        }
        data.extend_from_slice(&buf[..read]);
        if let Some(position) = data.windows(4).position(|part| part == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let head = std::str::from_utf8(&data[..header_end])?;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing method"))?
        .to_owned();
    let path = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing path"))?
        .to_owned();
    if parts.next().is_none() || !matches!(method.as_str(), "GET" | "POST") {
        anyhow::bail!("unsupported local UI request");
    }
    let mut headers = HashMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("invalid header"))?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    let length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(0);
    if length > 2 * 1024 || header_end + length > MAX_REQUEST_BYTES {
        anyhow::bail!("request body exceeds local UI limit");
    }
    while data.len() < header_end + length {
        let read = stream.read(&mut buf).await?;
        if read == 0 {
            anyhow::bail!("truncated request body");
        }
        data.extend_from_slice(&buf[..read]);
    }
    Ok(Some((
        method,
        path,
        headers,
        data[header_end..header_end + length].to_vec(),
    )))
}

async fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> anyhow::Result<()> {
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_are_json() {
        let (status, content_type, body) = error_response("400 Bad Request", "bad input");
        assert_eq!(status, "400 Bad Request");
        assert!(content_type.starts_with("application/json"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["error"],
            "bad input"
        );
    }

    #[test]
    fn ui_is_local_and_offers_all_supported_languages() {
        assert!(PAGE.contains("localhost only"));
        assert!(PAGE.contains("診断を行う権限"));
        assert!(PAGE.contains("xmlrpc.php"));
        assert!(PAGE.contains("Web サーバーのヘッダー設定"));
        assert!(PAGE.contains("English"));
        assert!(PAGE.contains("简体中文"));
        assert!(PAGE.contains("繁體中文"));
        assert!(PAGE.contains("applyLanguage"));
    }

    #[tokio::test]
    async fn refuses_an_ephemeral_port_that_cannot_be_announced() {
        assert!(serve(0).await.is_err());
    }
}
