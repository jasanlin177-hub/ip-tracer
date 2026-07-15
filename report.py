# -*- coding: utf-8 -*-
"""
產出鑑識報告內容（司法公文風）。

`render_content()` 產出「單筆結果」的核心 HTML 片段（標題、定性、RDAP、BGP、機房、發文建議），
`build_html()` 把它包成完整可下載的 HTML 檔。
`ip_analyzer.py` 直接重用同一份 `render_content()` + `STYLE`，讓網頁上的查詢結果
與下載的 HTML 報告永遠是同一套視覺，不會日後改一邊忘了改另一邊。
"""
from __future__ import annotations
import html

import tracer as _tracer

_VERDICT_TEXT = {
    "CDN_FRONTED": ("🛰️ 偵測到 CDN（Content Delivery Network 內容傳遞網路）／反向代理 — 此 IP 非目標網站真實主機",
                    "此 IP 屬於已知 CDN 服務商，網站真正的來源伺服器（origin）藏在其後，"
                    "直接函索此 IP 持有人通常僅能取得 CDN 邊緣節點的連線紀錄，查不到真正機房。"),
    "SUBLEASE": ("發現「大房東／二房東」分租現象",
                 "嫌犯實質向二房東租用伺服器作為犯罪跳板，該網段法律上仍歸屬大房東。"),
    "HIJACK_SUSPECT": ("⚠️ RPKI 驗證為 Invalid — 疑似路由劫持",
                       "BGP 宣告與 ROA 不符，路由來源可能遭偽造，證據力應以 RDAP 產權為準。"),
    "CONSISTENT": ("產權與路由一致",
                   "該 IP 由法定所有人直接營運，未發現分租或流量清洗。"),
    "NO_BGP": ("查無即時 BGP 宣告",
               "RIS 收集器未見該 IP 的路由宣告，請以 RDAP 產權登記為主。"),
}

# 司法公文風共用樣式：ip_analyzer.py 與 build_html() 都注入這份，確保工具介面／報告視覺一致
STYLE = """
  .doc-wrap{font-family:"Georgia","Noto Serif TC","Microsoft JhengHei",serif;color:#2b2b2b;line-height:1.7}
  .doc{background:#fdfbf6;border:1px solid #e2d8c6;padding:1.6rem 1.9rem;box-shadow:0 1px 4px rgba(0,0,0,.06);margin-bottom:1.2rem}
  .doc .hd{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid #1e3a5f;padding-bottom:.6rem}
  .doc h1{font-size:1.3rem;color:#1e3a5f;margin:0;letter-spacing:1px;font-weight:700}
  .doc .seal{width:48px;height:48px;border:2px solid #b23a2e;color:#b23a2e;border-radius:6px;display:flex;
    align-items:center;justify-content:center;font-weight:700;font-size:14px;transform:rotate(-8deg);flex-shrink:0}
  .doc h2{font-size:1.04rem;color:#1e3a5f;margin:1.6rem 0 .6rem;border-left:4px solid #1e3a5f;padding-left:.6rem;letter-spacing:.5px}
  .doc .target{font-size:1.15rem;font-weight:700;color:#1e3a5f;margin:.5rem 0 .3rem;letter-spacing:.3px}
  .doc .target b{color:#b23a2e;font-size:1.2rem}
  .doc table{border-collapse:collapse;width:100%;margin:.5rem 0;font-size:.9rem}
  .doc th,.doc td{border:1px solid #ddd0bd;padding:.4rem .6rem;text-align:left}
  .doc th{background:#1e3a5f;color:#fff;font-weight:600}
  .doc tr.lpm{background:#f5e3d0;font-weight:bold}
  .doc code{background:#efe9db;padding:.1rem .35rem;border-radius:3px;font-family:Consolas,monospace}
  .doc .meta{color:#6b5d4f;font-size:.83rem}
  .doc .verdict{padding:.75rem 1.05rem;border-radius:4px;margin:.9rem 0;font-size:1rem;border-left:5px solid}
  .doc .CDN_FRONTED{background:#e8dff0;border-color:#6b3fa0;color:#4a2470}
  .doc .SUBLEASE{background:#f5e3d0;border-color:#b23a2e;color:#8a2a1f}
  .doc .HIJACK_SUSPECT{background:#f7ecd6;border-color:#b8860b;color:#7a5a06}
  .doc .CONSISTENT,.doc .NO_BGP{background:#e6ece3;border-color:#3a6b4f;color:#2c5240}
  .doc .advice{background:#faf6ec;border:1px solid #e2d8c6;border-left:4px solid #1e3a5f;padding:.6rem 1rem;margin-top:.5rem}
  .doc .advice.sublease{border-left-color:#b23a2e} .doc .advice.hijack{border-left-color:#b8860b}
  .doc .advice.cdn{border-left-color:#6b3fa0}
  .doc .kv td:first-child{width:32%;background:#f2ece0;font-weight:bold;color:#1e3a5f}
  .doc .badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.83rem;font-weight:bold}
  .doc .rpki-valid{background:#e6ece3;color:#2c5240} .doc .rpki-invalid{background:#f5e3d0;color:#8a2a1f}
  .doc .rpki-unknown{background:#eae4d7;color:#5a5044}
  .doc .risk-HIGH{background:#f5e3d0;color:#8a2a1f} .doc .risk-MEDIUM{background:#f7ecd6;color:#7a5a06}
  .doc .risk-LOW{background:#e6ece3;color:#2c5240}
  .doc footer{margin-top:1.5rem;font-size:.78rem;color:#8a7a66;border-top:1px solid #e2d8c6;padding-top:.5rem}
  .doc .srclinks{display:flex;gap:.6rem;flex-wrap:wrap;margin:.5rem 0}
  .doc .srclinks a{display:inline-block;background:#f2ece0;border:1px solid #ddd0bd;border-radius:4px;
    padding:.35rem .8rem;font-size:.85rem;color:#1e3a5f;text-decoration:none;font-weight:600}
  .doc .srclinks a:hover{background:#e6ddc9}
  .doc .glossary{font-size:.83rem;color:#5a5044}
  .doc .glossary td{padding:.3rem .5rem;vertical-align:top}
  .doc .glossary td:first-child{width:24%;font-weight:bold;color:#1e3a5f;white-space:nowrap}
"""


# 名詞說明：給非網路背景同仁看懂報告中的專有名詞（中英全名 + 白話）
_GLOSSARY = [
    ("RDAP", "Registration Data Access Protocol，註冊資料存取協定。查 IP／網域「登記給誰」的官方資料，等同數位產權證明。"),
    ("BGP", "Border Gateway Protocol，邊界閘道協定。網路實際「把流量送到哪」的路由宣告，等同機房招牌。"),
    ("LPM", "Longest Prefix Match，最精準比對優先。同一 IP 對到多個網段時，取斜線數字最大（範圍最小）者為實際流量去向。"),
    ("RPKI／ROA", "Resource Public Key Infrastructure／Route Origin Authorization，資源公鑰基礎建設／路由起源授權。以密碼學驗證某網段是否確由合法 ASN 宣告，可偵測路由劫持。"),
    ("ASN", "Autonomous System Number，自治系統編號。一個網路營運者（電信商、機房）在全球網路的身分編號。"),
    ("CDN", "Content Delivery Network，內容傳遞網路。擋在網站前面的代理／加速服務（如 Cloudflare），會遮蔽真實主機。"),
    ("Origin IP", "真實來源 IP。網站真正架設的主機 IP，藏在 CDN 之後。"),
    ("Proxy／VPN", "代理伺服器／虛擬私人網路。可隱藏真實連線來源，常用於規避追查。"),
]


def _esc(x) -> str:
    return html.escape(str(x)) if x is not None else "—"


def render_origin_section(hunt: dict) -> str:
    """把 origin IP 追查結果（origin_finder.find_origin_candidates 的回傳）渲染成報告區塊。"""
    if not hunt:
        return ""
    cands = hunt.get("candidates", [])
    non_cdn = hunt.get("non_cdn_candidates", [])

    status = (
        f"子網域枚舉（crt.sh）："
        f"{'成功，' + str(len(hunt.get('subdomains', []))) + ' 個' if hunt.get('crtsh_ok') else '❌ 服務暫時無法連線，略過'}"
        f"　｜　歷史 DNS（OTX）："
        f"{'成功，' + str(hunt.get('passive_dns_count', 0)) + ' 筆' if hunt.get('otx_ok') else '❌ 查詢失敗'}"
    )

    rows = ""
    for c in cands:
        cdn = c.get("cdn_name")
        judge = _esc(cdn) if cdn else "🎯 非 CDN（可疑候選）"
        cls = "" if cdn else "lpm"
        hosts = "、".join(c.get("hostnames", [])[:3])
        if len(c.get("hostnames", [])) > 3:
            hosts += "…"
        rows += (
            f"<tr class='{cls}'><td><code>{_esc(c.get('ip'))}</code></td>"
            f"<td>{('AS' + _esc(c.get('asn'))) if c.get('asn') else '—'}</td>"
            f"<td>{judge}</td><td>{_esc(hosts)}</td>"
            f"<td>{_esc('、'.join(c.get('source', [])))}</td>"
            f"<td>{_esc((c.get('first_seen') or '—')[:10])}</td>"
            f"<td>{_esc((c.get('last_seen') or '—')[:10])}</td></tr>"
        )
    if not rows:
        rows = "<tr><td colspan='7'>未找到任何候選 IP</td></tr>"

    if non_cdn:
        concl = ("<p><b>研判：</b>上表標記為「🎯 非 CDN」者，為未受 CDN 保護、"
                 "疑似真實來源主機之候選 IP，應優先對其重新執行完整分析並保全事證。</p>")
    else:
        concl = ("<p><b>研判：</b>本次找到的候選 IP 皆屬已知 CDN，尚未發現明顯洩漏的真實主機；"
                 "建議改以正式公文向 CDN 業者調取 origin IP，或稍後重試（外部服務常暫時性失效）。</p>")

    domain = hunt.get("domain", "")
    srclinks = (
f"""<div class="srclinks">
<a href="https://crt.sh/?q={_esc(domain)}" target="_blank" rel="noopener">🔍 crt.sh 憑證紀錄</a>
<a href="https://otx.alienvault.com/indicator/hostname/{_esc(domain)}" target="_blank" rel="noopener">🔍 OTX 歷史 DNS</a>
</div>""")

    return (
f"""<h2>🔍 真實來源 IP（origin IP，藏在 CDN 內容傳遞網路後方的網站真正主機）追查</h2>
<p class="meta">{status}　｜　資料源皆為免金鑰公開服務，非百分之百完整，僅供辦案線索參考。</p>
<table>
<tr><th>候選 IP</th><th>ASN</th><th>CDN 判定</th><th>來源子網域</th><th>資料來源</th><th>首次出現</th><th>最後出現</th></tr>
{rows}
</table>
{concl}
<p class="meta">🔗 原始工具查證（開新分頁自行比對）：</p>
{srclinks}""")


def render_content(result: dict, origin_hunt: dict = None, domain: str = None) -> str:
    """
    回傳單筆查詢結果的 <div class="doc">…</div> 片段（不含 <html>/<style>）。
    origin_hunt：若有做過 origin IP 追查（CDN 遮蔽案件），一併寫進報告。
    domain：若使用者一開始輸入的是網址／網域（而非直接輸入 IP），一併記錄於報告標頭，
            完整留下「網域 → 解析 IP」的偵查鏈路，避免存證時只剩 IP、遺失原始查緝目標。
    """
    ip = result["ip"]
    rdap = result["rdap"]
    bgp = result["bgp"]
    rpki = result["rpki"]
    a = result["assessment"]
    verdict = a["verdict"]
    v_title, v_desc = _VERDICT_TEXT.get(verdict, ("未定性", ""))

    rows = ""
    for i, r in enumerate(bgp.get("routes", [])):
        tag = "🎯 最精準（實體流量去向）" if i == 0 else "包含關係（較大網段）"
        cls = "lpm" if i == 0 else ""
        rows += (f"<tr class='{cls}'><td><code>{_esc(r['prefix'])}</code></td>"
                 f"<td>AS{_esc(r['asn'])}</td><td>{_esc(r['holder'])}</td>"
                 f"<td>{_esc(r['num_addresses'])}</td><td>{tag}</td></tr>")
    if not rows:
        rows = "<tr><td colspan='5'>查無即時 BGP 宣告</td></tr>"

    if verdict == "CDN_FRONTED":
        cdn_name = a.get("cdn_name") or "CDN 業者"
        advice = (
f"""<div class="advice cdn">
<p><b>此 IP 為 CDN／反向代理（{_esc(cdn_name)}），並非目標網站真實主機：</b></p>
<ol>
<li>直接函索 <b>{_esc(a['legal_owner'])}</b>（{_esc(cdn_name)}）僅能取得 CDN 邊緣節點的連線紀錄，
<b>無法取得網站真正架設之機房或使用者資料</b>。</li>
<li><b>正確作法</b>：以正式公文向 {_esc(cdn_name)} 調取該網域／該次連線之
<b>真實來源伺服器 IP（Origin IP）</b>及對應時間戳。取得 origin IP 後，
<b>重新對該 IP 執行本系統分析</b>，才能鎖定實際機房與二房東。</li>
<li>亦可嘗試：歷史 DNS 紀錄（查該網域套用 CDN 前是否曾指向真實 IP）、
SSL 憑證透明度紀錄（crt.sh）、網站原始碼是否洩漏 origin IP（如子網域未套 CDN）等輔助技巧。</li>
</ol>
</div>""")
    elif verdict == "SUBLEASE":
        abuse_line = (f"Abuse 聯絡：<code>{_esc(a['abuse_email'])}</code>") if a.get('abuse_email') else ""
        advice = (
f"""<div class="advice sublease">
<p><b>建議調閱步驟（雙重發文）：</b></p>
<ol>
<li><b>函索大房東 — {_esc(a['legal_owner'])}</b>（{_esc(a.get('legal_country'))}）：
請出具案發時間點該網段 <code>{_esc(a['bgp_prefix'])}</code> 租賃／分租給下游機房之
<b>正式合約與分租證明文件</b>，建立法定證據鏈並實錘二房東管轄權。
{abuse_line}</li>
<li><b>函索二房東 — {_esc(a['bgp_holder'])}</b>（AS{_esc(a['bgp_asn'])}）：
同步函索該 IP 於案發時間點之 <b>VPS 租用者個資、登入日誌(Log)、金流來源</b>。</li>
</ol>
</div>""")
    elif verdict == "HIJACK_SUSPECT":
        advice = (
f"""<div class="advice hijack">
<p><b>⚠️ RPKI=Invalid，BGP 招牌可能造假：</b></p>
<ol>
<li>證據力<b>優先採 RDAP 產權登記</b>（{_esc(a['legal_owner'])}），BGP origin 存疑。</li>
<li>函索法定所有人查證是否曾授權(LOA) AS{_esc(a['bgp_asn'])} 宣告該網段。</li>
<li>保全 RIS/looking-glass 之路由宣告時間軸，作為劫持事證。</li>
</ol>
</div>""")
    else:
        abuse_line = (f"Abuse 聯絡：<code>{_esc(a['abuse_email'])}</code>") if a.get('abuse_email') else ""
        advice = (
f"""<div class="advice consistent">
<p><b>建議：</b>直接函索 <b>{_esc(a['legal_owner'])}</b> 調閱使用者個資與連線紀錄。
{abuse_line}</p>
</div>""")

    pinfo = result.get("proxy") or {}
    p_risk = pinfo.get("risk_level", "LOW")
    p_signals = pinfo.get("signals", [])
    _risk_label = {"HIGH": "🔴 高（Proxy/VPN/防彈機房疑慮）",
                   "MEDIUM": "🟠 中（機房/代管託管）",
                   "LOW": "🟢 低（未見機房/代理特徵）"}.get(p_risk, p_risk)
    sig_html = "".join(f"<li>{_esc(s)}</li>" for s in p_signals) or "<li>—（各來源均未觸發特徵）</li>"
    proxy_html = f"""
<h2>🛡️ 機房 / VPN（虛擬私人網路）/ Proxy（代理伺服器）屬性判定</h2>
<p>綜合風險：<span class="badge risk-{p_risk}">{_risk_label}</span></p>
<p>觸發訊號：</p><ul>{sig_html}</ul>
<p class="meta">來源：IP2Location.io（IP2Proxy）× ip-api.com × ASN 關鍵字/BGP 結構啟發式。
註：商用黑名單對「新租用之廉價機房 VPS」常標為未偵測，故本項以多訊號綜合研判，
LOW 不代表必非機房，仍應併同 RDAP/BGP 分租結構判讀。</p>
"""

    origin_html = render_origin_section(origin_hunt) if origin_hunt else ""

    glossary_rows = "".join(
        f"<tr><td>{_esc(term)}</td><td>{_esc(desc)}</td></tr>" for term, desc in _GLOSSARY)
    glossary_html = (
        '<h2>📖 名詞說明（給非網路背景同仁）</h2>'
        f'<table class="glossary">{glossary_rows}</table>'
    )

    # 台灣 IP 公司登記（方便製作公文）
    ctw = result.get("company_tw")
    if ctw:
        _addr = ctw.get("address")
        company_html = (
f"""<h2>🏢 台灣公司登記資訊（供製作公文參考）</h2>
<table class="kv">
<tr><td>中文名稱</td><td><b style="font-size:1.1rem;color:#b23a2e">{_esc(ctw.get('chinese_name'))}</b></td></tr>
<tr><td>英文名稱</td><td>{_esc(ctw.get('org_name'))}</td></tr>
<tr><td>登記地址</td><td>{_esc(_addr)}</td></tr>
<tr><td>網路名稱</td><td><code>{_esc(ctw.get('netname'))}</code></td></tr>
</table>
<p class="meta">資料來源：TWNIC（台灣網路資訊中心）IP 登記資料。此為<b>網路區段登記之公司</b>，
未必等同實際使用者；電話未收錄於此資料庫，請以下方連結至商工登記查詢。</p>
<div class="srclinks">
<a href="https://findbiz.nat.gov.tw/fts/query/QueryList/queryList.do?qryCond={_esc(ctw.get('org_name') or '')}" target="_blank" rel="noopener">🏢 經濟部商工登記查詢（查統編/電話/負責人）</a>
<a href="https://rms.twnic.tw/query_whois1.php" target="_blank" rel="noopener">🌐 TWNIC 原始查詢（自行核對）</a>
</div>""")
    else:
        company_html = ""

    target_line = (
        f'<p class="target">涉案網域：<b>{_esc(domain)}</b>　→　解析 IP：<b>{_esc(ip)}</b></p>'
        if domain else
        f'<p class="target">涉案 IP：<b>{_esc(ip)}</b></p>'
    )

    now = _tracer.now_tw().strftime("%Y-%m-%d %H:%M:%S") + "（UTC+8）"
    return f"""<div class="doc">
<div class="hd">
  <div><h1>科偵 IP 智慧溯源鑑識報告</h1>
  {target_line}
  <p class="meta" style="margin:.2rem 0 0">產製時間：{now}　｜　路由基準時間：{_esc(bgp.get('timestamp'))}</p></div>
  <div class="seal">科偵</div>
</div>

<div class="verdict {verdict}"><b>偵查定性：{v_title}</b><br>{v_desc}</div>

<h2>📜 RDAP（Registration Data Access Protocol 註冊資料存取協定）產權證明（法定大房東）</h2>
<table class="kv">
<tr><td>法定所有人</td><td>{_esc(rdap.get('name'))}</td></tr>
<tr><td>所屬國家</td><td>{_esc(rdap.get('country'))}</td></tr>
<tr><td>登記網段</td><td><code>{_esc(a.get('registered_block'))}</code>（{_esc(rdap.get('handle'))}）</td></tr>
<tr><td>Abuse 聯絡</td><td>{_esc(rdap.get('abuse_email'))}</td></tr>
<tr><td>資料來源</td><td>{_esc(rdap.get('raw_source'))}</td></tr>
</table>
{company_html}
<h2>🪧 BGP（Border Gateway Protocol 邊界閘道協定）實體路由（最精準二房東）＋ 重疊網段拆解</h2>
<p>已套用 <b>最精準比對優先（Longest Prefix Match，LPM）</b>，斜線數字越大者優先：</p>
<table>
<tr><th>網段</th><th>Origin ASN</th><th>ASN 持有人</th><th>涵蓋 IP 數</th><th>研判</th></tr>
{rows}
</table>
<p>RPKI（Resource Public Key Infrastructure 資源公鑰基礎建設）ROA 驗證（{_esc(a.get('bgp_prefix'))} × AS{_esc(a.get('bgp_asn'))}）：
<span class="badge rpki-{_esc(rpki.get('status'))}">{_esc(rpki.get('status','unknown')).upper()}</span>
　<span class="meta">valid=已授權可信／invalid=疑似劫持／unknown=無 ROA 無法驗證</span></p>
{proxy_html}
<h2>🔗 原始工具查證連結</h2>
<p class="meta">以上為系統自動整合研判，若需自行比對原始資料來源存證，可點選以下官方查詢頁面（會開新分頁，帶入本次查詢的 IP／網段）：</p>
<div class="srclinks">
<a href="https://rdap.org/ip/{_esc(ip)}" target="_blank" rel="noopener">📜 RDAP 原始資料（rdap.org）</a>
<a href="https://lookup.icann.org/en/lookup" target="_blank" rel="noopener">📜 ICANN RDAP Lookup（需自行貼上 IP）</a>
{"<a href='https://bgp.tools/prefix/" + _esc(a['bgp_prefix']) + "' target='_blank' rel='noopener'>🪧 bgp.tools 路由查詢</a>" if a.get('bgp_prefix') else ""}
<a href="https://www.ip2proxy.com/zh_tw/demo" target="_blank" rel="noopener">🛡️ IP2Proxy 快查（需自行貼上 IP）</a>
</div>

<h2>🚨 科技偵查發文調閱建議</h2>
{advice}
{origin_html}
{glossary_html}
<footer>
本報告由「科偵 IP 智慧溯源分析系統」自動產製，資料擷取自 ICANN RDAP bootstrap 與 RIPEstat（RIPE NCC）即時 API。
BGP 路由狀態具時效性，正式辦案請以案發時間點之路由回溯資料為準，並保全原始 API 回應。
</footer>
</div>"""


def build_html(result: dict, origin_hunt: dict = None, domain: str = None) -> str:
    ip = result["ip"]
    title = f"{domain}（{ip}）" if domain else ip
    return f"""<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>IP 溯源鑑識報告 {_esc(title)}</title>
<style>
  body{{margin:2.5rem auto;max-width:900px;background:#f7f3ea}}
  {STYLE}
</style></head><body class="doc-wrap">
{render_content(result, origin_hunt=origin_hunt, domain=domain)}
</body></html>"""
