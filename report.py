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
import datetime as _dt

_VERDICT_TEXT = {
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
  .doc table{border-collapse:collapse;width:100%;margin:.5rem 0;font-size:.9rem}
  .doc th,.doc td{border:1px solid #ddd0bd;padding:.4rem .6rem;text-align:left}
  .doc th{background:#1e3a5f;color:#fff;font-weight:600}
  .doc tr.lpm{background:#f5e3d0;font-weight:bold}
  .doc code{background:#efe9db;padding:.1rem .35rem;border-radius:3px;font-family:Consolas,monospace}
  .doc .meta{color:#6b5d4f;font-size:.83rem}
  .doc .verdict{padding:.75rem 1.05rem;border-radius:4px;margin:.9rem 0;font-size:1rem;border-left:5px solid}
  .doc .SUBLEASE{background:#f5e3d0;border-color:#b23a2e;color:#8a2a1f}
  .doc .HIJACK_SUSPECT{background:#f7ecd6;border-color:#b8860b;color:#7a5a06}
  .doc .CONSISTENT,.doc .NO_BGP{background:#e6ece3;border-color:#3a6b4f;color:#2c5240}
  .doc .advice{background:#faf6ec;border:1px solid #e2d8c6;border-left:4px solid #1e3a5f;padding:.6rem 1rem;margin-top:.5rem}
  .doc .advice.sublease{border-left-color:#b23a2e} .doc .advice.hijack{border-left-color:#b8860b}
  .doc .kv td:first-child{width:32%;background:#f2ece0;font-weight:bold;color:#1e3a5f}
  .doc .badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.83rem;font-weight:bold}
  .doc .rpki-valid{background:#e6ece3;color:#2c5240} .doc .rpki-invalid{background:#f5e3d0;color:#8a2a1f}
  .doc .rpki-unknown{background:#eae4d7;color:#5a5044}
  .doc .risk-HIGH{background:#f5e3d0;color:#8a2a1f} .doc .risk-MEDIUM{background:#f7ecd6;color:#7a5a06}
  .doc .risk-LOW{background:#e6ece3;color:#2c5240}
  .doc footer{margin-top:1.5rem;font-size:.78rem;color:#8a7a66;border-top:1px solid #e2d8c6;padding-top:.5rem}
"""


def _esc(x) -> str:
    return html.escape(str(x)) if x is not None else "—"


def render_content(result: dict) -> str:
    """回傳單筆查詢結果的 <div class="doc">…</div> 片段（不含 <html>/<style>）。"""
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

    if verdict == "SUBLEASE":
        advice = f"""
        <div class="advice sublease">
          <p><b>建議調閱步驟（雙重發文）：</b></p>
          <ol>
            <li><b>函索大房東 — {_esc(a['legal_owner'])}</b>（{_esc(a.get('legal_country'))}）：
                請出具案發時間點該網段 <code>{_esc(a['bgp_prefix'])}</code> 租賃／分租給下游機房之
                <b>正式合約與分租證明文件</b>，建立法定證據鏈並實錘二房東管轄權。
                {("Abuse 聯絡：<code>"+_esc(a['abuse_email'])+"</code>") if a.get('abuse_email') else ""}</li>
            <li><b>函索二房東 — {_esc(a['bgp_holder'])}</b>（AS{_esc(a['bgp_asn'])}）：
                同步函索該 IP 於案發時間點之 <b>VPS 租用者個資、登入日誌(Log)、金流來源</b>。</li>
          </ol>
        </div>"""
    elif verdict == "HIJACK_SUSPECT":
        advice = f"""
        <div class="advice hijack">
          <p><b>⚠️ RPKI=Invalid，BGP 招牌可能造假：</b></p>
          <ol>
            <li>證據力<b>優先採 RDAP 產權登記</b>（{_esc(a['legal_owner'])}），BGP origin 存疑。</li>
            <li>函索法定所有人查證是否曾授權(LOA) AS{_esc(a['bgp_asn'])} 宣告該網段。</li>
            <li>保全 RIS/looking-glass 之路由宣告時間軸，作為劫持事證。</li>
          </ol>
        </div>"""
    else:
        advice = f"""
        <div class="advice consistent">
          <p><b>建議：</b>直接函索 <b>{_esc(a['legal_owner'])}</b> 調閱使用者個資與連線紀錄。
          {("Abuse 聯絡：<code>"+_esc(a['abuse_email'])+"</code>") if a.get('abuse_email') else ""}</p>
        </div>"""

    pinfo = result.get("proxy") or {}
    p_risk = pinfo.get("risk_level", "LOW")
    p_signals = pinfo.get("signals", [])
    _risk_label = {"HIGH": "🔴 高（Proxy/VPN/防彈機房疑慮）",
                   "MEDIUM": "🟠 中（機房/代管託管）",
                   "LOW": "🟢 低（未見機房/代理特徵）"}.get(p_risk, p_risk)
    sig_html = "".join(f"<li>{_esc(s)}</li>" for s in p_signals) or "<li>—（各來源均未觸發特徵）</li>"
    proxy_html = f"""
<h2>🛡️ 機房 / VPN / Proxy 屬性判定</h2>
<p>綜合風險：<span class="badge risk-{p_risk}">{_risk_label}</span></p>
<p>觸發訊號：</p><ul>{sig_html}</ul>
<p class="meta">來源：IP2Location.io（IP2Proxy）× ip-api.com × ASN 關鍵字/BGP 結構啟發式。
註：商用黑名單對「新租用之廉價機房 VPS」常標為未偵測，故本項以多訊號綜合研判，
LOW 不代表必非機房，仍應併同 RDAP/BGP 分租結構判讀。</p>
"""

    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<div class="doc">
<div class="hd">
  <div><h1>科偵 IP 智慧溯源鑑識報告</h1>
  <p class="meta" style="margin:.4rem 0 0">涉案 IP：<b>{_esc(ip)}</b>　｜　產製時間：{now}　｜　路由基準時間：{_esc(bgp.get('timestamp'))}</p></div>
  <div class="seal">科偵</div>
</div>

<div class="verdict {verdict}"><b>偵查定性：{v_title}</b><br>{v_desc}</div>

<h2>📜 RDAP 產權證明（法定大房東）</h2>
<table class="kv">
<tr><td>法定所有人</td><td>{_esc(rdap.get('name'))}</td></tr>
<tr><td>所屬國家</td><td>{_esc(rdap.get('country'))}</td></tr>
<tr><td>登記網段</td><td><code>{_esc(a.get('registered_block'))}</code>（{_esc(rdap.get('handle'))}）</td></tr>
<tr><td>Abuse 聯絡</td><td>{_esc(rdap.get('abuse_email'))}</td></tr>
<tr><td>資料來源</td><td>{_esc(rdap.get('raw_source'))}</td></tr>
</table>

<h2>🪧 BGP 實體路由（最精準二房東）＋ 重疊網段拆解</h2>
<p>已套用 <b>最精準比對優先（Longest Prefix Match）</b>，斜線數字越大者優先：</p>
<table>
<tr><th>網段</th><th>Origin ASN</th><th>ASN 持有人</th><th>涵蓋 IP 數</th><th>研判</th></tr>
{rows}
</table>
<p>RPKI ROA 驗證（{_esc(a.get('bgp_prefix'))} × AS{_esc(a.get('bgp_asn'))}）：
<span class="badge rpki-{_esc(rpki.get('status'))}">{_esc(rpki.get('status','unknown')).upper()}</span>
　<span class="meta">valid=已授權可信／invalid=疑似劫持／unknown=無 ROA 無法驗證</span></p>
{proxy_html}
<h2>🚨 科技偵查發文調閱建議</h2>
{advice}

<footer>
本報告由「科偵 IP 智慧溯源分析系統」自動產製，資料擷取自 ICANN RDAP bootstrap 與 RIPEstat（RIPE NCC）即時 API。
BGP 路由狀態具時效性，正式辦案請以案發時間點之路由回溯資料為準，並保全原始 API 回應。
</footer>
</div>"""


def build_html(result: dict) -> str:
    ip = result["ip"]
    return f"""<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>IP 溯源鑑識報告 {_esc(ip)}</title>
<style>
  body{{margin:2.5rem auto;max-width:900px;background:#f7f3ea}}
  {STYLE}
</style></head><body class="doc-wrap">
{render_content(result)}
</body></html>"""
