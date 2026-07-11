# -*- coding: utf-8 -*-
"""產出可列印/存證的 HTML 鑑識報告。"""
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


def _esc(x) -> str:
    return html.escape(str(x)) if x is not None else "—"


def build_html(result: dict, querier: str = "", case_no: str = "") -> str:
    ip = result["ip"]
    rdap = result["rdap"]
    bgp = result["bgp"]
    rpki = result["rpki"]
    a = result["assessment"]
    verdict = a["verdict"]
    v_title, v_desc = _VERDICT_TEXT.get(verdict, ("未定性", ""))

    # 路由重疊表
    rows = ""
    for i, r in enumerate(bgp.get("routes", [])):
        tag = "🎯 最精準（實體流量去向）" if i == 0 else "包含關係（較大網段）"
        cls = "lpm" if i == 0 else ""
        rows += (f"<tr class='{cls}'><td><code>{_esc(r['prefix'])}</code></td>"
                 f"<td>AS{_esc(r['asn'])}</td><td>{_esc(r['holder'])}</td>"
                 f"<td>{_esc(r['num_addresses'])}</td><td>{tag}</td></tr>")
    if not rows:
        rows = "<tr><td colspan='5'>查無即時 BGP 宣告</td></tr>"

    # 發文建議
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

    # 機房 / VPN / Proxy 區塊
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
    return f"""<!DOCTYPE html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<title>IP 溯源鑑識報告 {_esc(ip)}</title>
<style>
  body{{font-family:"Microsoft JhengHei","Noto Sans TC",sans-serif;margin:2.5rem auto;max-width:900px;color:#222;line-height:1.6}}
  h1{{font-size:1.4rem;border-bottom:3px solid #1a3c6e;padding-bottom:.4rem}}
  h2{{font-size:1.1rem;color:#1a3c6e;margin-top:1.8rem;border-left:5px solid #1a3c6e;padding-left:.5rem}}
  table{{border-collapse:collapse;width:100%;margin:.6rem 0;font-size:.92rem}}
  th,td{{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}}
  th{{background:#1a3c6e;color:#fff}}
  tr.lpm{{background:#fff3cd;font-weight:bold}}
  code{{background:#eef;padding:.1rem .3rem;border-radius:3px}}
  .meta{{color:#666;font-size:.85rem}}
  .verdict{{padding:.8rem 1rem;border-radius:6px;margin:1rem 0;font-size:1.05rem}}
  .SUBLEASE{{background:#f8d7da;border:1px solid #dc3545}}
  .HIJACK_SUSPECT{{background:#fff3cd;border:1px solid #ffc107}}
  .CONSISTENT,.NO_BGP{{background:#d1e7dd;border:1px solid #198754}}
  .advice{{background:#f6f8fa;border:1px solid #ddd;border-radius:6px;padding:.6rem 1rem;margin-top:.6rem}}
  .kv td:first-child{{width:32%;background:#f2f5fa;font-weight:bold}}
  .badge{{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.85rem;font-weight:bold}}
  .rpki-valid{{background:#d1e7dd;color:#0f5132}} .rpki-invalid{{background:#f8d7da;color:#842029}}
  .rpki-unknown{{background:#e2e3e5;color:#41464b}}
  .risk-HIGH{{background:#f8d7da;color:#842029}} .risk-MEDIUM{{background:#fff3cd;color:#664d03}}
  .risk-LOW{{background:#d1e7dd;color:#0f5132}}
  footer{{margin-top:2rem;font-size:.8rem;color:#888;border-top:1px solid #ddd;padding-top:.6rem}}
</style></head><body>
<h1>🔍 科偵 IP 智慧溯源鑑識報告</h1>
<p class="meta">涉案 IP：<b>{_esc(ip)}</b>　｜　案號：{_esc(case_no) or "—"}　｜　查詢人：{_esc(querier) or "—"}<br>
產製時間：{now}　｜　路由基準時間：{_esc(bgp.get('timestamp'))}</p>

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
</body></html>"""
