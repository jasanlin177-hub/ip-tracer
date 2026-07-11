# -*- coding: utf-8 -*-
"""
批次查詢：一次分析多個 IP，輸出彙整表 / CSV / HTML。

節流：ip-api.com 免費限 45 次/分，故每顆 IP 間預設 sleep，避免被擋。
去重：相同 IP 只查一次；ASN 持有人查詢在 tracer 內已快取。
"""
from __future__ import annotations
import re
import io
import csv
import time
from typing import Optional, Callable

import tracer

# 從任意文字抽出 IPv4 / IPv6（支援換行、逗號、分號、空白混雜貼上）
_IP_TOKEN = re.compile(r"[0-9a-fA-F:.]+")


def parse_ips(text: str) -> list[str]:
    """從貼上的文字抽出合法且不重複的 IP（保留輸入順序）。"""
    seen, out = set(), []
    for tok in _IP_TOKEN.findall(text or ""):
        tok = tok.strip(".:")
        try:
            ip = tracer.validate_ip(tok)
        except ValueError:
            continue
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def analyze_batch(ips: list[str], timestamp: Optional[str] = None,
                  ip2proxy_key: Optional[str] = None, throttle: float = 1.2,
                  progress: Optional[Callable[[int, int, str], None]] = None) -> list[dict]:
    """
    逐一分析。單顆失敗不中斷整批，記錄 error。
    progress(done, total, ip) 供 UI 更新進度條。
    """
    results = []
    total = len(ips)
    for i, ip in enumerate(ips, 1):
        try:
            r = tracer.analyze(ip, timestamp=timestamp, ip2proxy_key=ip2proxy_key)
            r["error"] = None
        except Exception as e:
            r = {"ip": ip, "error": str(e), "assessment": {}, "proxy": {}}
        results.append(r)
        if progress:
            progress(i, total, ip)
        if throttle and i < total:
            time.sleep(throttle)
    return results


def to_rows(results: list[dict]) -> list[dict]:
    """壓成彙整表用的扁平 row。"""
    rows = []
    for r in results:
        a = r.get("assessment", {}) or {}
        p = r.get("proxy", {}) or {}
        rows.append({
            "IP": r.get("ip"),
            "定性": a.get("verdict") or ("ERROR" if r.get("error") else "-"),
            "大房東(RDAP)": a.get("legal_owner"),
            "國家": a.get("legal_country"),
            "二房東(BGP)": a.get("bgp_holder"),
            "最精準網段": a.get("bgp_prefix"),
            "ASN": f"AS{a.get('bgp_asn')}" if a.get("bgp_asn") else None,
            "RPKI": a.get("rpki_status"),
            "機房風險": p.get("risk_level"),
            "備註": r.get("error") or "",
        })
    return rows


def to_csv(results: list[dict]) -> str:
    rows = to_rows(results)
    buf = io.StringIO()
    if rows:
        w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    return buf.getvalue()


_VERDICT_ZH = {
    "SUBLEASE": "分租(大≠二房東)", "HIJACK_SUSPECT": "疑似路由劫持",
    "CONSISTENT": "產權路由一致", "NO_BGP": "查無BGP", "ERROR": "查詢失敗",
}


def to_html(results: list[dict]) -> str:
    """批次彙整 HTML 報告（含統計摘要 + 明細表）。"""
    import html as _h
    import datetime as _dt
    rows = to_rows(results)

    # 摘要統計
    n = len(rows)
    n_sub = sum(1 for r in rows if r["定性"] == "SUBLEASE")
    n_hij = sum(1 for r in rows if r["定性"] == "HIJACK_SUSPECT")
    n_err = sum(1 for r in rows if r["定性"] == "ERROR")
    n_highrisk = sum(1 for r in rows if r["機房風險"] == "HIGH")

    def esc(x):
        return _h.escape(str(x)) if x not in (None, "") else "—"

    tr = ""
    for r in rows:
        v = r["定性"]
        cls = {"SUBLEASE": "v-sub", "HIJACK_SUSPECT": "v-hij",
               "ERROR": "v-err"}.get(v, "")
        risk = r["機房風險"] or "—"
        rcls = {"HIGH": "r-h", "MEDIUM": "r-m", "LOW": "r-l"}.get(risk, "")
        tr += (f"<tr class='{cls}'><td><code>{esc(r['IP'])}</code></td>"
               f"<td>{_VERDICT_ZH.get(v, esc(v))}</td>"
               f"<td>{esc(r['大房東(RDAP)'])}</td><td>{esc(r['國家'])}</td>"
               f"<td>{esc(r['二房東(BGP)'])}</td>"
               f"<td><code>{esc(r['最精準網段'])}</code></td><td>{esc(r['ASN'])}</td>"
               f"<td>{esc(r['RPKI'])}</td>"
               f"<td class='{rcls}'>{esc(risk)}</td><td>{esc(r['備註'])}</td></tr>")

    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!DOCTYPE html><html lang="zh-Hant"><head><meta charset="utf-8">
<title>IP 批次溯源彙整報告</title><style>
 body{{font-family:"Georgia","Noto Serif TC","Microsoft JhengHei",serif;margin:2rem auto;max-width:1100px;color:#2b2b2b;background:#f7f3ea}}
 .doc{{background:#fdfbf6;border:1px solid #e2d8c6;padding:1.8rem 2rem;box-shadow:0 1px 4px rgba(0,0,0,.06)}}
 .hd{{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid #1e3a5f;padding-bottom:.6rem;margin-bottom:.4rem}}
 h1{{font-size:1.3rem;color:#1e3a5f;margin:0;letter-spacing:1px;font-weight:700}}
 .seal{{width:48px;height:48px;border:2px solid #b23a2e;color:#b23a2e;border-radius:6px;display:flex;
   align-items:center;justify-content:center;font-weight:700;font-size:14px;transform:rotate(-8deg);flex-shrink:0}}
 .cards{{display:flex;gap:12px;flex-wrap:wrap;margin:1rem 0}}
 .card{{background:#f2ece0;border:1px solid #e2d8c6;border-radius:6px;padding:.6rem 1rem;min-width:120px}}
 .card b{{font-size:1.5rem;display:block;color:#1e3a5f}}
 table{{border-collapse:collapse;width:100%;font-size:.85rem}}
 th,td{{border:1px solid #ddd0bd;padding:.35rem .5rem;text-align:left}}
 th{{background:#1e3a5f;color:#fff;position:sticky;top:0;font-weight:600}}
 code{{background:#efe9db;padding:.05rem .3rem;border-radius:3px;font-family:Consolas,monospace}}
 .v-sub{{background:#f5e3d0}} .v-hij{{background:#f7ecd6}} .v-err{{background:#eae4d7;color:#8a7a66}}
 .r-h{{color:#8a2a1f;font-weight:bold}} .r-m{{color:#7a5a06;font-weight:bold}} .r-l{{color:#2c5240}}
 .meta{{color:#6b5d4f;font-size:.85rem}} footer{{margin-top:1.5rem;font-size:.8rem;color:#8a7a66;border-top:1px solid #e2d8c6;padding-top:.5rem}}
</style></head><body>
<div class="doc">
<div class="hd">
 <div><h1>科偵 IP 批次溯源彙整報告</h1>
 <p class="meta" style="margin:.4rem 0 0">產製時間：{now}　｜　共 {n} 個 IP</p></div>
 <div class="seal">科偵</div>
</div>
<div class="cards">
 <div class="card"><b>{n}</b>總數</div>
 <div class="card"><b>{n_sub}</b>分租現象</div>
 <div class="card"><b>{n_hij}</b>疑似劫持</div>
 <div class="card"><b>{n_highrisk}</b>機房高風險</div>
 <div class="card"><b>{n_err}</b>查詢失敗</div>
</div>
<table>
<tr><th>IP</th><th>定性</th><th>大房東(RDAP)</th><th>國</th><th>二房東(BGP)</th>
<th>最精準網段</th><th>ASN</th><th>RPKI</th><th>機房風險</th><th>備註</th></tr>
{tr}
</table>
<footer>資料擷取自 ICANN RDAP bootstrap 與 RIPEstat（RIPE NCC）即時 API。BGP 具時效性，辦案請以案發時間點回溯為準。</footer>
</div>
</body></html>"""


if __name__ == "__main__":
    ips = parse_ips("61.111.248.173, 8.8.8.8\n1.1.1.1")
    print("parsed:", ips)
    res = analyze_batch(ips, throttle=0.5)
    print(to_csv(res))
