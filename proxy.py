# -*- coding: utf-8 -*-
"""
機房 / VPN / Proxy 屬性偵測模組

多來源交叉，避免單一黑名單漏判：
  1. IP2Location.io  官方 IP2Proxy 資料（免金鑰 1000/日；給金鑰可拿 proxy_type/usage_type/threat）
  2. ip-api.com      免費回傳 proxy / hosting / mobile 旗標
  3. ASN 持有人關鍵字啟發式  → 補強「資料庫尚未標記的機房 VPS」

重要認知：商用黑名單對「剛租用的廉價機房 VPS」常標為 False（實測 Moack 即如此），
故本模組以「多訊號 + 啟發式」綜合定性，並誠實標示信心等級。
"""
from __future__ import annotations
from typing import Optional
import requests

UA = {"User-Agent": "KKB-IP-Tracer/1.0 (forensic-use)"}
TIMEOUT = 15

# 機房 / 代管 / VPS 常見關鍵字（出現在 ASN 持有人或 org 名稱時，高度疑似機房）
_DC_KEYWORDS = [
    "hosting", "host", "server", "vps", "cloud", "data center", "datacenter",
    "data-center", "colo", "colocation", "idc", "dedicated", "digital",
    "internet data", "cdn", "network solutions", "telecom cloud",
]
# 防彈機房 / 高風險關鍵字（僅作提示，非定論）
_BULLETPROOF_HINT = ["bulletproof", "offshore", "anonymous", "privacy"]


def _get_json(url: str, params: Optional[dict] = None) -> dict:
    r = requests.get(url, params=params, headers=UA, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


# --------------------------------------------------------------------------- #
# 來源 1：IP2Location.io（IP2Proxy）
# --------------------------------------------------------------------------- #
def query_ip2location(ip: str, api_key: Optional[str] = None) -> dict:
    params = {"ip": ip}
    if api_key:
        params["key"] = api_key
    try:
        d = _get_json("https://api.ip2location.io/", params)
        return {
            "ok": True,
            "is_proxy": d.get("is_proxy"),
            "proxy_type": (d.get("proxy") or {}).get("proxy_type") if isinstance(d.get("proxy"), dict) else d.get("proxy_type"),
            "usage_type": (d.get("proxy") or {}).get("usage_type") if isinstance(d.get("proxy"), dict) else d.get("usage_type"),
            "threat": (d.get("proxy") or {}).get("threat") if isinstance(d.get("proxy"), dict) else d.get("threat"),
            "as": d.get("as"),
            "note": d.get("message"),  # 免金鑰時的額度提示
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


# --------------------------------------------------------------------------- #
# 來源 2：ip-api.com（proxy / hosting / mobile 旗標）
# --------------------------------------------------------------------------- #
def query_ipapi(ip: str) -> dict:
    try:
        d = _get_json(
            f"http://ip-api.com/json/{ip}",
            {"fields": "status,message,isp,org,as,asname,mobile,proxy,hosting,query"},
        )
        if d.get("status") != "success":
            return {"ok": False, "error": d.get("message", "query failed")}
        return {
            "ok": True,
            "proxy": d.get("proxy"),
            "hosting": d.get("hosting"),
            "mobile": d.get("mobile"),
            "isp": d.get("isp"),
            "org": d.get("org"),
            "as": d.get("as"),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


# --------------------------------------------------------------------------- #
# 來源 3：ASN 持有人關鍵字啟發式
# --------------------------------------------------------------------------- #
def datacenter_heuristic(*names: Optional[str]) -> dict:
    blob = " ".join(n for n in names if n).lower()
    hits = [k for k in _DC_KEYWORDS if k in blob]
    bp_hits = [k for k in _BULLETPROOF_HINT if k in blob]
    return {
        "likely_datacenter": bool(hits),
        "keywords_hit": hits,
        "bulletproof_hint": bp_hits,
    }


# --------------------------------------------------------------------------- #
# 綜合定性
# --------------------------------------------------------------------------- #
def assess_proxy(ip: str, bgp_holder: Optional[str] = None,
                 rdap_name: Optional[str] = None,
                 api_key: Optional[str] = None,
                 is_sublease: bool = False) -> dict:
    """
    回傳綜合機房/代理屬性。
    risk_level: HIGH / MEDIUM / LOW
    signals: 觸發的正向訊號清單（供報告列舉）
    is_sublease: 由 tracer 傳入 — BGP 最精準網段被分租給不同 ASN，
                 此「二房東轉租」結構本身即為機房/代管的強證據，
                 可補足商用黑名單對「新租 VPS」的漏判。
    """
    i2l = query_ip2location(ip, api_key=api_key)
    ipapi = query_ipapi(ip)
    heur = datacenter_heuristic(bgp_holder, rdap_name,
                                ipapi.get("org"), ipapi.get("isp"), i2l.get("as"))

    signals: list[str] = []
    if is_sublease:
        signals.append("BGP 結構分租（大房東≠二房東）→ 機房/代管轉租型態")
    if i2l.get("ok") and i2l.get("is_proxy"):
        pt = i2l.get("proxy_type")
        signals.append(f"IP2Proxy 標記為 Proxy" + (f"（型態 {pt}）" if pt else ""))
    if i2l.get("ok") and i2l.get("usage_type"):
        signals.append(f"IP2Location 用途類別：{i2l['usage_type']}")
    if ipapi.get("ok") and ipapi.get("proxy"):
        signals.append("ip-api 標記為 Proxy/VPN")
    if ipapi.get("ok") and ipapi.get("hosting"):
        signals.append("ip-api 標記為 Hosting/機房")
    if heur.get("likely_datacenter"):
        signals.append(f"ASN/持有人名稱含機房關鍵字：{', '.join(heur['keywords_hit'])}")
    if heur.get("bulletproof_hint"):
        signals.append(f"⚠️ 名稱含高風險關鍵字：{', '.join(heur['bulletproof_hint'])}")
    if ipapi.get("ok") and ipapi.get("mobile"):
        signals.append("ip-api 標記為行動網路（門號動態 IP，追查方向不同）")

    # 風險分級
    strong = (i2l.get("is_proxy") or (ipapi.get("ok") and ipapi.get("proxy"))
              or bool(heur.get("bulletproof_hint")))
    medium = ((ipapi.get("ok") and ipapi.get("hosting"))
              or heur.get("likely_datacenter") or is_sublease)
    if strong:
        risk = "HIGH"
    elif medium:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "risk_level": risk,
        "signals": signals,
        "is_mobile": bool(ipapi.get("mobile")) if ipapi.get("ok") else None,
        "sources": {"ip2location": i2l, "ip_api": ipapi, "heuristic": heur},
    }


if __name__ == "__main__":
    import sys, json
    ip = sys.argv[1] if len(sys.argv) > 1 else "61.111.248.173"
    print(json.dumps(assess_proxy(ip, bgp_holder="MOACK.Co.LTD"), ensure_ascii=False, indent=2))
