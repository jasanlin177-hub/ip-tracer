# -*- coding: utf-8 -*-
"""
科偵 IP 智慧溯源分析 — 核心邏輯模組 (tracer)

設計原則：
  * 全部使用「即時 API 真實資料」，不寫死任何網段/ASN。
  * 純函式、不依賴 Streamlit，方便 CLI / 報告 / 單元測試重用。
  * 資料來源：
      - RDAP  : https://rdap.org/ip/{ip}   (ICANN 官方 bootstrap，會 302 轉址到權責 RIR)
      - BGP   : https://stat.ripe.net/data/network-info  + looking-glass  (RIPE RIS 即時路由)
      - ASN   : https://stat.ripe.net/data/as-overview   (ASN 持有人)
      - RPKI  : https://stat.ripe.net/data/rpki-validation (ROA 有效性 → 路由劫持偵測)
"""

from __future__ import annotations
import ipaddress
import datetime as _dt
from typing import Optional

import requests

TW_TZ = _dt.timezone(_dt.timedelta(hours=8))


def now_tw() -> _dt.datetime:
    """伺服器（Streamlit Cloud）跑在 UTC，這裡統一轉台灣時間（UTC+8）供顯示用。"""
    return _dt.datetime.now(TW_TZ)

import proxy as _proxy

RIPESTAT = "https://stat.ripe.net/data"
RDAP_BOOTSTRAP = "https://rdap.org/ip"
UA = {"User-Agent": "KKB-IP-Tracer/1.0 (forensic-use)"}
TIMEOUT = 25


# --------------------------------------------------------------------------- #
# 低階 HTTP
# --------------------------------------------------------------------------- #
def _get_json(url: str, params: Optional[dict] = None) -> dict:
    r = requests.get(url, params=params, headers=UA, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


def validate_ip(ip: str) -> str:
    """驗證並正規化 IP，失敗丟 ValueError。"""
    return str(ipaddress.ip_address(ip.strip()))


def is_ip(target: str) -> bool:
    try:
        validate_ip(target)
        return True
    except ValueError:
        return False


def resolve_domain(target: str) -> dict:
    """
    偵查人員一開始拿到的通常是網址而非 IP。
    這裡把網址/網域解析成實際 IP（A/AAAA），交給既有流程繼續分析。
    """
    import socket
    from urllib.parse import urlparse

    raw = target.strip()
    if "://" not in raw:
        raw = "http://" + raw
    hostname = urlparse(raw).hostname or target.strip()

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ValueError(f"網域解析失敗：{hostname}（{e}）")

    seen, ips = set(), []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)

    return {
        "input": target,
        "hostname": hostname,
        "ips": ips,
        "resolved_at": now_tw().isoformat(timespec="seconds"),
    }


# 常見 CDN / 反向代理業者的 ASN → 名稱。
# 這些 IP 背後幾乎必定藏著真正的來源主機（origin），直接函索 CDN 業者
# 通常只能拿到 CDN 邊緣節點的連線紀錄，不是網站真正架設的機房。
CDN_ASNS = {
    "13335": "Cloudflare",
    "54113": "Fastly",
    "20940": "Akamai",
    "16625": "Akamai",
    "21342": "Akamai",
    "31108": "Akamai",
    "34164": "Akamai",
    "19551": "Imperva (Incapsula)",
    "33438": "StackPath",
    "30148": "Sucuri",
    "209242": "BunnyCDN",
}


def cdn_provider(asn: Optional[str]) -> Optional[str]:
    if not asn:
        return None
    return CDN_ASNS.get(str(asn))


# --------------------------------------------------------------------------- #
# 1. RDAP — 法定大房東（產權登記）
# --------------------------------------------------------------------------- #
def _extract_entities(rdap: dict) -> list[dict]:
    """從 RDAP entities 抽出可讀的組織/聯絡人（含 abuse email）。"""
    out = []
    for ent in rdap.get("entities", []) or []:
        name, kind, email = None, None, None
        for item in ent.get("vcardArray", [None, []])[1] or []:
            if not isinstance(item, list):
                continue
            if item[0] == "fn":
                name = item[3]
            elif item[0] == "kind":
                kind = item[3]
            elif item[0] == "email":
                email = item[3]
        out.append({
            "handle": ent.get("handle"),
            "roles": ent.get("roles", []),
            "name": name,
            "kind": kind,
            "email": email,
        })
    return out


def query_rdap(ip: str) -> dict:
    """回傳法定產權資訊。follow redirect 到權責 RIR。"""
    rdap = _get_json(f"{RDAP_BOOTSTRAP}/{ip}")
    entities = _extract_entities(rdap)
    # 找 abuse 聯絡信箱（發函對象）
    abuse_email = None
    for e in entities:
        if "abuse" in [r.lower() for r in e.get("roles", [])] and e.get("email"):
            abuse_email = e["email"]
            break
    return {
        "name": rdap.get("name"),                 # 例：SEJONG-KR
        "country": rdap.get("country"),           # 例：KR
        "handle": rdap.get("handle"),             # 例：61.111.240.0 - 61.111.255.255
        "start": rdap.get("startAddress"),
        "end": rdap.get("endAddress"),
        "type": rdap.get("type"),
        "registered_block": _range_to_cidr(rdap.get("startAddress"), rdap.get("endAddress")),
        "entities": entities,
        "abuse_email": abuse_email,
        "raw_source": "rdap.org (ICANN bootstrap)",
    }


def _range_to_cidr(start: Optional[str], end: Optional[str]) -> Optional[str]:
    if not start or not end:
        return None
    try:
        nets = list(ipaddress.summarize_address_range(
            ipaddress.ip_address(start), ipaddress.ip_address(end)))
        return ", ".join(str(n) for n in nets)
    except Exception:
        return f"{start} - {end}"


# --------------------------------------------------------------------------- #
# 2. BGP — 實體二房東（即時路由），含 LPM
# --------------------------------------------------------------------------- #
def query_bgp(ip: str, timestamp: Optional[str] = None) -> dict:
    """
    回傳即時（或指定時間點）BGP 路由狀態。
    timestamp: ISO 字串，例 '2026-05-01T00:00:00'，可回溯案發當時路由。
    """
    # (a) network-info：最精準宣告網段 + origin ASN
    ni = _get_json(f"{RIPESTAT}/network-info/data.json", {"resource": ip}).get("data", {})
    most_specific = ni.get("prefix")
    origin_asns = ni.get("asns", []) or []

    # (b) looking-glass：RIS 各收集器實際看到的宣告（去重後即為重疊網段全貌）
    lg_params = {"resource": ip}
    if timestamp:
        lg_params["timestamp"] = timestamp
    lg = _get_json(f"{RIPESTAT}/looking-glass/data.json", lg_params).get("data", {})

    seen: dict[tuple, dict] = {}
    for rrc in lg.get("rrcs", []):
        for peer in rrc.get("peers", []):
            pfx = peer.get("prefix")
            asn = str(peer.get("asn_origin")) if peer.get("asn_origin") is not None else None
            if not pfx or asn is None:
                continue
            key = (pfx, asn)
            if key not in seen:
                seen[key] = {"prefix": pfx, "asn": asn}

    routes = list(seen.values())
    # LPM：斜線數字越大（範圍越小）排越前面
    routes.sort(key=lambda r: ipaddress.ip_network(r["prefix"]).prefixlen, reverse=True)

    # 補上每條路由的 ASN 持有人與涵蓋 IP 數
    for r in routes:
        net = ipaddress.ip_network(r["prefix"])
        r["prefixlen"] = net.prefixlen
        r["num_addresses"] = net.num_addresses
        r["holder"] = query_asn_holder(r["asn"])

    lpm = routes[0] if routes else None
    # fallback：若 looking-glass 無資料，用 network-info
    if lpm is None and most_specific and origin_asns:
        asn = str(origin_asns[0])
        net = ipaddress.ip_network(most_specific)
        lpm = {
            "prefix": most_specific, "asn": asn,
            "prefixlen": net.prefixlen, "num_addresses": net.num_addresses,
            "holder": query_asn_holder(asn),
        }
        routes = [lpm]

    return {
        "routes": routes,          # 已依 LPM 排序
        "lpm": lpm,                # 最精準網段（實體控制者 = 二房東）
        "timestamp": timestamp or "現況 (live)",
        "raw_source": "RIPEstat network-info + looking-glass (RIPE RIS)",
    }


_ASN_CACHE: dict[str, Optional[str]] = {}


def query_asn_holder(asn: str) -> Optional[str]:
    if asn in _ASN_CACHE:
        return _ASN_CACHE[asn]
    try:
        d = _get_json(f"{RIPESTAT}/as-overview/data.json",
                      {"resource": f"AS{asn}"}).get("data", {})
        holder = d.get("holder")
    except Exception:
        holder = None
    _ASN_CACHE[asn] = holder
    return holder


def quick_asn(ip: str) -> Optional[str]:
    """輕量 ASN 查詢（只打 network-info，不跑 looking-glass），給子網域批次掃描用。"""
    try:
        d = _get_json(f"{RIPESTAT}/network-info/data.json", {"resource": ip}).get("data", {})
        asns = d.get("asns") or []
        return str(asns[0]) if asns else None
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# 3. RPKI — 路由劫持偵測
# --------------------------------------------------------------------------- #
def query_rpki(asn: str, prefix: str) -> dict:
    """
    回傳 (asn, prefix) 的 ROA 驗證狀態：
      valid   → 已授權，路由可信
      invalid → ⚠️ ROA 存在但與宣告不符，疑似劫持/設定錯誤，應優先採 RDAP
      unknown → 無 ROA，無法用密碼學驗證（境外常見）
    """
    try:
        d = _get_json(f"{RIPESTAT}/rpki-validation/data.json",
                      {"resource": asn, "prefix": prefix}).get("data", {})
        return {
            "status": d.get("status", "unknown"),
            "validating_roas": d.get("validating_roas", []),
        }
    except Exception as e:
        return {"status": "error", "error": str(e), "validating_roas": []}


# --------------------------------------------------------------------------- #
# 4. 情資定性引擎
# --------------------------------------------------------------------------- #
def _norm(s: Optional[str]) -> str:
    return (s or "").upper().replace(".", "").replace(",", "").replace("-", " ")


_COMMON_ORG_TOKENS = {"KR", "AS", "CO", "LTD", "INC", "NET", "NETWORK",
                      "THE", "AP", "LLC", "GMBH", "SA", "BV", "CORP",
                      "COMPANY", "GROUP", "TELECOM", "COMMUNICATIONS"}


def _same_org(a: Optional[str], b: Optional[str]) -> bool:
    """粗略判斷兩個組織名是否為同一實體（去通用詞後 token 交集）。"""
    ta = set(_norm(a).split()) - _COMMON_ORG_TOKENS
    tb = set(_norm(b).split()) - _COMMON_ORG_TOKENS
    return bool(ta & tb)


def _owner_candidates(rdap: dict) -> list[str]:
    """RDAP 中所有可代表『法定所有人』的名稱：netname + registrant 組織名。"""
    names = [rdap.get("name")]
    for e in rdap.get("entities", []) or []:
        roles = [r.lower() for r in (e.get("roles") or [])]
        if e.get("name") and ("registrant" in roles or "administrative" in roles):
            names.append(e["name"])
    return [n for n in names if n]


def assess(rdap: dict, bgp: dict, rpki: dict) -> dict:
    """
    綜合定性，回傳偵辦建議所需的結構化結論。
    verdict:
      CDN_FRONTED     → IP 屬於已知 CDN/反向代理，真正主機藏在後面（origin），優先權最高
      HIJACK_SUSPECT  → RPKI invalid，疑似路由劫持
      SUBLEASE        → 大房東≠二房東（分租/代管）
      CONSISTENT      → 產權與路由一致
      NO_BGP          → 查無 BGP 宣告
    """
    lpm = bgp.get("lpm")
    legal_owner = rdap.get("name")
    if not lpm:
        return {
            "verdict": "NO_BGP",
            "legal_owner": legal_owner,
            "bgp_holder": None,
            "rpki_status": rpki.get("status"),
            "cdn_name": None,
        }

    bgp_holder = lpm.get("holder")
    rpki_status = rpki.get("status")
    cdn_name = cdn_provider(lpm.get("asn"))

    # 與『任一個』法定所有人候選名相符即視為同一實體（避免 netname 縮寫誤判分租）
    owner_names = _owner_candidates(rdap)
    matched = any(_same_org(name, bgp_holder) for name in owner_names)

    if cdn_name:
        verdict = "CDN_FRONTED"
    elif rpki_status == "invalid":
        verdict = "HIJACK_SUSPECT"
    elif not matched:
        verdict = "SUBLEASE"
    else:
        verdict = "CONSISTENT"

    return {
        "verdict": verdict,
        "legal_owner": legal_owner,
        "legal_country": rdap.get("country"),
        "registered_block": rdap.get("registered_block") or rdap.get("handle"),
        "abuse_email": rdap.get("abuse_email"),
        "bgp_holder": bgp_holder,
        "bgp_prefix": lpm.get("prefix"),
        "bgp_asn": lpm.get("asn"),
        "rpki_status": rpki_status,
        "cdn_name": cdn_name,
    }


# --------------------------------------------------------------------------- #
# 主流程：一次跑完
# --------------------------------------------------------------------------- #
def analyze(ip: str, timestamp: Optional[str] = None,
            ip2proxy_key: Optional[str] = None) -> dict:
    ip = validate_ip(ip)
    rdap = query_rdap(ip)
    bgp = query_bgp(ip, timestamp=timestamp)
    lpm = bgp.get("lpm")
    if lpm:
        rpki = query_rpki(lpm["asn"], lpm["prefix"])
    else:
        rpki = {"status": "unknown", "validating_roas": []}
    verdict = assess(rdap, bgp, rpki)

    # 機房 / VPN / Proxy 屬性（把 BGP 分租結構當作機房訊號餵入）
    proxy_info = _proxy.assess_proxy(
        ip,
        bgp_holder=verdict.get("bgp_holder"),
        rdap_name=rdap.get("name"),
        api_key=ip2proxy_key,
        is_sublease=(verdict.get("verdict") == "SUBLEASE"),
    )

    # 台灣 IP：自動補公司登記資訊（中文名／登記地址），方便製作公文
    company_tw = None
    if (rdap.get("country") or "").upper() == "TW":
        try:
            import company_tw as _company_tw
            company_tw = _company_tw.lookup(ip)
        except Exception:
            company_tw = None

    return {
        "ip": ip,
        "queried_at": now_tw().isoformat(timespec="seconds"),
        "case_timestamp": timestamp,
        "rdap": rdap,
        "bgp": bgp,
        "rpki": rpki,
        "assessment": verdict,
        "proxy": proxy_info,
        "company_tw": company_tw,
    }


if __name__ == "__main__":
    import sys, json
    target = sys.argv[1] if len(sys.argv) > 1 else "61.111.248.173"
    print(json.dumps(analyze(target), ensure_ascii=False, indent=2))
