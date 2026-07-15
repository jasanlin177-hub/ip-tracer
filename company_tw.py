# -*- coding: utf-8 -*-
"""
台灣公司登記查詢：對「大房東／二房東屬於台灣」的案件補上中文公司名、登記地址、統編、負責人，
方便同仁製作公文，並能一眼看出大／二房東是否為同一人（自我分租）。

資料源（皆免金鑰、走正常 TLS 憑證驗證，非繞過）：
  1. TWNIC RMS Whois（IP 查詢）      → 大房東中文名 + 英文登記地址   （HTTP/2）
  2. TWNIC ASN 核發對照表            → 用 BGP 的 ASN 反查二房東中文名  （HTTP/2）
  3. g0v 公司登記 API（同 GCIS 資料的公民科技鏡像，憑證正常）
       用中文公司名 → 統編、中文登記地址、負責人

流程：
  大房東 = company_for_ip(ip)   （TWNIC-IP 拿中文名 → g0v 補完）
  二房東 = company_for_asn(asn) （TWNIC-ASN表 拿中文名 → g0v 補完）

限制：台灣公開登記不揭露「公司電話」；報告改附官方商工登記查詢連結供同仁自行核對正本。
"""
from __future__ import annotations
import re
import html as _html
from typing import Optional

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False

TWNIC_WHOIS = "https://rms.twnic.tw/query_whois1.php"
TWNIC_ASN_LIST = "https://rms.twnic.tw/help_asn_assign.php"
G0V_SEARCH = "https://company.g0v.ronny.tw/api/search"
UA = {"User-Agent": "KKB-IP-Tracer/1.0 (forensic-use)"}
TIMEOUT = 20

_asn_table_cache: Optional[dict] = None  # {asn(str): {"netname","company"}}


def _clean(s: str) -> str:
    return _html.unescape(re.sub(r"<[^>]+>", "", s)).strip()


# --------------------------------------------------------------------------- #
# 1. TWNIC Whois（IP）→ 大房東中文名 + 英文地址
# --------------------------------------------------------------------------- #
def _twnic_whois_ip(ip: str) -> dict:
    if not _HAS_HTTPX:
        return {}
    try:
        with httpx.Client(http2=True, timeout=TIMEOUT, headers=UA) as c:
            r = c.post(TWNIC_WHOIS, data={"q": ip})
        if r.status_code != 200:
            return {}
        cells = [_clean(x) for x in re.findall(r"<td[^>]*>(.*?)</td>", r.text, re.S)]
        raw = {}
        for i in range(0, len(cells) - 1, 2):
            if cells[i] and cells[i + 1]:
                raw.setdefault(cells[i], cells[i + 1])
        return {
            "chinese_name": raw.get("Chinese Name"),
            "org_name": raw.get("Organization Name"),
            "address_en": raw.get("Street Address"),
            "netname": raw.get("Netname"),
        }
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
# 2. TWNIC ASN 對照表 → 用 ASN 反查二房東中文名
# --------------------------------------------------------------------------- #
def _load_asn_table() -> dict:
    global _asn_table_cache
    if _asn_table_cache is not None:
        return _asn_table_cache
    table = {}
    if _HAS_HTTPX:
        try:
            with httpx.Client(http2=True, timeout=25, headers=UA) as c:
                r = c.get(TWNIC_ASN_LIST)
            for row in re.findall(r"<tr[^>]*>(.*?)</tr>", r.text, re.S):
                cells = [_clean(x) for x in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)]
                if len(cells) >= 3 and cells[0].upper().startswith("AS"):
                    asn = cells[0].upper().replace("AS", "").strip()
                    table[asn] = {"netname": cells[1], "company": cells[2]}
        except Exception:
            table = {}
    _asn_table_cache = table
    return table


def _twnic_asn_name(asn: str) -> dict:
    asn = str(asn).upper().replace("AS", "").strip()
    row = _load_asn_table().get(asn)
    if not row:
        return {}
    return {"chinese_name": row.get("company"), "netname": row.get("netname")}


# --------------------------------------------------------------------------- #
# 3. g0v → 用中文公司名補完統編／中文地址／負責人
# --------------------------------------------------------------------------- #
def _g0v_enrich(chinese_name: str) -> dict:
    if not _HAS_HTTPX or not chinese_name:
        return {}
    try:
        with httpx.Client(timeout=TIMEOUT, headers=UA) as c:
            r = c.get(G0V_SEARCH, params={"q": chinese_name})
        found = r.json().get("data", []) if r.status_code == 200 else []
    except Exception:
        return {}
    # 精確比對公司名（避免「天空數位」誤中「天空數位圖書」）
    exact = [x for x in found if x.get("公司名稱") == chinese_name]
    pick = exact[0] if exact else (found[0] if found else None)
    if not pick:
        return {}
    return {
        "tax_id": pick.get("統一編號"),
        "address_zh": pick.get("公司所在地"),
        "responsible": pick.get("代表人姓名"),
        "status": pick.get("公司狀態") or pick.get("Company_Status_Desc"),
    }


# --------------------------------------------------------------------------- #
# 對外：組出大房東／二房東的完整公司資訊
# --------------------------------------------------------------------------- #
def _merge(base: dict, role: str) -> Optional[dict]:
    cn = base.get("chinese_name")
    if not cn:
        return None
    out = {"role": role, "chinese_name": cn,
           "org_name": base.get("org_name"),
           "address_en": base.get("address_en"),
           "netname": base.get("netname")}
    out.update(_g0v_enrich(cn))
    return out


def company_for_ip(ip: str) -> Optional[dict]:
    """大房東（IP 登記人）完整公司資訊。"""
    return _merge(_twnic_whois_ip(ip), "大房東（產權登記）")


def company_for_asn(asn: str) -> Optional[dict]:
    """二房東（BGP 宣告者 ASN）完整公司資訊。"""
    return _merge(_twnic_asn_name(asn), "二房東（實體路由）")


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) > 1 and sys.argv[1].upper().startswith("AS"):
        print(json.dumps(company_for_asn(sys.argv[1]), ensure_ascii=False, indent=2))
    else:
        ip = sys.argv[1] if len(sys.argv) > 1 else "103.137.22.132"
        print(json.dumps(company_for_ip(ip), ensure_ascii=False, indent=2))
