# -*- coding: utf-8 -*-
"""
台灣 IP 的公司登記查詢（TWNIC）。

對「大房東／二房東屬於台灣」的案件，直接補上中文公司名稱與登記地址，方便同仁製作公文。

資料源：TWNIC RMS Whois（https://rms.twnic.tw/query_whois1.php）
  - 該站強制 HTTP/2（純 HTTP/1.1 客戶端會收到 426 Upgrade Required），故用 httpx[http2]。
  - 走正常 TLS 憑證驗證（verify 預設 True），非繞過反爬蟲。
  - 僅台灣（TWNIC 管理）之 IP 有資料；非 TW IP 回 None。
  - 注意：此資料源含中文名／英文名／登記地址，但「不含公司電話」——電話請改用商工登記查詢。
"""
from __future__ import annotations
import re
import html as _html
from typing import Optional

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:  # 未安裝 httpx 時優雅降級（此功能停用，不影響其他分析）
    _HAS_HTTPX = False

TWNIC_URL = "https://rms.twnic.tw/query_whois1.php"
UA = {"User-Agent": "KKB-IP-Tracer/1.0 (forensic-use)"}
TIMEOUT = 20

# 要抽出的欄位（TWNIC 表格中的英文標籤 → 我方欄位名）
_FIELDS = {
    "Chinese Name": "chinese_name",
    "Organization Name": "org_name",
    "Street Address": "address",
    "Netname": "netname",
    "Country Code": "country",
}


def _parse_table(text: str) -> dict:
    """把 TWNIC 回傳頁面的 <td>標籤</td><td>值</td> 配對抽成 dict。"""
    cells = re.findall(r"<td[^>]*>(.*?)</td>", text, re.S)
    cells = [_html.unescape(re.sub(r"<[^>]+>", "", c)).strip() for c in cells]
    raw = {}
    for i in range(0, len(cells) - 1, 2):
        k, v = cells[i], cells[i + 1]
        if k and v:
            raw[k] = v
    out = {}
    for label, key in _FIELDS.items():
        if raw.get(label):
            out[key] = raw[label]
    return out


def lookup(ip: str) -> Optional[dict]:
    """
    查台灣 IP 的公司登記資訊。回傳 dict（chinese_name/org_name/address/netname/country）或 None。
    只要沒資料、未安裝 httpx、或連線失敗，一律回 None（純加值功能，失敗不影響主流程）。
    """
    if not _HAS_HTTPX:
        return None
    try:
        with httpx.Client(http2=True, timeout=TIMEOUT, headers=UA) as c:
            r = c.post(TWNIC_URL, data={"q": ip})
        if r.status_code != 200:
            return None
        data = _parse_table(r.text)
        # 至少要有中文名或組織名才算查到
        if data.get("chinese_name") or data.get("org_name"):
            return data
        return None
    except Exception:
        return None


if __name__ == "__main__":
    import sys, json
    ip = sys.argv[1] if len(sys.argv) > 1 else "103.137.22.132"
    print(json.dumps(lookup(ip), ensure_ascii=False, indent=2))
