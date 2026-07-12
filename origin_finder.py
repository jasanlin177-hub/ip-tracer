# -*- coding: utf-8 -*-
"""
origin IP 追查輔助工具：當目標網域被 CDN／反向代理遮蔽時，
嘗試找出「套用 CDN 前」或「未套用 CDN 的子網域」洩漏的真實來源 IP。

技巧：
  1. crt.sh 憑證透明度紀錄  → 枚舉該網域曾申請過憑證的所有子網域
     （某些子網域如 mail/ftp/直連後台常常沒套 CDN，會直接洩漏真實主機）
  2. AlienVault OTX Passive DNS → 該網域/子網域「歷史上」曾解析過的 IP
     （若網域是後來才加裝 CDN，改用 CDN 前的舊紀錄可能就是真實主機）

兩者皆為免金鑰公開服務，資料非百分之百即時／完整，僅供辦案線索參考，
找到候選 IP 後仍須以 tracer.analyze() 重新驗證其 RDAP/BGP 屬性。
"""
from __future__ import annotations
import time
import socket
from typing import Optional

import requests

import tracer

UA = {"User-Agent": "KKB-IP-Tracer/1.0 (forensic-use)"}
TIMEOUT = 25

# crt.sh 是單一伺服器、常過載（實測會整段時間 502/連不上）。
# 用「少量快速重試」救偶發抖動即可，不做長時間狂試以免拖垮使用者等待。
CRTSH_TIMEOUT = 12
CRTSH_RETRIES = 2       # 首次 + 2 次重試 = 最多 3 次嘗試
CRTSH_BACKOFF = 1.5     # 每次重試間隔（秒）

# OTX 較穩但仍會偶發限流，給少量重試即可
OTX_RETRIES = 2
OTX_BACKOFF = 2.0


def query_crtsh(domain: str) -> tuple[list[str], bool]:
    """
    回傳 (子網域清單, 是否查詢成功)。
    區分「成功但無資料」與「服務不可用」——後者才回 ok=False，讓上層誠實告知使用者
    （避免 crt.sh 掛掉時靜默回空清單，害人誤以為該網域真的沒有子網域）。
    """
    last_err = None
    for attempt in range(CRTSH_RETRIES + 1):
        try:
            r = requests.get("https://crt.sh/", params={"q": domain, "output": "json"},
                             headers=UA, timeout=CRTSH_TIMEOUT)
            r.raise_for_status()
            entries = r.json()  # 成功：即使空陣列也算查詢成功
            names = set()
            for entry in entries:
                for n in (entry.get("name_value") or "").split("\n"):
                    n = n.strip().lower()
                    if n and not n.startswith("*."):
                        names.add(n)
            return sorted(names), True
        except Exception as e:
            last_err = e
            if attempt < CRTSH_RETRIES:
                time.sleep(CRTSH_BACKOFF)
    return [], False


def query_passive_dns(domain: str) -> tuple[list[dict], bool]:
    """
    回傳 (歷史 A/AAAA 解析紀錄, 是否查詢成功)。
    OTX 是本功能主力來源，雖比 crt.sh 穩，實測仍會偶發限流／抖動，
    故同樣加少量重試並回報狀態（失敗時 UI 應告知，避免誤以為「無歷史紀錄」）。
    """
    recs = None
    for attempt in range(OTX_RETRIES + 1):
        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/passive_dns",
                headers=UA, timeout=TIMEOUT)
            r.raise_for_status()
            recs = r.json().get("passive_dns", [])
            break
        except Exception:
            if attempt < OTX_RETRIES:
                time.sleep(OTX_BACKOFF)
    if recs is None:
        return [], False

    out = []
    for rec in recs:
        if rec.get("record_type") not in ("A", "AAAA"):
            continue
        out.append({
            "hostname": rec.get("hostname"),
            "ip": rec.get("address"),
            "asn": (rec.get("asn") or "").split()[0].lstrip("AS") or None,
            "asn_desc": rec.get("asn"),
            "first_seen": rec.get("first"),
            "last_seen": rec.get("last"),
        })
    return out, True


def _resolve_now(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []
    seen, ips = set(), []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips


def find_origin_candidates(domain: str) -> dict:
    """
    綜合 crt.sh 子網域枚舉 + passive DNS 歷史紀錄，
    回傳所有曾經/現在出現過的 IP，並標記是否為已知 CDN。
    非 CDN 的候選 IP 是最值得深入追查的「可能真實主機」。
    """
    subdomains, crtsh_ok = query_crtsh(domain)
    if domain not in subdomains:
        subdomains = [domain] + subdomains
    pdns, otx_ok = query_passive_dns(domain)

    candidates: dict[str, dict] = {}  # ip -> info

    # 來源一：子網域現況解析
    for sub in subdomains[:30]:  # 避免子網域過多時查詢時間爆炸
        for ip in _resolve_now(sub):
            c = candidates.setdefault(ip, {
                "ip": ip, "hostnames": set(), "first_seen": None, "last_seen": None,
                "source": set(),
            })
            c["hostnames"].add(sub)
            c["source"].add("目前解析")

    # 來源二：歷史 passive DNS
    for rec in pdns:
        ip = rec["ip"]
        c = candidates.setdefault(ip, {
            "ip": ip, "hostnames": set(), "first_seen": None, "last_seen": None,
            "source": set(),
        })
        if rec["hostname"]:
            c["hostnames"].add(rec["hostname"])
        c["source"].add("歷史 DNS")
        if rec["first_seen"] and (not c["first_seen"] or rec["first_seen"] < c["first_seen"]):
            c["first_seen"] = rec["first_seen"]
        if rec["last_seen"] and (not c["last_seen"] or rec["last_seen"] > c["last_seen"]):
            c["last_seen"] = rec["last_seen"]

    # 標記每個候選 IP 是否為已知 CDN
    results = []
    for ip, c in candidates.items():
        asn = tracer.quick_asn(ip)
        cdn = tracer.cdn_provider(asn)
        results.append({
            "ip": ip,
            "asn": asn,
            "cdn_name": cdn,
            "is_cdn": bool(cdn),
            "hostnames": sorted(c["hostnames"]),
            "source": sorted(c["source"]),
            "first_seen": c["first_seen"],
            "last_seen": c["last_seen"],
        })

    # 非 CDN 的排前面（最值得追查）
    results.sort(key=lambda r: (r["is_cdn"], r["ip"]))

    return {
        "domain": domain,
        "subdomains": subdomains,
        "crtsh_ok": crtsh_ok,          # crt.sh 是否查詢成功（失敗時 UI 應誠實告知子網域枚舉略過）
        "otx_ok": otx_ok,              # OTX 歷史 DNS 是否查詢成功
        "passive_dns_count": len(pdns),
        "candidates": results,
        "non_cdn_candidates": [r for r in results if not r["is_cdn"]],
    }


if __name__ == "__main__":
    import sys, json
    d = sys.argv[1] if len(sys.argv) > 1 else "555vip.net"
    print(json.dumps(find_origin_candidates(d), ensure_ascii=False, indent=2))
