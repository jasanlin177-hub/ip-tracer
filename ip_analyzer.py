# -*- coding: utf-8 -*-
"""
科偵 IP 智慧溯源分析系統 — Streamlit 主程式
執行： streamlit run ip_analyzer.py
"""
import datetime as dt

import streamlit as st

import tracer
import batch as batch_mod
import report as report_mod

st.set_page_config(page_title="科偵 IP 智慧溯源分析系統", page_icon="⚙️", layout="wide")

# --------------------------------------------------------------------------- #
# 主介面（純工具，不收集/不儲存任何查詢紀錄）
# --------------------------------------------------------------------------- #
st.title("⚙️ 科偵 IP 智慧溯源分析系統")
st.caption("RDAP（法定產權）× BGP（實體路由 LPM）× RPKI（劫持偵測）交叉比對，並自動產出發文偵辦建議")

with st.sidebar:
    st.header("查詢設定")
    ip2proxy_key = st.text_input("IP2Location.io 金鑰（選填，可拿更完整 Proxy 型態）",
                                 type="password") or None
    use_ts = st.checkbox("回溯案發時間點路由（歷史 BGP）")
    ts_value = None
    if use_ts:
        d = st.date_input("案發日期", value=dt.date.today())
        t = st.time_input("案發時間", value=dt.time(0, 0))
        ts_value = dt.datetime.combine(d, t).isoformat(timespec="seconds")
        st.caption(f"路由基準時間：{ts_value}")
    st.caption("本工具僅整合公開的 RDAP / RIPEstat / ip-api 查詢，不儲存任何查詢紀錄。")

mode = st.radio("查詢模式", ["🔍 單筆查詢", "📋 批次查詢"], horizontal=True)

ip_input = st.text_input("請輸入欲追查的涉案 IP（例：61.111.248.173）", "") \
    if mode == "🔍 單筆查詢" else ""

if mode == "🔍 單筆查詢" and ip_input:
    try:
        ip = tracer.validate_ip(ip_input)
    except ValueError:
        st.error("❌ IP 格式錯誤，請重新輸入。")
        st.stop()

    with st.spinner("正在進行 RDAP × BGP × RPKI 多維度交叉檢索…"):
        try:
            result = tracer.analyze(ip, timestamp=ts_value, ip2proxy_key=ip2proxy_key)
        except Exception as e:
            st.error(f"查詢失敗：{e}")
            st.stop()

    rdap = result["rdap"]
    bgp = result["bgp"]
    rpki = result["rpki"]
    a = result["assessment"]

    # --- 儀表板 ---
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("📜 RDAP 產權證明（法定大房東）")
        st.info(
            f"**法定所有人：** {rdap.get('name')}　\n"
            f"**所屬國家：** {rdap.get('country')}　\n"
            f"**登記網段：** `{a.get('registered_block')}`　\n"
            f"**Abuse 聯絡：** {rdap.get('abuse_email') or '—'}　\n"
            f"**性質：** 法律上的 IP 持有者，下游不配合時的唯一司法施壓槓桿。"
        )
    with col2:
        st.subheader("🪧 BGP 實體路由（最精準二房東）")
        lpm = bgp.get("lpm")
        if lpm:
            st.success(
                f"**實體控制者：** {lpm.get('holder')}　\n"
                f"**宣告 ASN：** AS{lpm.get('asn')}　\n"
                f"**最精準網段：** `{lpm.get('prefix')}`　\n"
                f"**涵蓋 IP 數：** {lpm.get('num_addresses')}　\n"
                f"**路由基準：** {bgp.get('timestamp')}"
            )
            status = rpki.get("status", "unknown")
            badge = {"valid": "✅ VALID（已授權可信）",
                     "invalid": "🚨 INVALID（疑似路由劫持）",
                     "unknown": "➖ UNKNOWN（無 ROA，無法驗證）"}.get(status, status)
            st.metric("RPKI ROA 驗證", badge)
        else:
            st.warning("未偵測到即時 BGP 路由宣告。")

    # --- 重疊路由表 ---
    st.divider()
    st.subheader("📊 全球 BGP 路由重疊交叉比對（Longest Prefix Match）")
    routes = bgp.get("routes", [])
    if routes:
        table = [{
            "網段": r["prefix"], "Origin ASN": f"AS{r['asn']}",
            "ASN 持有人": r.get("holder"), "涵蓋 IP 數": r["num_addresses"],
            "研判": "🎯 最精準（實體流量去向）" if i == 0 else "包含關係（較大網段）",
        } for i, r in enumerate(routes)]
        st.dataframe(table, use_container_width=True, hide_index=True)
    else:
        st.warning("查無即時 BGP 宣告，請以 RDAP 產權登記為主。")

    # --- 機房 / VPN / Proxy 屬性 ---
    st.divider()
    st.subheader("🛡️ 機房 / VPN / Proxy 屬性判定")
    pinfo = result.get("proxy", {})
    p_risk = pinfo.get("risk_level", "LOW")
    c1, c2 = st.columns([1, 3])
    with c1:
        st.metric("綜合風險", {"HIGH": "🔴 高", "MEDIUM": "🟠 中", "LOW": "🟢 低"}.get(p_risk, p_risk))
    with c2:
        sigs = pinfo.get("signals", [])
        if sigs:
            st.write("**觸發訊號：**")
            for s in sigs:
                st.write(f"- {s}")
        else:
            st.write("各來源均未觸發機房/代理特徵。")
        st.caption("來源：IP2Location.io（IP2Proxy）× ip-api.com × ASN/BGP 結構啟發式。"
                   "商用黑名單對新租廉價 VPS 常漏判，LOW 不代表必非機房。")

    # --- 定性與發文建議 ---
    st.divider()
    st.subheader("🚨 科技偵查發文調閱建議")
    verdict = a["verdict"]
    if verdict == "SUBLEASE":
        st.error(
            f"### ⚠️ 偵查定性：大房東／二房東分租現象\n"
            f"嫌犯實質向二房東 **{a['bgp_holder']}** 租用伺服器作跳板，"
            f"該網段法律上歸屬 **{a['legal_owner']}**。\n\n"
            f"**建議調閱步驟（雙重發文）：**\n"
            f"1. **函索大房東 {a['legal_owner']}**：出具案發時網段 `{a['bgp_prefix']}` "
            f"租賃／分租證明（建立法定證據鏈）。\n"
            f"2. **函索二房東 {a['bgp_holder']}（AS{a['bgp_asn']}）**："
            f"該 IP 之 VPS 租用者個資、登入日誌、金流來源。"
        )
    elif verdict == "HIJACK_SUSPECT":
        st.warning(
            f"### 🚨 偵查定性：RPKI=Invalid，疑似路由劫持\n"
            f"BGP 宣告與 ROA 不符，**證據力優先採 RDAP 產權**（{a['legal_owner']}）。\n\n"
            f"1. 函索法定所有人查證是否曾授權(LOA) AS{a['bgp_asn']} 宣告該網段。\n"
            f"2. 保全 RIS/looking-glass 路由時間軸作為劫持事證。"
        )
    elif verdict == "NO_BGP":
        st.info(f"### ⚖️ 查無即時 BGP 宣告\n請以 RDAP 產權登記為主，直接函索 **{a['legal_owner']}**。")
    else:
        st.info(
            f"### ⚖️ 偵查定性：產權與路由一致\n"
            f"該 IP 由 **{a['legal_owner']}** 直接營運，未見分租。"
            f"直接函索調閱使用者個資與連線紀錄。"
        )

    # --- 報告匯出 ---
    st.divider()
    html_report = report_mod.build_html(result)
    st.download_button(
        "📄 下載 HTML 鑑識報告（公文附件）",
        data=html_report.encode("utf-8"),
        file_name=f"IP溯源報告_{ip}_{dt.datetime.now():%Y%m%d_%H%M}.html",
        mime="text/html",
    )
    with st.expander("🔧 原始 API 回應（存證用）"):
        st.json(result)


# --------------------------------------------------------------------------- #
# 批次查詢模式
# --------------------------------------------------------------------------- #
if mode == "📋 批次查詢":
    st.write("一次貼上多個 IP（換行、逗號、空白皆可混雜）：")
    bulk = st.text_area("批次 IP 清單", height=140,
                        placeholder="61.111.248.173\n8.8.8.8, 1.1.1.1")
    ips = batch_mod.parse_ips(bulk)
    st.caption(f"已辨識 {len(ips)} 個有效且不重複的 IP" + (f"：{', '.join(ips[:10])}" + ("…" if len(ips) > 10 else "") if ips else ""))

    if ips and st.button(f"🚀 開始批次分析（{len(ips)} 個）", type="primary"):
        prog = st.progress(0.0, text="準備中…")

        def _cb(done, total, ip):
            prog.progress(done / total, text=f"分析中 {done}/{total}：{ip}")

        results = batch_mod.analyze_batch(
            ips, timestamp=ts_value, ip2proxy_key=ip2proxy_key, progress=_cb)
        prog.empty()
        st.session_state["batch_results"] = results

    if st.session_state.get("batch_results"):
        results = st.session_state["batch_results"]
        rows = batch_mod.to_rows(results)

        # 摘要卡
        n = len(rows)
        n_sub = sum(1 for x in rows if x["定性"] == "SUBLEASE")
        n_hij = sum(1 for x in rows if x["定性"] == "HIJACK_SUSPECT")
        n_high = sum(1 for x in rows if x["機房風險"] == "HIGH")
        n_err = sum(1 for x in rows if x["定性"] == "ERROR")
        c = st.columns(5)
        c[0].metric("總數", n)
        c[1].metric("分租現象", n_sub)
        c[2].metric("疑似劫持", n_hij)
        c[3].metric("機房高風險", n_high)
        c[4].metric("查詢失敗", n_err)

        st.divider()
        st.subheader("📊 批次彙整表")
        st.dataframe(rows, use_container_width=True, hide_index=True)

        col_a, col_b = st.columns(2)
        col_a.download_button(
            "📄 下載 HTML 彙整報告",
            data=batch_mod.to_html(results).encode("utf-8"),
            file_name=f"IP批次溯源_{dt.datetime.now():%Y%m%d_%H%M}.html",
            mime="text/html",
        )
        col_b.download_button(
            "📥 下載 CSV",
            data=batch_mod.to_csv(results).encode("utf-8-sig"),  # BOM 讓 Excel 正確顯示中文
            file_name=f"IP批次溯源_{dt.datetime.now():%Y%m%d_%H%M}.csv",
            mime="text/csv",
        )
