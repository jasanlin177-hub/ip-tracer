# -*- coding: utf-8 -*-
"""
科偵 IP 智慧溯源分析系統 — Streamlit 主程式
執行： streamlit run ip_analyzer.py

查詢結果直接重用 report.py / batch.py 的 HTML 渲染邏輯（render_content），
與下載的 HTML 鑑識報告是同一套視覺，不再用 Streamlit 原生元件拼版面。
"""
import datetime as dt

import streamlit as st

import tracer
import batch as batch_mod
import report as report_mod
import origin_finder as origin_mod

st.set_page_config(page_title="科偵 IP 智慧溯源分析系統", page_icon="⚙️", layout="wide")

# --------------------------------------------------------------------------- #
# 全域樣式：直接注入 report.STYLE（司法公文風），查詢結果與 HTML 報告視覺完全一致
# --------------------------------------------------------------------------- #
st.markdown(f"""
<style>
  html, body, [class*="css"] {{ font-family:Georgia,"Noto Serif TC","Microsoft JhengHei",serif; }}
  .stApp {{ background:#f7f3ea; }}
  .block-container {{ padding-top:1.9rem; max-width:1060px; }}
  {report_mod.STYLE}
  {batch_mod._BATCH_STYLE}
  /* Streamlit 原生控件重皮：融入公文紙質感 */
  [data-testid="stAlert"]{{ border-radius:6px; box-shadow:none; border:1px solid #e2d8c6; background:#fdfbf6; }}
  [data-testid="stSidebar"]{{ background:#fdfbf6; border-right:1px solid #e2d8c6; }}
  .stButton>button, .stDownloadButton>button{{ border-radius:5px; font-weight:600; border-color:#1e3a5f; color:#1e3a5f; }}
  .stTextInput input, .stTextArea textarea{{ border-radius:5px; background:#fdfbf6; border-color:#ddd0bd; }}
  hr{{ border-color:#e2d8c6; }}
</style>
""", unsafe_allow_html=True)


def _render_simple_table(rows: list) -> None:
    """輕量 HTML 表格（不用 st.dataframe，避開 pandas/pyarrow 在雲端 segfault 的坑）。"""
    import html as _h
    if not rows:
        return
    cols = list(rows[0].keys())
    ths = "".join(f"<th>{_h.escape(str(c))}</th>" for c in cols)
    trs = ""
    for r in rows:
        tds = "".join(f"<td>{_h.escape('' if r.get(c) is None else str(r.get(c)))}</td>" for c in cols)
        trs += f"<tr>{tds}</tr>"
    st.markdown(f"<div class='doc' style='padding:.8rem 1rem'><table>"
                f"<thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table></div>",
                unsafe_allow_html=True)


# --------------------------------------------------------------------------- #
# 標題：與報告同一套 .doc / .hd / .seal 樣式
# --------------------------------------------------------------------------- #
st.markdown("""
<div class="doc" style="margin-bottom:1.4rem">
  <div class="hd">
    <div>
      <h1>科偵 IP 智慧溯源分析系統</h1>
      <p class="meta" style="margin:.4rem 0 0">RDAP · BGP（LPM）· RPKI 交叉比對，自動產出發文偵辦建議 ｜ 不登入、不儲存任何查詢紀錄</p>
    </div>
    <div class="seal">科偵</div>
  </div>
</div>
""", unsafe_allow_html=True)

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

ip_input = st.text_input(
    "請輸入欲追查的涉案 IP 或網址（例：61.111.248.173 或 https://example.com）", ""
) if mode == "🔍 單筆查詢" else ""

if mode == "🔍 單筆查詢" and ip_input:
    ip = None
    resolved_hostname = None
    if tracer.is_ip(ip_input):
        ip = tracer.validate_ip(ip_input)
    else:
        # 偵查人員一開始通常拿到的是網址，不是 IP：先解析網域再繼續分析
        with st.spinner(f"正在解析網域 {ip_input}…"):
            try:
                resolved = tracer.resolve_domain(ip_input)
            except ValueError as e:
                st.error(f"❌ {e}")
                st.stop()

        ipv4s = [x for x in resolved["ips"] if ":" not in x]
        st.info(
            f"🌐 網域 **{resolved['hostname']}** 解析出 {len(resolved['ips'])} 個 IP："
            f"{'、'.join(resolved['ips'])}"
        )
        choices = ipv4s or resolved["ips"]
        ip_choice = st.selectbox("選擇要深入分析的 IP（預設取第一個 IPv4）：", choices)
        # 用 session_state 記住「已確認要分析的 IP」，避免後續按鈕（如追查 origin）
        # 觸發整頁 rerun 時，此按鈕變回 False 而 st.stop() 退回初始畫面。
        if st.button("👉 分析此 IP", type="primary"):
            st.session_state["confirmed"] = {"host": resolved["hostname"], "ip": ip_choice}
            st.session_state.pop("origin_hunt", None)   # 換分析目標時清掉舊追查結果
            st.session_state.pop("hunt_result", None)

        confirmed = st.session_state.get("confirmed")
        if not confirmed or confirmed["host"] != resolved["hostname"] or confirmed["ip"] not in choices:
            st.stop()
        ip = tracer.validate_ip(confirmed["ip"])
        resolved_hostname = resolved["hostname"]

    with st.spinner("正在進行 RDAP × BGP × RPKI 多維度交叉檢索…"):
        try:
            result = tracer.analyze(ip, timestamp=ts_value, ip2proxy_key=ip2proxy_key)
        except Exception as e:
            st.error(f"查詢失敗：{e}")
            st.stop()

    # --- 查詢結果：與 HTML 報告同一份渲染邏輯 ---
    st.markdown(report_mod.render_content(result, domain=resolved_hostname), unsafe_allow_html=True)

    # --- CDN 遮蔽時，提供 origin IP 追查輔助 ---
    if result["assessment"].get("verdict") == "CDN_FRONTED" and resolved_hostname:
        st.divider()
        st.subheader("🔍 嘗試找出真實來源 IP（origin IP）")
        st.caption(
            "透過憑證透明度紀錄（crt.sh）枚舉子網域，並比對 AlienVault OTX 的歷史 DNS 解析紀錄，"
            "找出套用 CDN 前或未受 CDN 保護的候選 IP。兩者皆為免金鑰公開服務，資料非百分之百完整，"
            "僅供辦案線索參考，找到候選 IP 後仍應重新查詢驗證。"
        )
        st.markdown(
            f"🔗 原始工具查證（開新分頁自行比對）："
            f"　<a href='https://crt.sh/?q={resolved_hostname}' target='_blank' rel='noopener'>crt.sh 憑證紀錄</a>"
            f"　｜　<a href='https://otx.alienvault.com/indicator/hostname/{resolved_hostname}' target='_blank' rel='noopener'>OTX 歷史 DNS</a>",
            unsafe_allow_html=True,
        )
        if st.button("🚀 開始追查 origin IP", key="hunt_origin_btn"):
            with st.spinner(f"正在查詢 {resolved_hostname} 的憑證紀錄與歷史 DNS…"):
                st.session_state["origin_hunt"] = origin_mod.find_origin_candidates(resolved_hostname)

        hunt = st.session_state.get("origin_hunt")
        if hunt and hunt["domain"] == resolved_hostname:
            n_total = len(hunt["candidates"])
            n_noncdn = len(hunt["non_cdn_candidates"])
            # 兩個外部服務都常抖動，失敗時誠實告知（避免同仁誤以為「沒有資料」）
            if not hunt.get("crtsh_ok"):
                st.warning(
                    "⚠️ crt.sh 憑證紀錄服務暫時無法連線（該站常過載），本次**子網域枚舉已略過**，"
                    "改以歷史 DNS 紀錄為主。建議稍後重試以補齊線索。"
                )
            if not hunt.get("otx_ok"):
                st.warning(
                    "⚠️ AlienVault OTX 歷史 DNS 服務暫時無回應（可能限流），本次**歷史紀錄查詢失敗**。"
                    "這是本功能的主力線索，建議**稍後重試**（本工具已自動重試數次仍失敗）。"
                )
            st.write(f"子網域枚舉 crt.sh {'✅ 成功（' + str(len(hunt['subdomains'])) + ' 個）' if hunt.get('crtsh_ok') else '❌ 略過'}、"
                     f"歷史 DNS {'✅ ' + str(hunt.get('passive_dns_count', 0)) + ' 筆' if hunt.get('otx_ok') else '❌ 失敗'}，"
                     f"共 **{n_total}** 個候選 IP，其中 **{n_noncdn}** 個非已知 CDN（最值得追查）：")
            table = [{
                "IP": c["ip"],
                "ASN": f"AS{c['asn']}" if c["asn"] else "-",
                "CDN 判定": c["cdn_name"] or "🟢 非CDN（可疑候選）",
                "來源子網域": "、".join(c["hostnames"][:3]) + ("…" if len(c["hostnames"]) > 3 else ""),
                "資料來源": "、".join(c["source"]),
                "首次出現": (c["first_seen"] or "-")[:10],
                "最後出現": (c["last_seen"] or "-")[:10],
            } for c in hunt["candidates"]]
            _render_simple_table(table)

            if hunt["non_cdn_candidates"]:
                cand_ips = [c["ip"] for c in hunt["non_cdn_candidates"]]
                pick = st.selectbox("選一個非 CDN 候選 IP，重新跑完整分析：", cand_ips, key="hunt_pick")
                if st.button("👉 深入分析此候選 IP", key="hunt_analyze_btn"):
                    with st.spinner("正在進行 RDAP × BGP × RPKI 多維度交叉檢索…"):
                        try:
                            cand_result = tracer.analyze(pick, timestamp=ts_value, ip2proxy_key=ip2proxy_key)
                            st.session_state["hunt_result"] = cand_result
                        except Exception as e:
                            st.error(f"查詢失敗：{e}")

                cand_result = st.session_state.get("hunt_result")
                if cand_result and cand_result["ip"] in cand_ips:
                    st.markdown(report_mod.render_content(cand_result, domain=resolved_hostname),
                               unsafe_allow_html=True)
            else:
                st.info("目前找到的候選 IP 皆為已知 CDN，未發現明顯洩漏的真實主機。")

    # 若有做過 origin 追查（且對應本次網域），一併寫進報告
    _hunt = st.session_state.get("origin_hunt")
    report_hunt = _hunt if (_hunt and resolved_hostname and _hunt.get("domain") == resolved_hostname) else None
    html_report = report_mod.build_html(result, origin_hunt=report_hunt, domain=resolved_hostname)
    st.download_button(
        "📄 下載 HTML 鑑識報告（公文附件）" + ("（含 origin 追查結果）" if report_hunt else ""),
        data=html_report.encode("utf-8"),
        file_name=f"IP溯源報告_{ip}_{tracer.now_tw():%Y%m%d_%H%M}.html",
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

        # --- 批次結果：與 HTML 彙整報告同一份渲染邏輯 ---
        st.markdown(batch_mod.render_content(results), unsafe_allow_html=True)

        col_a, col_b = st.columns(2)
        col_a.download_button(
            "📄 下載 HTML 彙整報告",
            data=batch_mod.to_html(results).encode("utf-8"),
            file_name=f"IP批次溯源_{tracer.now_tw():%Y%m%d_%H%M}.html",
            mime="text/html",
        )
        col_b.download_button(
            "📥 下載 CSV",
            data=batch_mod.to_csv(results).encode("utf-8-sig"),  # BOM 讓 Excel 正確顯示中文
            file_name=f"IP批次溯源_{tracer.now_tw():%Y%m%d_%H%M}.csv",
            mime="text/csv",
        )
