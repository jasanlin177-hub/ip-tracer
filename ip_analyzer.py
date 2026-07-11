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

    # --- 查詢結果：與 HTML 報告同一份渲染邏輯 ---
    st.markdown(report_mod.render_content(result), unsafe_allow_html=True)

    html_report = report_mod.build_html(result)
    st.download_button(
        "📄 下載 HTML 鑑識報告（公文附件）",
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
