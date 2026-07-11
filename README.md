# 科偵 IP 智慧溯源分析系統

輸入涉案 IP，系統自動跑完 **RDAP（法定產權）× BGP（實體路由 LPM）× RPKI（劫持偵測）** 交叉比對，
直接吐出「公文要發給誰」的偵辦建議與可列印的 HTML 鑑識報告。全程使用即時 API，**無任何寫死資料**。

## 🌐 線上使用（已部署，全國科偵可直接用）
👉 **https://ip-tracer-hfn7obwb4gez7kjzaavxye.streamlit.app/**

點開即用，免安裝、免登入，不收集任何查詢紀錄。

## 檔案
| 檔案 | 用途 |
|---|---|
| `tracer.py` | 核心邏輯（純函式）：RDAP / BGP / RPKI / LPM / 定性引擎。可單獨 CLI 執行 |
| `report.py` | 產生 HTML 鑑識報告（公文附件） |
| `proxy.py` | 機房／VPN／Proxy 屬性判定（IP2Location.io × ip-api × 啟發式） |
| `batch.py` | 批次查詢：多 IP 解析、節流分析、CSV／HTML 彙整輸出 |
| `ip_analyzer.py` | Streamlit 網頁介面（單筆／批次雙模式） |

> 本工具僅整合公開的 RDAP / RIPEstat / ip-api 查詢，**不登入、不收集、不儲存任何查詢紀錄**。

## 安裝與執行
```bash
pip install -r requirements.txt
streamlit run ip_analyzer.py
```
瀏覽器開 http://localhost:8501 即可使用。

### CLI 快速測試（不開網頁）
```bash
python tracer.py 61.111.248.173      # 單筆完整分析
python batch.py                      # 批次範例（多 IP → CSV）
```

## 批次查詢
網頁上切到「📋 批次查詢」分頁，貼上多個 IP（換行／逗號／空白皆可混雜），系統會：
- 自動抽出合法且不重複的 IP、逐一分析（含節流，避免觸發 ip-api 免費限速 45/分）
- 顯示摘要卡（分租數／疑似劫持數／機房高風險數／失敗數）與彙整表
- 一鍵匯出 **HTML 彙整報告** 或 **CSV**（含 BOM，Excel 開中文正常）

## 資料來源
- **RDAP**：`https://rdap.org/ip/{ip}`（ICANN 官方 bootstrap，302 轉址到權責 RIR）
- **BGP**：RIPEstat `network-info` + `looking-glass`（RIPE RIS 即時路由，支援 `timestamp` 回溯案發時間）
- **ASN 持有人**：RIPEstat `as-overview`
- **RPKI**：RIPEstat `rpki-validation`（valid / invalid / unknown）
- **機房/Proxy**：IP2Location.io（IP2Proxy，免金鑰 1000/日，給金鑰更完整）＋ ip-api.com（proxy/hosting/mobile）＋ ASN 關鍵字/BGP 分租結構啟發式

## 機房/VPN/Proxy 判定邏輯
綜合三來源分級 HIGH / MEDIUM / LOW：
- **HIGH**：IP2Proxy/ip-api 標記 Proxy/VPN，或名稱含防彈機房關鍵字
- **MEDIUM**：標記 Hosting、ASN 名稱含機房關鍵字，或 **BGP 分租結構（大房東≠二房東）**
- **LOW**：均未觸發

> ⚠️ 重要：商用黑名單對「新租用之廉價機房 VPS」常標為未偵測（實測本案 Moack IP 即被 IP2Location/ip-api/ipapi.is 全標為非 proxy）。
> 故本系統額外以 **BGP 分租結構**作為機房證據——這是資料庫抓不到、但辦案最關鍵的結構訊號。LOW 不代表必非機房。

## 偵查定性邏輯
- **SUBLEASE**：大房東(RDAP) ≠ 二房東(BGP holder) → 產出雙重發文建議
- **HIJACK_SUSPECT**：RPKI = invalid → 疑似路由劫持，證據力優先採 RDAP
- **CONSISTENT**：產權與路由一致 → 單一發文
- **NO_BGP**：查無即時 BGP 宣告 → 以 RDAP 為主

## 上架 Streamlit Community Cloud（免費、給多人共用一個網址）
目前已部署於 **https://ip-tracer-hfn7obwb4gez7kjzaavxye.streamlit.app/**（repo：`jasanlin177-hub/ip-tracer`，main file：`ip_analyzer.py`）。
推上 `main` 分支後，Streamlit Cloud 會自動偵測並重新部署，網址不變。

若要另外部署一份（例如給別的單位），詳細圖文步驟見 `deploy_guide.html`。摘要：
1. 把整個資料夾推上 GitHub（公開或私有 repo 皆可）。
2. 登入 [share.streamlit.io](https://share.streamlit.io)（用 GitHub 帳號）。
3. **New app** → 選 repo、branch、Main file 填 `ip_analyzer.py`。
4. （可選）Advanced settings 選 Python 3.11+。
5. Deploy，幾分鐘後得到一個 `https://xxx.streamlit.app` 公開網址，分享給同仁即可。

需要進版控的檔案：`ip_analyzer.py`、`tracer.py`、`proxy.py`、`batch.py`、`report.py`、
`requirements.txt`、`.streamlit/config.toml`。（`.gitignore` 已排除本機測試產出。）

**營運提醒（非機密）**：ip-api 免費版依伺服器 IP 限速 45 次/分，全國共用一個網址時共享此額度；
人多時可申請付費金鑰或改採本機/內網各自執行。

## 時效性
BGP 路由具時效，正式辦案請用「回溯案發時間點路由」並保全原始 API 回應（單筆頁面下方「原始 API 回應」可展開存證）。

## 可擴充
- RDAP 歷史版本與 BGP 時間軸比對圖
- 更多 Proxy/威脅情資來源整合（如 IPQS，需金鑰）
