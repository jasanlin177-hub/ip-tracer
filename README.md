# 科偵 IP 智慧溯源分析系統

輸入涉案 **IP 或網址**，系統自動跑完 **RDAP（法定產權）× BGP（實體路由 LPM）× RPKI（劫持偵測）**
交叉比對，辨識 **CDN／反向代理遮蔽**，並嘗試**追查真實來源 IP（origin IP）**，
直接吐出「公文要發給誰」的偵辦建議與可列印的 HTML 鑑識報告。全程使用即時 API，**無任何寫死資料**。

## 🌐 線上使用（已部署，全國科偵可直接用）
👉 **https://ip-tracer-hfn7obwb4gez7kjzaavxye.streamlit.app/**

點開即用，免安裝、免登入，不收集任何查詢紀錄。

## 檔案
| 檔案 | 用途 |
|---|---|
| `tracer.py` | 核心邏輯（純函式）：RDAP / BGP / RPKI / LPM / CDN 偵測 / 定性引擎 / 網域解析。可單獨 CLI 執行 |
| `report.py` | 產生 HTML 鑑識報告（公文附件），含 origin IP 追查區塊 |
| `proxy.py` | 機房／VPN／Proxy 屬性判定（IP2Location.io × ip-api × 啟發式） |
| `origin_finder.py` | CDN 遮蔽案件的 origin IP 追查：crt.sh 憑證紀錄 + AlienVault OTX 歷史 DNS |
| `batch.py` | 批次查詢：多 IP 解析、節流分析、CSV／HTML 彙整輸出 |
| `ip_analyzer.py` | Streamlit 網頁介面（單筆／批次雙模式，單筆支援網址輸入） |

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

## 網址輸入（單筆查詢）
偵查人員一開始通常拿到的是網址而非 IP。單筆查詢的輸入框同時接受 IP 或網址／網域：
- 自動判斷輸入是否為合法 IP；不是的話當網域處理，解析 A/AAAA 紀錄
- 解析出多個 IP 時列出全部，選一個深入分析
- 報告標頭會完整記錄「涉案網域 → 解析 IP」的偵查鏈路，不會存證時只剩 IP、遺失原始查緝目標

## CDN／反向代理偵測
非法網站（如線上博弈）常見套用 Cloudflare／Akamai／Fastly 等 CDN，DNS 解出來的 IP 只是代理節點，
不是真正主機。系統會辨識已知 CDN 的 ASN（`tracer.CDN_ASNS`），改判定為 **CDN_FRONTED**，
明確警示「直接函索此 IP 持有人查不到真正機房，需向 CDN 業者調取 origin IP」，
避免誤判成一般「產權路由一致」而發錯公文對象。

## origin IP 追查
當定性為 `CDN_FRONTED` 時，網頁會出現「🔍 嘗試找出真實來源 IP」按鈕，綜合兩個免金鑰公開服務找線索：
- **crt.sh 憑證透明度紀錄**：枚舉該網域曾申請過憑證的子網域（如 `mail.`／`api.` 常未套 CDN，可能洩漏真實主機）
- **AlienVault OTX Passive DNS**：該網域（含子網域）的歷史 A/AAAA 解析紀錄，含首次/最後出現時間
  （若網域是後來才加裝 CDN，改用 CDN 前的舊紀錄可能就是真實主機）

找到的候選 IP 會標記是否為已知 CDN，**非 CDN 者排最前面、最值得追查**，可一鍵重新跑完整分析。
追查結果與 crt.sh／OTX 原始查證連結會一併寫進下載的 HTML 鑑識報告。

> ⚠️ 兩個服務皆非 100% 穩定（crt.sh 是單一伺服器，常過載 502；OTX 也偶發限流），
> 系統內建少量重試（crt.sh 最多 3 次、OTX 最多 3 次），失敗時會在畫面與報告上**誠實標示**
> 「略過／失敗」，不會靜默回空清單讓人誤以為「沒有資料」。找不到線索也不代表沒有 origin，
> 仍應改用正式公文向 CDN 業者調取，或稍後重試。

## 資料來源
- **RDAP**：`https://rdap.org/ip/{ip}`（ICANN 官方 bootstrap，302 轉址到權責 RIR）
- **BGP**：RIPEstat `network-info` + `looking-glass`（RIPE RIS 即時路由，支援 `timestamp` 回溯案發時間）
- **ASN 持有人**：RIPEstat `as-overview`
- **RPKI**：RIPEstat `rpki-validation`（valid / invalid / unknown）
- **機房/Proxy**：IP2Location.io（IP2Proxy，免金鑰 1000/日，給金鑰更完整）＋ ip-api.com（proxy/hosting/mobile）＋ ASN 關鍵字/BGP 分租結構啟發式

## 原始工具查證連結
每份報告最後附「🔗 原始工具查證連結」，一鍵帶入本次查詢的 IP／網段開新分頁核對：
- RDAP 原始資料（`rdap.org/ip/{ip}`，與本系統查的是同一份權威資料）
- ICANN RDAP Lookup 官方頁面（該站 `?q=` 參數不支援帶入，需自行貼上 IP）
- bgp.tools 路由查詢（`bgp.tools/prefix/{網段}`，已帶入最精準網段）
- IP2Proxy 快查官方頁面（需自行貼上 IP）

供偏好「自己查原始工具再截圖存證」的同仁快速交叉比對，而非只信任本系統整合後的研判結果。

## 機房/VPN/Proxy 判定邏輯
綜合三來源分級 HIGH / MEDIUM / LOW：
- **HIGH**：IP2Proxy/ip-api 標記 Proxy/VPN，或名稱含防彈機房關鍵字
- **MEDIUM**：標記 Hosting、ASN 名稱含機房關鍵字，或 **BGP 分租結構（大房東≠二房東）**
- **LOW**：均未觸發

> ⚠️ 重要：商用黑名單對「新租用之廉價機房 VPS」常標為未偵測（實測本案 Moack IP 即被 IP2Location/ip-api/ipapi.is 全標為非 proxy）。
> 故本系統額外以 **BGP 分租結構**作為機房證據——這是資料庫抓不到、但辦案最關鍵的結構訊號。LOW 不代表必非機房。

## 偵查定性邏輯
判定優先順序（由上到下）：
- **CDN_FRONTED**：IP 屬於已知 CDN／反向代理 → 優先權最高，警示需向 CDN 業者調 origin IP
- **HIJACK_SUSPECT**：RPKI = invalid → 疑似路由劫持，證據力優先採 RDAP
- **SUBLEASE**：大房東(RDAP) ≠ 二房東(BGP holder) → 產出雙重發文建議
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

需要進版控的檔案：`ip_analyzer.py`、`tracer.py`、`proxy.py`、`origin_finder.py`、`batch.py`、`report.py`、
`requirements.txt`、`.streamlit/config.toml`。（`.gitignore` 已排除本機測試產出。）

**營運提醒（非機密）**：ip-api 免費版依伺服器 IP 限速 45 次/分，全國共用一個網址時共享此額度；
人多時可申請付費金鑰或改採本機/內網各自執行。

## 時效性
BGP 路由具時效，正式辦案請用「回溯案發時間點路由」並保全原始 API 回應（單筆頁面下方「原始 API 回應」可展開存證）。

## 時區
Streamlit Cloud 伺服器跑 UTC，所有顯示給使用者的時間（報告產製時間、下載檔名）一律經 `tracer.now_tw()`
轉換為台灣時間並標註「（UTC+8）」，避免時間顯示少 8 小時、日期跳到前一天。日後若新增顯示時間的地方，
記得用 `tracer.now_tw()` 而非直接呼叫 `datetime.now()`。

## 可擴充
- RDAP 歷史版本與 BGP 時間軸比對圖
- 更多 Proxy/威脅情資來源整合（如 IPQS，需金鑰）
- 網站原始碼掃描找 origin IP 洩漏（如子網域未套 CDN 的連結、內嵌資源網址）— 因涉及對目標網站發請求，
  風險與複雜度較高，目前僅做 crt.sh + OTX 兩個被動查詢管道
- 批次查詢目前僅接受 IP，尚未支援批次網址輸入
