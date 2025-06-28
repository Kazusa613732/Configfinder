# 🛡️ Configfinder - Sensitive File Scanner

**Configfinder** 是一款命令列工具，專為滲透測試與資安檢測設計，用於掃描網站中常見的機敏設定檔案，支援副檔名分析、Content-Type 比對、登入態模擬、延遲控制與遞迴掃描等功能。

---

## 🚀 功能特色

- 🔍 掃描常見機敏檔案（如 `.env`, `.git`, `phpinfo.php`, `backup.zip` 等）
- 📎 根據副檔名、Content-Type、關鍵字、檔案大小判斷是否可疑
- 📁 支援網站子目錄與子網域遞迴掃描
- 🍪 支援自訂 Cookie 模擬登入狀態
- ⏱️ 支援掃描延遲與多執行緒控制
- 🔒 可阻止跳轉至 CDN 或外部網站
- 🐞 支援 Debug 模式，顯示完整命中分析依據

---

## 📦 安裝方式

```bash
git clone https://github.com/Kazusa613732/Configfinder.git
cd Configfinder
```

---

## 🧭 使用說明

```bash
python3 configfinder.py -u <目標網址> [其他選項]
```

---

### 📋 指令參數

| 參數    | 說明                                                        |
|---------|-------------------------------------------------------------|
| `-u`    | 📌 目標網站根目錄（必填）                                   |
| `-min`  | ⏳ 最小延遲秒數（預設：0）                                   |
| `-max`  | ⏱️ 最大延遲秒數（預設：0）                                   |
| `-t`    | 🔄 並發線程數（預設：1）                                     |
| `-c`    | 🍪 自訂 Cookie（模擬登入狀態）->效果待測 試                               |
| `-sd`   | 📂 掃描子目錄與子網域                                        |
| `-fr`   | 🛑 僅追蹤主網域，避免跳轉至外部網站                         |
| `-d`    | 🐞 開啟 Debug 模式，顯示每筆命中與過濾依據                 |

---

## 💡 使用範例

🔹 **基本掃描：**

```bash
python3 configfinder.py -u https://example.com
```

🔹 **加入延遲與多執行緒：**

```bash
python3 configfinder.py -u https://example.com -min 1 -max 3 -t 5
```

🔹 **模擬登入狀態掃描後台：**

```bash
python3 configfinder.py -u https://example.com/admin -c "PHPSESSID=abc123"
```

🔹 **只掃描主網站、阻擋外部跳轉：**

```bash
python3 configfinder.py -u https://example.com -fr
```

---

## 📁 user_agents.txt 格式

若目錄中存在 `user_agents.txt` 檔案，會隨機選擇其中一行作為請求的 User-Agent。

```
Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)
...
```

---

## 📤 輸出範例

命中時將顯示：

```
[!!] 發現機敏檔案: https://example.com/.env 
     (ext=.env → expect=text/plain, actual=text/plain, size=1024 bytes)
```

---

## 🔍 判斷邏輯簡介

Configfinder 根據以下依據進行機敏檔案偵測：

- **副檔名判斷**：是否為常見敏感副檔名（如 `.env`, `.git/config`, `.sql`, `.bak`, `.zip`, `.pem`, `.key` 等）
- **Content-Type 比對**：是否為 `text/plain`, `application/octet-stream` 等可疑類型，或與副檔名不符
- **檔案大小**：是否非空（通常大於 0 且小於 5MB）
- **內容關鍵字**（如啟用 Debug 模式）：判斷是否包含 `DB_PASSWORD`, `APP_SECRET`, `BEGIN RSA PRIVATE KEY` 等機敏資訊

---

## ⚠️ 使用須知

- 請僅在**合法授權**範圍內使用本工具
- 建議搭配合法滲透測試流程與相關授權聲明
- 若目標網站有 CDN 或 WAF，請使用 `-fr` 限制跳轉，避免誤判

---
