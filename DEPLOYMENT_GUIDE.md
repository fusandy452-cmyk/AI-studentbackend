# AI 留學顧問 - 部署指南

## 📁 文件說明

### 主要文件（用於生產環境）
- **`app-main.py`** - 主要後端應用程式（推薦使用）
  - ✅ 修復了 502 錯誤
  - ✅ 包含完整的 Google 登入功能
  - ✅ 彈出視窗登入支援
  - ✅ 健康檢查路由正確配置

### 備份文件
- **`app.py`** - 原始後端文件（功能完整但可能有部署問題）
- **`app-fixed.py`** - 修復版本（已整合到 app-main.py）

### 配置文件
- **`zeabur.json`** - Zeabur 部署配置
- **`requirements.txt`** - Python 依賴
- **`database.py`** - 資料庫管理

## 🚀 部署步驟

### 1. GitHub 上傳
```bash
# 將以下文件上傳到 GitHub：
- app-main.py (主要後端文件)
- zeabur.json (部署配置)
- requirements.txt (依賴)
- database.py (資料庫)
- admin.html (管理頁面)
- knowledge/ (知識庫)
```

### 2. Zeabur 部署
- 確保 `zeabur.json` 中的 `startCommand` 指向 `app-main:app`
- 部署後檢查健康檢查端點：`/health`

### 3. 環境變數設置
在 Zeabur 控制台設置以下環境變數：
- `GEMINI_API_KEY` - Google Gemini API 金鑰
- `GOOGLE_CLIENT_ID` - Google OAuth 客戶端 ID
- `GOOGLE_CLIENT_SECRET` - Google OAuth 客戶端密鑰
- `SESSION_SECRET` - JWT 會話密鑰
- `LINE_CHANNEL_ID` - LINE 登入頻道 ID（可選）
- `LINE_CHANNEL_SECRET` - LINE 登入頻道密鑰（可選）

## 🔧 調試功能

### 前端調試
- 按 `Ctrl + Shift + D` 開啟調試面板
- 可以測試 Google API、後端配置和登入功能

### 後端調試
- 訪問 `https://aistudentbackend.zeabur.app/health` 檢查健康狀態
- 訪問 `https://aistudentbackend.zeabur.app/` 查看環境變數狀態

## 📋 測試清單

部署完成後請測試：
- [ ] 前端頁面正常載入
- [ ] Google 登入彈出視窗功能
- [ ] 後端 API 響應正常
- [ ] 健康檢查通過
- [ ] 聊天功能正常

## 🆘 故障排除

### 502 錯誤
- 檢查 `zeabur.json` 中的健康檢查路徑是否為 `/health`
- 確認 `startCommand` 指向正確的文件

### Google 登入問題
- 確認環境變數 `GOOGLE_CLIENT_ID` 和 `GOOGLE_CLIENT_SECRET` 已設置
- 檢查前端調試面板的錯誤信息

### 資料庫問題
- 確認 `database.py` 文件存在
- 檢查 Zeabur 的持久化存儲配置
