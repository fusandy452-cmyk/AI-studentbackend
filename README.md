# AI 留學顧問 - 後端服務 (微服務架構)

## 🚀 專案概述

這是 AI 留學顧問平台的後端服務，採用微服務架構設計，提供完整的 API 服務，包括用戶認證、資料管理、AI 對話和系統管理功能。整合 Google OAuth 2.0、LINE Login、Gemini AI，並通過 API 與獨立的資料庫服務進行通信。

## 🏗️ 微服務架構

### 服務分離
```
前端服務 (aistudent.zeabur.app)
    ↓ API 調用
後端服務 (aistudentbackend.zeabur.app) ← 本專案
    ↓ API 調用
資料庫服務 (ai-studentdatabas.zeabur.app)
```

### 架構優勢
- ✅ **獨立部署**：各服務可獨立擴展和更新
- ✅ **故障隔離**：單一服務故障不影響整體系統
- ✅ **技術多樣性**：可為不同服務選擇最適合的技術棧
- ✅ **團隊協作**：不同團隊可獨立開發不同服務

## 🌟 完整功能列表

### 🔐 用戶認證系統
- ✅ **Google OAuth 2.0**：完整的 OAuth 2.0 流程
- ✅ **LINE Login**：LINE 第三方登入整合
- ✅ **JWT Token**：安全的身份驗證機制
- ✅ **Cookie 安全**：支援 Cookie 和 Header 雙重認證
- ✅ **Token 驗證**：完整的 JWT 驗證和錯誤處理

### 📊 資料庫通信
- ✅ **DatabaseClient**：統一的資料庫服務客戶端
- ✅ **API 通信**：通過 HTTP API 與資料庫服務通信
- ✅ **錯誤處理**：完整的 API 錯誤處理和重試機制
- ✅ **健康檢查**：資料庫服務連接狀態監控
- ✅ **資料同步**：與資料庫服務的資料一致性保證

### 💬 AI 對話系統
- ✅ **Gemini AI 整合**：Google Gemini AI 服務
- ✅ **知識庫整合**：RAG (檢索增強生成)
- ✅ **角色感知**：根據用戶身份提供個性化回應
- ✅ **上下文記憶**：記住用戶設定和對話歷史
- ✅ **多語言支援**：中文/英文 AI 回應
- ✅ **智能摘要**：自動生成對話摘要

### 👨‍👩‍👧‍👦 家長專用功能
- ✅ **學生進度查詢**：家長查看孩子諮詢進度
- ✅ **統計分析**：活動統計和進度分析
- ✅ **AI 分析報告**：智能生成學習建議
- ✅ **進度追蹤**：詳細的諮詢記錄追蹤

### ⚙️ 系統管理
- ✅ **健康檢查**：系統狀態監控
- ✅ **管理員面板**：Web 界面管理系統
- ✅ **用戶搜尋**：管理員用戶查詢功能
- ✅ **統計報表**：系統使用統計和分析
- ✅ **服務監控**：資料庫服務連接狀態

### 🔒 安全性功能
- ✅ **CORS 設定**：跨域請求安全控制
- ✅ **輸入驗證**：API 參數驗證和清理
- ✅ **錯誤處理**：完整的錯誤日誌和處理
- ✅ **Cookie 安全**：安全的 Cookie 設定
- ✅ **JWT 安全**：Token 過期和驗證機制

## 🛠️ 技術架構

### 核心技術
- **Python 3.9+**：主要程式語言
- **Flask**：輕量級 Web 框架
- **requests**：HTTP 客戶端庫，用於與資料庫服務通信
- **JWT**：JSON Web Token 認證
- **Google Gemini AI**：AI 對話服務
- **OAuth 2.0**：第三方登入認證

### 依賴套件
```
Flask==2.3.3
requests==2.31.0
google-generativeai==0.3.2
PyJWT==2.8.0
cryptography==41.0.4
python-dotenv==1.0.0
```

### DatabaseClient 架構
```python
class DatabaseClient:
    """資料庫服務客戶端"""
    
    def __init__(self, base_url=None):
        # 使用環境變數配置資料庫服務 URL
        self.base_url = base_url or os.getenv('DATABASE_SERVICE_URL')
    
    # 用戶管理 API
    def save_user(self, user_data)
    def get_all_users(self)
    def get_user(self, user_id)
    
    # 用戶設定 API
    def save_user_profile(self, profile_data)
    def get_user_profile(self, profile_id)
    def get_user_profiles(self, user_id)
    def update_user_profile(self, profile_id, data)
    
    # 聊天記錄 API
    def save_chat_message(self, message_data)
    def get_chat_messages(self, profile_id, limit=100)
    
    # 統計和監控 API
    def health_check(self)
    def get_users_count(self)
    def get_profiles_count(self)
    def get_messages_count(self)
```

## 🔗 API 端點完整列表

### 認證相關 API
```
GET  /api/v1/auth/config          # 獲取認證配置
GET  /api/v1/auth/line/login      # 獲取 LINE 登入 URL
GET  /auth/google/callback        # Google OAuth 回調
GET  /auth/line/callback          # LINE Login 回調
```

### 用戶資料管理 API
```
GET  /api/v1/user/check-profile           # 檢查用戶設定狀態
GET  /api/v1/user/profile/<profile_id>    # 獲取用戶設定資料
PUT  /api/v1/user/update-profile/<id>     # 更新用戶設定
POST /api/v1/intake                       # 提交初始設定
GET  /api/v1/user/sync                    # 跨設備資料同步
```

### 通知設定 API
```
GET  /api/v1/user/notification-settings   # 獲取通知設定
POST /api/v1/user/notification-settings   # 更新通知設定
```

### AI 對話 API
```
POST /api/v1/chat                         # 發送聊天訊息
GET  /api/v1/chat/stream                  # SSE 串流聊天（開發中）
```

### 家長功能 API
```
GET  /api/v1/parent/student-progress      # 查詢學生進度
```

### 系統管理 API
```
GET  /api/v1/health                       # 健康檢查
GET  /api/v1/debug/database               # 資料庫狀態查詢
GET  /api/v1/admin/database-status        # 詳細資料庫資訊
GET  /api/v1/admin/search-user            # 搜尋用戶
```

### 管理員面板
```
GET  /admin.html                          # 管理員 Web 界面
```

## 📁 檔案結構

```
backend/
├── app.py                    # 主要 Flask 應用程式
├── database_client.py        # 資料庫服務客戶端
├── admin.html              # 管理員 Web 界面
├── requirements.txt        # Python 依賴套件
├── zeabur.json            # Zeabur 部署配置
├── runtime.txt            # Python 運行時版本
├── README.md              # 後端說明文檔
├── templates/             # HTML 模板
│   └── popup_close.html
└── knowledge/             # AI 知識庫
    ├── AI留學顧問_FAQ_美國大學申請_v2025-10-14.jsonl
    └── AI留學顧問_KB_美國大學申請_v2025-10-14.md
```

## 🚀 部署指南

### 本地開發
```bash
# 進入後端目錄
cd backend

# 安裝依賴
pip install -r requirements.txt

# 設定環境變數
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
export GEMINI_API_KEY="your-gemini-api-key"
export LINE_CHANNEL_ID="your-line-channel-id"
export LINE_CHANNEL_SECRET="your-line-channel-secret"
export JWT_SECRET_KEY="your-jwt-secret"
export DATABASE_SERVICE_URL="https://ai-studentdatabas.zeabur.app"

# 執行應用程式
python app.py
```

### 雲端部署 (Zeabur)
1. 將 `backend/` 目錄推送到 GitHub
2. 在 Zeabur 中連接 GitHub 倉庫
3. 選擇 `backend` 目錄作為根目錄
4. 設定部署類型為 "Python"
5. 配置環境變數
6. 自動部署完成

### 環境變數配置
```bash
# Google OAuth
GOOGLE_CLIENT_ID=300123710303-m4j1laa65p664n5vtrdkfvfa7b42c2o6.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Gemini AI
GEMINI_API_KEY=your-gemini-api-key

# LINE Login
LINE_CHANNEL_ID=2008117059
LINE_CHANNEL_SECRET=your-line-channel-secret

# JWT 安全
JWT_SECRET_KEY=your-jwt-secret-key

# 前端 URL
FRONTEND_URL=https://aistudent.zeabur.app
API_BASE_URL=https://aistudentbackend.zeabur.app

# 資料庫服務 URL (重要!)
DATABASE_SERVICE_URL=https://ai-studentdatabas.zeabur.app
```

## 🔧 核心功能實現

### DatabaseClient 初始化
```python
def __init__(self, base_url=None):
    # 初始化資料庫服務客戶端
    self.base_url = base_url or os.getenv('DATABASE_SERVICE_URL')
    self.session = requests.Session()
```

### JWT 認證系統
```python
def verify_jwt_token(f):
    """JWT Token 驗證裝飾器"""
    # 1. 從 Cookie 或 Header 讀取 Token
    # 2. 驗證 Token 有效性
    # 3. 檢查過期時間
    # 4. 設定 request.user
```

### AI 對話處理
```python
def gemini_generate_text(prompt):
    """使用 Gemini AI 生成回應"""
    # 1. 載入 AI 模型
    # 2. 處理提示詞
    # 3. 生成回應
    # 4. 錯誤處理和重試
```

### 資料庫服務通信
```python
def _make_request(self, method, endpoint, data=None, params=None):
    """發送 HTTP 請求到資料庫服務"""
    # 1. 構建請求 URL
    # 2. 發送 HTTP 請求
    # 3. 處理回應
    # 4. 錯誤處理和重試
```

### 健康檢查
```python
def health_check(self):
    """檢查系統健康狀態"""
    # 1. 檢查後端服務狀態
    # 2. 檢查資料庫服務連接
    # 3. 檢查 AI 服務狀態
    # 4. 返回綜合健康報告
```

## 🎯 系統特色

### 微服務設計
- **服務解耦**：資料庫邏輯獨立部署
- **API 通信**：標準化的 HTTP API 接口
- **錯誤隔離**：單一服務故障不影響整體
- **獨立擴展**：各服務可獨立擴展資源

### 安全性設計
- **JWT 認證**：安全的 Token 機制
- **Cookie 安全**：HttpOnly、Secure、SameSite 設定
- **輸入驗證**：所有 API 參數驗證
- **CORS 控制**：跨域請求安全限制
- **錯誤處理**：不洩露敏感資訊

### 效能優化
- **HTTP 連接池**：資料庫服務連接重用
- **快取機制**：常用資料快取
- **非同步處理**：AI 請求非同步化
- **錯誤重試**：網路請求自動重試

### 監控和日誌
- **健康檢查**：系統狀態監控
- **使用統計**：API 使用情況追蹤
- **錯誤日誌**：詳細的錯誤記錄
- **效能監控**：回應時間追蹤
- **服務監控**：資料庫服務連接狀態

## 🐛 常見問題

### Q: 如何解決資料庫服務連接錯誤？
A: 檢查 `DATABASE_SERVICE_URL` 環境變數是否正確設定，確認資料庫服務是否正常運行。

### Q: Gemini AI 回應失敗？
A: 確認 `GEMINI_API_KEY` 環境變數設定正確，檢查 API 配額。

### Q: Google OAuth 登入失敗？
A: 檢查 `GOOGLE_CLIENT_ID` 和 `GOOGLE_CLIENT_SECRET`，確認回調 URL 設定。

### Q: LINE Login 無法使用？
A: 確認 `LINE_CHANNEL_ID` 和 `LINE_CHANNEL_SECRET`，檢查 Channel 狀態。

### Q: 管理員面板無法訪問？
A: 確認管理員帳號已創建，檢查 JWT Token 有效性。

### Q: 後台管理系統顯示「載入失敗」？
A: 檢查資料庫服務是否正常運行，確認 `DATABASE_SERVICE_URL` 配置正確。

## 📊 監控和維護

### 健康檢查
```bash
# 檢查系統狀態
curl https://aistudentbackend.zeabur.app/api/v1/health

# 檢查資料庫服務連接
curl https://ai-studentdatabas.zeabur.app/health
```

### 服務監控
```bash
# 檢查後端服務日誌
# 在 Zeabur 控制台查看部署日誌

# 檢查資料庫服務狀態
curl https://ai-studentdatabas.zeabur.app/health
```

### 日誌查看
- **Zeabur 控制台**：查看部署日誌
- **應用程式日誌**：Python logging 輸出
- **錯誤追蹤**：詳細的錯誤堆疊資訊
- **API 監控**：資料庫服務 API 調用日誌

## 🔗 相關服務

### 前端服務
- **GitHub 倉庫**：`AI-studentfrontend`
- **部署 URL**：`https://aistudent.zeabur.app`
- **功能**：用戶界面、認證、設定、聊天

### 資料庫服務
- **GitHub 倉庫**：`AI-studentdatabase`
- **部署 URL**：`https://ai-studentdatabas.zeabur.app`
- **功能**：資料存儲、用戶管理、統計分析

## 📞 技術支援

如需技術支援，請聯繫：
- **GitHub Issues**: [專案 Issues 頁面](https://github.com/your-repo/issues)
- **Email**: backend-support@aistudyadvisor.com

---

**後端開發團隊** - 提供穩定可靠的微服務架構 🎓🚀

## 📝 更新日誌

### 最新更新 (2025-10-17)
- ✅ **微服務架構分離**：將資料庫功能獨立為單獨服務
- ✅ **DatabaseClient 實現**：統一的資料庫服務客戶端
- ✅ **API 通信優化**：標準化的 HTTP API 接口
- ✅ **健康檢查增強**：包含資料庫服務狀態監控
- ✅ **錯誤處理改進**：完善的 API 錯誤處理和重試機制
- ✅ **部署配置更新**：支援獨立部署和擴展

### 歷史更新 (2024)
- ✅ 完整實現所有認證和 API 功能
- ✅ 整合 Google OAuth 2.0 和 LINE Login
- ✅ 實現 Gemini AI 對話系統
- ✅ 建立完整的資料庫架構
- ✅ 添加家長專用功能
- ✅ 實現系統管理和監控
- ✅ 優化資料備份和恢復機制
- ✅ 完善錯誤處理和安全性
- ✅ 支援跨設備資料同步
- ✅ 實現管理員 Web 界面