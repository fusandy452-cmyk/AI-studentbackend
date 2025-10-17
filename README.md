# AI 留學顧問 - 後端完整功能指南

## 🚀 專案概述

這是 AI 留學顧問平台的後端服務，提供完整的 API 服務，包括用戶認證、資料管理、AI 對話和系統管理功能。整合 Google OAuth 2.0、LINE Login、Gemini AI 和 SQLite 資料庫。

## 🌟 完整功能列表

### 🔐 用戶認證系統
- ✅ **Google OAuth 2.0**：完整的 OAuth 2.0 流程
- ✅ **LINE Login**：LINE 第三方登入整合
- ✅ **JWT Token**：安全的身份驗證機制
- ✅ **Cookie 安全**：支援 Cookie 和 Header 雙重認證
- ✅ **Token 驗證**：完整的 JWT 驗證和錯誤處理

### 📊 資料庫管理
- ✅ **SQLite 資料庫**：輕量級本地資料庫
- ✅ **用戶資料表**：用戶基本資訊管理
- ✅ **設定資料表**：留學需求設定儲存
- ✅ **聊天記錄表**：對話歷史持久化
- ✅ **使用統計表**：系統使用情況追蹤
- ✅ **管理員系統**：後台管理功能
- ✅ **資料備份**：自動備份和恢復機制

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
- ✅ **資料庫管理**：備份、恢復、狀態查詢
- ✅ **管理員面板**：Web 界面管理系統
- ✅ **用戶搜尋**：管理員用戶查詢功能
- ✅ **統計報表**：系統使用統計和分析

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
- **SQLite**：嵌入式資料庫
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

### 資料庫架構
```sql
-- 用戶表
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    avatar TEXT,
    provider TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 用戶設定表
CREATE TABLE user_profiles (
    profile_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    user_role TEXT NOT NULL,
    student_name TEXT,
    student_email TEXT,
    parent_name TEXT,
    parent_email TEXT,
    relationship TEXT,
    child_name TEXT,
    child_email TEXT,
    citizenship TEXT,
    gpa REAL,
    degree TEXT,
    countries TEXT,
    budget INTEGER,
    target_intake TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (user_id)
);

-- 聊天記錄表
CREATE TABLE chat_messages (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    profile_id INTEGER,
    message TEXT NOT NULL,
    response TEXT NOT NULL,
    user_role TEXT,
    language TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (user_id),
    FOREIGN KEY (profile_id) REFERENCES user_profiles (profile_id)
);

-- 通知設定表
CREATE TABLE user_settings (
    setting_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    email_notifications BOOLEAN DEFAULT FALSE,
    push_notifications BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (user_id)
);

-- 管理員表
CREATE TABLE admins (
    admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
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
POST /api/v1/admin/backup                 # 手動備份資料庫
POST /api/v1/admin/restore                # 恢復資料庫
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
├── database.py              # 資料庫管理模組
├── admin.html              # 管理員 Web 界面
├── requirements.txt        # Python 依賴套件
├── zeabur.json            # Zeabur 部署配置
├── README.md              # 後端說明文檔
├── README_COMPLETE.md     # 完整功能指南（本文件）
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
```

## 🔧 核心功能實現

### 資料庫初始化
```python
def init_database():
    """初始化資料庫和表結構"""
    # 1. 建立資料庫連接
    # 2. 創建所有必要的表
    # 3. 設定資料庫優化參數
    # 4. 創建初始備份
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

### 知識庫整合
```python
def load_knowledge_base():
    """載入 AI 知識庫"""
    # 1. 讀取 Markdown 知識檔案
    # 2. 解析 JSONL 問答資料
    # 3. 建立搜尋索引
    # 4. 提供 RAG 功能
```

### 資料備份系統
```python
def create_backup():
    """創建資料庫備份"""
    # 1. 生成時間戳檔名
    # 2. 複製資料庫檔案
    # 3. 壓縮備份檔案
    # 4. 管理備份保留策略
```

## 🎯 系統特色

### 安全性設計
- **JWT 認證**：安全的 Token 機制
- **Cookie 安全**：HttpOnly、Secure、SameSite 設定
- **輸入驗證**：所有 API 參數驗證
- **CORS 控制**：跨域請求安全限制
- **錯誤處理**：不洩露敏感資訊

### 效能優化
- **資料庫優化**：WAL 模式、快取設定
- **連接池**：資料庫連接管理
- **快取機制**：常用資料快取
- **非同步處理**：AI 請求非同步化

### 監控和日誌
- **健康檢查**：系統狀態監控
- **使用統計**：API 使用情況追蹤
- **錯誤日誌**：詳細的錯誤記錄
- **效能監控**：回應時間追蹤

### 資料持久化
- **自動備份**：定期資料庫備份
- **恢復機制**：快速災難恢復
- **資料遷移**：版本升級支援
- **持久化儲存**：Zeabur 持久化目錄

## 🐛 常見問題

### Q: 如何解決資料庫連接錯誤？
A: 檢查資料庫檔案權限和路徑，確保 Zeabur 持久化目錄設定正確。

### Q: Gemini AI 回應失敗？
A: 確認 GEMINI_API_KEY 環境變數設定正確，檢查 API 配額。

### Q: Google OAuth 登入失敗？
A: 檢查 GOOGLE_CLIENT_ID 和 GOOGLE_CLIENT_SECRET，確認回調 URL 設定。

### Q: LINE Login 無法使用？
A: 確認 LINE_CHANNEL_ID 和 LINE_CHANNEL_SECRET，檢查 Channel 狀態。

### Q: 管理員面板無法訪問？
A: 確認管理員帳號已創建，檢查 JWT Token 有效性。

### Q: 資料庫備份失敗？
A: 檢查 `/data/backups` 目錄權限，確認磁碟空間充足。

## 📊 監控和維護

### 健康檢查
```bash
# 檢查系統狀態
curl https://aistudentbackend.zeabur.app/api/v1/health

# 檢查資料庫狀態
curl https://aistudentbackend.zeabur.app/api/v1/debug/database
```

### 資料庫維護
```bash
# 手動備份
curl -X POST https://aistudentbackend.zeabur.app/api/v1/admin/backup

# 檢查備份狀態
curl https://aistudentbackend.zeabur.app/api/v1/admin/database-status
```

### 日誌查看
- **Zeabur 控制台**：查看部署日誌
- **應用程式日誌**：Python logging 輸出
- **錯誤追蹤**：詳細的錯誤堆疊資訊

## 📞 技術支援

如需技術支援，請聯繫：
- **GitHub Issues**: [專案 Issues 頁面](https://github.com/your-repo/issues)
- **Email**: backend-support@aistudyadvisor.com

---

**後端開發團隊** - 提供穩定可靠的 AI 留學顧問服務 🎓🚀

## 📝 更新日誌

### 最新更新 (2024)
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
