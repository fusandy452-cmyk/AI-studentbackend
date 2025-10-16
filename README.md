# AI 留學顧問 - 後端服務

## 🚀 概述

這是 AI 留學顧問平台的後端服務，提供 RESTful API、資料庫管理、AI 整合和用戶認證功能。基於 Python Flask 框架，整合 Google Gemini AI 和 OAuth 2.0 認證系統。

## 🌟 核心功能

### 🔐 認證與授權
- **Google OAuth 2.0**：安全的第三方登入整合
- **LINE Login**：支援台灣用戶的登入方式
- **JWT Token**：無狀態的身份認證
- **角色管理**：支援學生和家長兩種身份

### 🤖 AI 智能服務
- **Google Gemini AI 整合**：先進的語言模型
- **知識庫驅動**：基於專業留學知識的智能回覆
- **上下文感知**：記住用戶設定和對話歷史
- **多語言支援**：中文/英文智能切換

### 📊 資料庫管理
- **SQLite 資料庫**：輕量級嵌入式資料庫
- **用戶資料管理**：完整的 CRUD 操作
- **聊天記錄儲存**：對話歷史和分析
- **使用統計**：用戶行為數據收集

### 📧 通知系統
- **郵件通知設定**：用戶偏好管理
- **推送通知**：即時訊息提醒
- **通知頻率控制**：自訂通知間隔

### 👨‍👩‍👧‍👦 家長監控功能
- **學生進度追蹤**：詳細的諮詢進度分析
- **活動統計**：訊息數、活躍天數等指標
- **進度評估**：自動化的進度等級判定
- **建議生成**：基於數據的改進建議

## 🛠️ 技術架構

### 核心技術
- **Python 3.11**：現代化的 Python 版本
- **Flask 2.2.5**：輕量級 Web 框架
- **SQLite**：嵌入式關聯式資料庫
- **JWT**：JSON Web Token 認證
- **Google Gemini AI**：先進的 AI 語言模型

### 依賴套件
```
Flask==2.2.5              # Web 框架
Flask-CORS==4.0.0         # 跨域請求支援
PyJWT==2.8.0              # JWT 處理
google-generativeai==0.3.2 # Gemini AI 整合
gunicorn==20.1.0          # WSGI 伺服器
requests==2.28.2          # HTTP 請求庫
Werkzeug==2.3.7           # WSGI 工具
```

### 架構設計
- **RESTful API**：標準化的 API 設計
- **分層架構**：控制器、服務、資料存取層分離
- **錯誤處理**：統一的錯誤回應格式
- **日誌記錄**：完整的請求追蹤和除錯

## 🔗 與前端整合

### API 端點設計
後端提供完整的 RESTful API 供前端調用：

#### 認證相關 API
```python
GET  /api/v1/auth/config          # 獲取認證配置
GET  /auth/google/callback        # Google OAuth 回調處理
GET  /auth/line/callback          # LINE Login 回調處理
```

#### 用戶資料管理 API
```python
GET  /api/v1/user/check-profile           # 檢查用戶設定狀態
GET  /api/v1/user/profile/<profile_id>    # 獲取用戶設定資料
PUT  /api/v1/user/update-profile/<id>     # 更新用戶設定
POST /api/v1/intake                       # 提交初始設定資料
```

#### 通知設定 API
```python
GET  /api/v1/user/notification-settings   # 獲取通知設定
POST /api/v1/user/notification-settings   # 更新通知設定
```

#### AI 對話 API
```python
POST /api/v1/chat                         # 處理 AI 對話請求
```

#### 家長專用 API
```python
GET  /api/v1/parent/student-progress      # 查詢學生諮詢進度
```

### 資料交換格式
所有 API 使用 JSON 格式進行資料交換：

#### 請求格式範例
```json
{
    "message": "我想申請美國大學",
    "user_role": "student",
    "profile_id": "profile_123456_789",
    "language": "zh"
}
```

#### 回應格式範例
```json
{
    "ok": true,
    "reply": "根據您的背景，我建議您考慮以下美國大學...",
    "data": {
        "user_profile": {...},
        "chat_history": [...]
    }
}
```

### 前端整合要點
- **CORS 設定**：允許前端域名跨域請求
- **JWT 驗證**：所有受保護的 API 需要有效的 JWT Token
- **錯誤處理**：統一的錯誤回應格式，便於前端處理
- **資料驗證**：嚴格的輸入驗證，確保資料完整性

## 📁 專案結構

```
backend/
├── app.py                    # Flask 主應用程式
├── database.py              # 資料庫管理模組
├── requirements.txt         # Python 依賴套件
├── runtime.txt             # Python 版本指定
├── zeabur.json            # 部署配置
├── knowledge/             # AI 知識庫
│   ├── AI留學顧問_KB_美國大學申請_v2025-10-14.md
│   └── AI留學顧問_FAQ_美國大學申請_v2025-10-14.jsonl
├── templates/             # HTML 模板
│   └── popup_close.html   # OAuth 回調頁面
└── README.md             # 後端說明文檔
```

## 🗄️ 資料庫設計

### 核心資料表

#### users - 用戶基本資料
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT UNIQUE NOT NULL,
    email TEXT,
    name TEXT,
    avatar TEXT,
    provider TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### user_profiles - 用戶留學設定
```sql
CREATE TABLE user_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id TEXT UNIQUE NOT NULL,
    user_id TEXT NOT NULL,
    user_role TEXT NOT NULL,
    student_name TEXT,
    student_email TEXT,
    parent_name TEXT,
    parent_email TEXT,
    -- 更多留學相關欄位
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### chat_messages - 聊天記錄
```sql
CREATE TABLE chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    message_type TEXT NOT NULL,  -- 'user' or 'ai'
    message_content TEXT NOT NULL,
    language TEXT,
    user_role TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### user_settings - 用戶設定
```sql
CREATE TABLE user_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT UNIQUE NOT NULL,
    email_notifications BOOLEAN DEFAULT 0,
    push_notifications BOOLEAN DEFAULT 1,
    notification_frequency TEXT DEFAULT 'daily',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 🚀 部署指南

### 本地開發環境
```bash
# 安裝依賴
pip install -r requirements.txt

# 設定環境變數
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
export LINE_CHANNEL_ID="your-line-channel-id"
export LINE_CHANNEL_SECRET="your-line-channel-secret"
export GEMINI_API_KEY="your-gemini-api-key"
export SESSION_SECRET="your-session-secret"

# 啟動開發伺服器
python app.py
```

### 雲端部署 (Zeabur)
1. 將 `backend/` 目錄推送到 GitHub
2. 在 Zeabur 中連接 GitHub 倉庫
3. 選擇 `backend` 目錄作為根目錄
4. 設定環境變數
5. 自動部署完成

### 環境變數配置
```bash
# OAuth 認證
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
LINE_CHANNEL_ID=your-line-channel-id
LINE_CHANNEL_SECRET=your-line-channel-secret

# AI 服務
GEMINI_API_KEY=your-gemini-api-key

# 安全設定
SESSION_SECRET=your-secure-session-secret
```

## 🤖 AI 整合詳解

### Gemini AI 配置
```python
import google.generativeai as genai

# 配置 API Key
genai.configure(api_key=GEMINI_API_KEY)

# 創建模型實例
model = genai.GenerativeModel('gemini-pro')

# 生成內容
response = model.generate_content(prompt)
```

### 知識庫整合
```python
def load_knowledge_base():
    """載入留學顧問知識庫"""
    # 載入 Markdown 知識庫
    with open('knowledge/AI留學顧問_KB_美國大學申請_v2025-10-14.md', 'r') as f:
        md_content = f.read()
    
    # 載入 FAQ 知識庫
    faq_items = []
    with open('knowledge/AI留學顧問_FAQ_美國大學申請_v2025-10-14.jsonl', 'r') as f:
        for line in f:
            item = json.loads(line.strip())
            faq_items.append(f"Q: {item['question']}\nA: {item['answer']}")
    
    return f"KNOWLEDGE BASE:\n{md_content}\n\nFAQ:\n{faq_content}"
```

### 智能提示工程
```python
system_prompt = """你是一位專業的AI留學顧問。

用戶角色：{}
用戶資料：{}
知識庫：{}

重要回覆原則：
1. 回覆要簡潔有重點
2. 使用 emoji 讓內容更生動
3. 每個段落之間必須有空行分隔
4. 使用項目符號 (•) 列出要點
5. 提出 1-2 個後續問題延續對話
6. 總是參考知識庫提供具體資訊

請用中文回應，提供有針對性的建議。"""
```

## 📊 監控與日誌

### 日誌記錄
```python
import logging

# 配置日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# 記錄 API 請求
logger.info(f"Chat request - profile_id: {profile_id}, user_role: {user_role}")
```

### 健康檢查
```python
@app.route('/health', methods=['GET'])
def health_check():
    """系統健康檢查"""
    try:
        # 檢查資料庫連接
        db.get_connection()
        
        # 檢查 AI 服務
        ai_status = "available" if use_gemini() else "unavailable"
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'ai_service': ai_status,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500
```

## 🔒 安全性考量

### 認證與授權
- **JWT Token 驗證**：所有受保護的 API 端點
- **OAuth 2.0**：安全的第三方認證
- **Session 管理**：安全的會話處理

### 資料保護
- **輸入驗證**：嚴格的資料驗證和清理
- **SQL 注入防護**：使用參數化查詢
- **XSS 防護**：輸出資料轉義
- **HTTPS**：強制加密通信

### 錯誤處理
```python
def verify_jwt_token(f):
    """JWT 驗證裝飾器"""
    def wrapper(*args, **kwargs):
        try:
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return jsonify({'ok': False, 'error': 'unauthorized'}), 401
            
            token = auth_header.split(' ')[1]
            decoded = jwt.decode(token, SESSION_SECRET, algorithms=['HS256'])
            request.user = decoded
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f'JWT verification failed: {e}')
            return jsonify({'ok': False, 'error': 'unauthorized'}), 401
    return wrapper
```

## 🧪 測試指南

### 單元測試
```python
import unittest
from app import app, db

class TestAPI(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
    
    def test_health_check(self):
        response = self.app.get('/health')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['status'], 'healthy')
```

### API 測試
```bash
# 測試健康檢查
curl -X GET https://your-backend-url/health

# 測試聊天 API
curl -X POST https://your-backend-url/api/v1/chat \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{"message": "測試訊息", "user_role": "student"}'
```

## 🐛 常見問題

### Q: Gemini AI 沒有回應？
A: 檢查 GEMINI_API_KEY 是否正確設定，以及網路連接是否正常。

### Q: 資料庫連接失敗？
A: 確認 SQLite 檔案權限，以及資料庫初始化是否完成。

### Q: OAuth 登入失敗？
A: 檢查 Google/LINE 的 Client ID 和 Secret 是否正確配置。

### Q: JWT Token 驗證失敗？
A: 確認 SESSION_SECRET 設定正確，以及 Token 格式是否有效。

## 📈 效能優化

### 資料庫優化
- **索引優化**：在常用查詢欄位添加索引
- **查詢優化**：使用適當的 SQL 查詢
- **連接池**：管理資料庫連接

### API 優化
- **快取機制**：快取常用的 API 回應
- **分頁處理**：大量資料的分頁載入
- **異步處理**：長時間操作的異步處理

## 📞 技術支援

如需技術支援，請聯繫：
- **GitHub Issues**: [專案 Issues 頁面](https://github.com/your-repo/issues)
- **Email**: backend-support@aistudyadvisor.com

---

**後端開發團隊** - 為 AI 留學顧問提供強大的技術支撐 🚀✨
