# AI 留學顧問 - 後端 API

這是 AI 留學顧問智能體的後端 API 服務，提供 AI 對話、用戶管理和知識庫功能。

## 功能特色

- 🤖 Gemini AI 整合
- 🔐 Google 和 LINE 登入認證
- 🌐 中英文語言支援
- 📚 動態知識庫管理
- 👥 用戶資料管理
- 📊 管理員儀表板

## 專案結構

```
backend/
├── server.js              # 主服務器檔案
├── app.js                 # 應用邏輯
├── package.json           # 依賴配置
├── zeabur.json           # 部署配置
├── .zeaburignore         # 忽略檔案
├── services/             # 服務層
│   ├── authService.js     # 認證服務
│   ├── languageService.js # 語言服務
│   ├── geminiService.js   # AI 服務
│   └── knowledgeBaseService.js # 知識庫服務
├── routes/               # 路由層
│   └── api.js            # API 路由
└── knowledge/            # 知識庫檔案
    ├── AI留學顧問_KB_美國大學申請_v2025-10-14.md
    └── AI留學顧問_FAQ_美國大學申請_v2025-10-14.jsonl
```

## API 端點

### 認證相關
- `GET /auth/status` - 獲取認證狀態
- `GET /auth/google` - Google 登入
- `GET /auth/line` - LINE 登入
- `GET /auth/logout` - 登出

### AI 對話
- `POST /api/v1/chat` - AI 對話
- `POST /api/v1/handoff` - 轉接真人顧問

### 知識庫管理
- `GET /api/v1/knowledge/search` - 搜尋知識庫
- `POST /api/v1/knowledge/update` - 更新知識庫

### 管理員功能
- `GET /api/v1/admin/dashboard` - 管理員儀表板
- `GET /api/v1/admin/user/:id` - 用戶詳情

## 環境變數

```env
NODE_ENV=production
PORT=8080
FRONTEND_URL=https://aistudent.zeabur.app
GEMINI_API_KEY=your_gemini_api_key
SESSION_SECRET=your_session_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
LINE_CHANNEL_ID=your_line_channel_id
LINE_CHANNEL_SECRET=your_line_channel_secret
```

## 部署說明

1. 將此資料夾內容上傳到後端 GitHub 倉庫
2. 在 Zeabur 中創建新的 Node.js 專案
3. 連接 GitHub 倉庫
4. 設定環境變數
5. 設定域名：`aistudentbackend.zeabur.app`

## 開發

```bash
npm install
npm run dev
```

## 注意事項

- 確保所有環境變數已正確設定
- 檢查 OAuth 憑證是否有效
- 測試所有 API 端點功能
