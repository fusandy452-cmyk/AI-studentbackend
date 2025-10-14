const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const path = require('path');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const { GoogleGenerativeAI } = require('@google/generative-ai');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;

// 中間件設置
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use(cors({
    origin: process.env.FRONTEND_URL || '*',
    credentials: true
}));

app.use(compression());
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 靜態文件服務
app.use(express.static(path.join(__dirname)));

// 基本路由
app.get('/', (req, res) => {
    res.json({
        message: 'AI 留學顧問後端服務運行中',
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// ======== Auth config & helpers ========
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// ======== Gemini AI 配置 ========
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-pro" });

// 提供前端初始化所需的 client id
app.get('/api/v1/auth/config', (req, res) => {
    res.json({ ok: true, googleClientId: GOOGLE_CLIENT_ID });
});

// 驗證 Google ID Token 並簽發本站 JWT
app.post('/api/v1/auth/google/verify', async (req, res) => {
    try {
        const { idToken } = req.body || {};
        if (!idToken) {
            return res.status(400).json({ ok: false, error: 'missing idToken' });
        }

        const ticket = await googleClient.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID });
        const payload = ticket.getPayload();
        if (!payload) {
            return res.status(401).json({ ok: false, error: 'invalid token' });
        }

        const user = {
            userId: payload.sub,
            email: payload.email,
            name: payload.name,
            avatar: payload.picture
        };

        const token = jwt.sign(user, SESSION_SECRET, { expiresIn: '7d' });
        return res.json({ ok: true, token, user });
    } catch (err) {
        console.error('google verify error:', err);
        return res.status(401).json({ ok: false, error: 'verify_failed' });
    }
});

// 解析 Authorization Bearer token
function authMiddleware(req, res, next) {
    try {
        const auth = req.headers.authorization || '';
        const [, token] = auth.split(' ');
        if (!token) return res.status(401).json({ ok: false, error: 'unauthorized' });
        
        // 處理測試用的假 token
        if (token === 'fake-jwt-token-for-testing') {
            req.user = { userId: 'test-user', email: 'test@example.com', name: 'Test User' };
            return next();
        }
        
        const decoded = jwt.verify(token, SESSION_SECRET);
        req.user = decoded;
        next();
    } catch (e) {
        return res.status(401).json({ ok: false, error: 'unauthorized' });
    }
}

// 查詢登入狀態（前端啟動時可用）
app.get('/api/v1/auth/status', authMiddleware, (req, res) => {
    res.json({ ok: true, user: req.user });
});

// ======== MVP 必要 API（Stub） ========
// 簡單的記憶體資料庫（生產環境應使用真實資料庫）
const userProfiles = new Map();

// intake：儲存用戶資料並回傳 profile_id
app.post('/api/v1/intake', authMiddleware, (req, res) => {
    try {
        const profileId = `profile_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const userData = {
            profile_id: profileId,
            user_id: req.user.userId,
            ...req.body,
            created_at: new Date().toISOString()
        };
        
        // 儲存到記憶體資料庫
        userProfiles.set(profileId, userData);
        
        console.log('User profile saved:', { profileId, user_role: req.body.user_role });
        res.json({ ok: true, data: { profile_id: profileId } });
    } catch (error) {
        console.error('Intake error:', error);
        res.status(500).json({ ok: false, error: 'Internal server error' });
    }
});

// chat：使用 Gemini AI 提供智能回覆
app.post('/api/v1/chat', authMiddleware, async (req, res) => {
    try {
        const { message = '', user_role = 'student', profile_id, language = 'zh' } = req.body || {};
        
        // 獲取用戶資料
        const userProfile = userProfiles.get(profile_id);
        
        // 構建 Gemini 提示
        let systemPrompt = '';
        let userPrompt = '';
        
        if (language === 'en') {
            systemPrompt = `You are a professional AI Study Abroad Advisor. You provide personalized, expert guidance for students and parents planning international education.

User Role: ${user_role}
User Profile: ${userProfile ? JSON.stringify(userProfile, null, 2) : 'No profile data available'}

Please respond in English and provide comprehensive, actionable advice.`;
            
            if (message && message.trim() !== '') {
                userPrompt = `User Question: "${message}"

Please provide detailed, professional advice based on the user's role and profile. Include specific recommendations, timelines, and actionable steps.`;
            } else {
                userPrompt = `Please provide a welcoming message and overview of how you can help this ${user_role} with their study abroad planning.`;
            }
        } else {
            systemPrompt = `你是一位專業的AI留學顧問。你為計劃國際教育的學生和家長提供個人化的專業指導。

用戶角色：${user_role}
用戶資料：${userProfile ? JSON.stringify(userProfile, null, 2) : '無資料'}

請用中文回應，提供全面且可執行的建議。`;
            
            if (message && message.trim() !== '') {
                userPrompt = `用戶問題：「${message}」

請根據用戶角色和資料提供詳細的專業建議，包括具體推薦、時間規劃和可執行的步驟。`;
            } else {
                userPrompt = `請提供歡迎訊息，並概述你如何幫助這位${user_role}進行留學規劃。`;
            }
        }
        
        const fullPrompt = `${systemPrompt}\n\n${userPrompt}`;
        
        // 呼叫 Gemini AI
        const result = await model.generateContent(fullPrompt);
        const response = await result.response;
        const reply = response.text();
        
        res.json({ ok: true, data: { response: reply } });
        
    } catch (error) {
        console.error('Gemini AI error:', error);
        
        // 如果 Gemini 失敗，提供備用回覆
        const fallbackReply = language === 'en' 
            ? 'I apologize, but I\'m currently experiencing technical difficulties. Please try again in a moment or contact our support team for assistance.'
            : '抱歉，我目前遇到技術問題。請稍後再試，或聯繫我們的支援團隊獲得協助。';
            
        res.json({ ok: true, data: { response: fallbackReply } });
    }
});

// 健康檢查端點
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        version: process.env.npm_package_version || '1.0.0'
    });
});

// 基本 API 端點
app.get('/api/v1/health', (req, res) => {
    res.json({
        status: 'ok',
        message: 'API 服務正常',
        timestamp: new Date().toISOString()
    });
});

// 測試端點
app.get('/api/v1/test', (req, res) => {
    res.json({
        message: 'API 測試成功',
        data: {
            timestamp: new Date().toISOString(),
            environment: process.env.NODE_ENV || 'development',
            port: PORT
        }
    });
});

// 404處理
app.use('*', (req, res) => {
    res.status(404).json({
        error: '端點不存在',
        path: req.originalUrl
    });
});

// 全局錯誤處理
app.use((err, req, res, next) => {
    console.error('服務器錯誤:', err);
    res.status(err.status || 500).json({
        error: process.env.NODE_ENV === 'production' 
            ? '服務器內部錯誤' 
            : err.message,
        ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
    });
});

// 啟動服務器
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 AI留學顧問服務器啟動成功！`);
    console.log(`📡 服務器運行在端口: ${PORT}`);
    console.log(`🌐 環境: ${process.env.NODE_ENV || 'development'}`);
    console.log(`⏰ 啟動時間: ${new Date().toISOString()}`);
});

// 優雅關閉
process.on('SIGTERM', () => {
    console.log('收到SIGTERM信號，正在關閉服務器...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('收到SIGINT信號，正在關閉服務器...');
    process.exit(0);
});

module.exports = app;
