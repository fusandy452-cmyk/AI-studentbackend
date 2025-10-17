# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, redirect, send_file, Response, stream_with_context, make_response
from flask_cors import CORS
import os
import jwt
import json
from datetime import datetime, timedelta
import google.generativeai as genai
import requests  # 用於 Google OAuth 和 LINE OAuth 的 HTTP 請求
from database import DatabaseManager
import urllib.parse
import time
from collections import defaultdict
import re
import html
import logging
import hashlib
import secrets
import threading
# import schedule  # 暫時註解掉避免部署問題

app = Flask(__name__)
CORS(app, origins=["https://aistudent.zeabur.app"])

# 設定日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 環境變數
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY')
GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-2.5-flash')
SESSION_SECRET = os.getenv('SESSION_SECRET', 'dev-secret')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
LINE_CHANNEL_ID = os.getenv('LINE_CHANNEL_ID') or os.getenv('LINE_CLIENT_ID')
LINE_CHANNEL_SECRET = os.getenv('LINE_CHANNEL_SECRET') or os.getenv('LINE_CLIENT_SECRET')

# URL 配置
FRONTEND_URL = 'https://aistudent.zeabur.app'
API_BASE_URL = 'https://aistudentbackend.zeabur.app'

# 載入知識庫
def load_knowledge_base():
    """載入留學顧問知識庫"""
    try:
        knowledge_path = os.path.join(os.path.dirname(__file__), 'knowledge')
        
        # 載入 Markdown 知識庫
        md_file = os.path.join(knowledge_path, 'AI留學顧問_KB_美國大學申請_v2025-10-14.md')
        if os.path.exists(md_file):
            with open(md_file, 'r', encoding='utf-8') as f:
                md_content = f.read()
        else:
            md_content = ""
        
        # 載入 FAQ 知識庫
        jsonl_file = os.path.join(knowledge_path, 'AI留學顧問_FAQ_美國大學申請_v2025-10-14.jsonl')
        faq_content = ""
        if os.path.exists(jsonl_file):
            with open(jsonl_file, 'r', encoding='utf-8') as f:
                faq_items = []
                for line in f:
                    try:
                        item = json.loads(line.strip())
                        faq_items.append(f"Q: {item.get('question', '')}\nA: {item.get('answer', '')}")
                    except:
                        continue
                faq_content = "\n\n".join(faq_items)
        
        return f"MARKDOWN KNOWLEDGE BASE:\n{md_content}\n\nFAQ KNOWLEDGE BASE:\n{faq_content}"
        
    except Exception as e:
        logger.error(f"Error loading knowledge base: {e}")
        return "Knowledge base not available"

def rag_search(query, knowledge_base, top_k=3):
    """RAG 檢索：從知識庫中檢索相關片段"""
    try:
        if not knowledge_base or not query:
            return ""
        
        # 簡單的關鍵字匹配檢索
        query_words = query.lower().split()
        knowledge_sections = knowledge_base.split('\n\n')
        
        scored_sections = []
        for section in knowledge_sections:
            if len(section.strip()) < 50:  # 跳過太短的段落
                continue
            
            section_lower = section.lower()
            score = 0
            
            # 計算關鍵字匹配分數
            for word in query_words:
                if word in section_lower:
                    score += section_lower.count(word)
            
            if score > 0:
                scored_sections.append((score, section))
        
        # 按分數排序，取前 top_k 個
        scored_sections.sort(key=lambda x: x[0], reverse=True)
        top_sections = scored_sections[:top_k]
        
        # 組合檢索結果
        rag_content = ""
        for score, section in top_sections:
            rag_content += section + "\n\n"
        
        logger.info(f"RAG search found {len(top_sections)} relevant sections for query: {query}")
        return rag_content.strip()
        
    except Exception as e:
        logger.error(f"RAG search error: {e}")
        return ""

# 初始化 Gemini AI
def use_gemini():
    return bool(GEMINI_API_KEY)

def gemini_generate_text(prompt):
    """使用 Gemini AI 生成文本"""
    if not use_gemini():
        logger.warning("Gemini API key not configured")
        return ""
    
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        res = model.generate_content(prompt)
        
        # 修復 response.text 錯誤
        try:
            if hasattr(res, 'text') and res.text:
                logger.info(f"Gemini response generated successfully, length: {len(res.text)}")
                return res.text
            elif hasattr(res, 'candidates') and res.candidates:
                # 嘗試從 candidates 中獲取文本
                candidate = res.candidates[0]
                if hasattr(candidate, 'content') and candidate.content:
                    if hasattr(candidate.content, 'parts') and candidate.content.parts:
                        text_parts = []
                        for part in candidate.content.parts:
                            if hasattr(part, 'text') and part.text:
                                text_parts.append(part.text)
                        if text_parts:
                            text = ''.join(text_parts)
                            logger.info(f"Gemini response generated from candidates, length: {len(text)}")
                            return text
                logger.warning("Gemini returned empty response from candidates")
                return ""
            else:
                logger.warning("Gemini returned empty response")
                return ""
        except Exception as text_error:
            logger.error(f"Error accessing Gemini response text: {text_error}")
            return ""
    except Exception as e:
        logger.error(f"Gemini API error: {e}")
        return ""

def gemini_generate_stream(prompt):
    """使用 Gemini AI 生成串流文本"""
    try:
        if not use_gemini():
            logger.warning("Gemini API key not configured")
            yield "data: 抱歉，AI 服務暫時無法使用。\n\n"
            return
        
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        
        logger.info(f"Generating stream with Gemini AI - Model: {GEMINI_MODEL}")
        logger.info(f"Prompt length: {len(prompt)} characters")
        
        # 生成內容
        res = model.generate_content(prompt)
        
        # 嘗試多種方式獲取文本
        text = None
        try:
            if hasattr(res, 'text') and res.text:
                text = res.text
            elif hasattr(res, 'candidates') and res.candidates:
                candidate = res.candidates[0]
                if hasattr(candidate, 'content') and candidate.content:
                    if hasattr(candidate.content, 'parts') and candidate.content.parts:
                        text_parts = []
                        for part in candidate.content.parts:
                            if hasattr(part, 'text') and part.text:
                                text_parts.append(part.text)
                        if text_parts:
                            text = ''.join(text_parts)
        except Exception as text_error:
            logger.error(f"Error accessing Gemini response text: {text_error}")
            yield "data: 抱歉，AI 回應格式有誤，請稍後再試。\n\n"
            return
        
        if not text:
            logger.error("Failed to extract text from Gemini response")
            yield "data: 抱歉，AI 回應格式有誤，請稍後再試。\n\n"
            return
        
        logger.info(f"Generated stream text length: {len(text)} characters")
        
        # 模擬串流：將文本切成 20-40 字的片段
        words = text.split()
        chunk_size = 25  # 平均 25 個字
        
        for i in range(0, len(words), chunk_size):
            chunk_words = words[i:i + chunk_size]
            chunk_text = " ".join(chunk_words)
            
            if i + chunk_size < len(words):
                chunk_text += " "  # 如果不是最後一塊，加個空格
            
            yield f"data: {chunk_text}\n\n"
            time.sleep(0.05)  # 50ms 延遲，模擬打字效果
        
    except Exception as e:
        logger.error(f"Gemini AI stream error: {e}")
        yield "data: 抱歉，AI 服務暫時無法使用，請稍後再試。\n\n"

# 初始化資料庫
try:
    # 使用 Zeabur 的持久化存儲目錄
    import os
    persistent_dir = '/data'
    
    # 確保持久化目錄存在
    if not os.path.exists(persistent_dir):
        try:
            os.makedirs(persistent_dir, exist_ok=True)
            logger.info(f"Created persistent directory: {persistent_dir}")
        except Exception as e:
            logger.warning(f"Failed to create persistent directory: {e}")
    
    # 優先使用持久化存儲
    if os.path.exists(persistent_dir):
        db_path = os.path.join(persistent_dir, 'ai_study_advisor.db')
        logger.info(f"Using persistent storage: {db_path}")
        
        # 檢查是否已有資料庫文件
        if os.path.exists(db_path):
            logger.info(f"Existing database found: {db_path}")
        else:
            logger.info(f"Creating new database: {db_path}")
    else:
        # 如果持久化目錄不存在，使用當前目錄
        db_path = 'ai_study_advisor.db'
        logger.warning(f"Persistent directory not found, using local path: {db_path}")
    
    db = DatabaseManager(db_path=db_path)
    
    # 創建初始備份
    try:
        db.create_backup()
        logger.info("Initial database backup created")
    except Exception as e:
        logger.warning(f"Failed to create initial backup: {e}")
    
    # 確保 user_settings 表格存在（遷移機制）
    try:
        conn = db.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT UNIQUE NOT NULL,
                email_notifications BOOLEAN DEFAULT 0,
                push_notifications BOOLEAN DEFAULT 1,
                notification_frequency TEXT DEFAULT 'daily',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        conn.commit()
        conn.close()
        logger.info("User settings table ensured")
    except Exception as e:
        logger.error(f"User settings table creation failed: {e}")
    
    logger.info("Database initialized successfully")
    
    # 檢查並創建定期備份
    try:
        # 檢查資料庫是否有資料，如果沒有則嘗試從備份恢復
        try:
            test_conn = db.get_connection()
            cursor = test_conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            test_conn.close()
            
            if user_count == 0:
                logger.info("Database is empty, attempting to restore from backup")
                if db.restore_from_backup():
                    logger.info("Successfully restored database from backup")
                else:
                    logger.info("No backup found or restore failed, starting with empty database")
        except Exception as e:
            logger.warning(f"Database check failed: {e}")
        
        # 創建初始備份
        db.create_backup()
        logger.info("Created initial backup")
        
    except Exception as e:
        logger.warning(f"Backup initialization failed: {e}")
        
except Exception as e:
    logger.error(f"Database initialization failed: {e}")
    db = None

# 安全 Cookie 設置函數
def set_secure_cookie(response, key, value, max_age=86400):
    """設置安全的 Cookie"""
    # 檢查是否為 HTTPS 環境
    is_secure = request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https'
    
    # 設置 Cookie 屬性
    response.set_cookie(
        key,
        value,
        max_age=max_age,
        path='/',
        secure=is_secure,  # 只在 HTTPS 下傳輸
        httponly=False,    # 允許 JavaScript 訪問（SSE 需要）
        samesite='Lax'     # 防止 CSRF 攻擊
    )
    
    logger.info(f"Secure cookie set: {key} (secure={is_secure}, samesite=Lax)")
    return response

# JWT 驗證裝飾器
def verify_jwt_token(f):
    """JWT 驗證裝飾器"""
    def wrapper(*args, **kwargs):
        try:
            # 優先從 Cookie 獲取 token，其次從 Authorization header
            token = request.cookies.get("jwt") or ""
            if not token and "Authorization" in request.headers:
                auth_header = request.headers.get('Authorization', '')
                if auth_header.startswith('Bearer '):
                    token = auth_header.split(' ')[1]
            
            if not token:
                return jsonify({'ok': False, 'error': 'unauthorized'}), 401
            
            # 處理測試用的假 token
            if token == 'fake-jwt-token-for-testing':
                request.user = {
                    'user_id': 'test-user',
                    'email': 'test@example.com',
                    'name': 'Test User'
                }
                return f(*args, **kwargs)
            
            decoded = jwt.decode(token, SESSION_SECRET, algorithms=['HS256'])
            request.user = decoded
            return f(*args, **kwargs)
            
        except Exception as e:
            return jsonify({'ok': False, 'error': 'unauthorized'}), 401
    wrapper.__name__ = f.__name__
    return wrapper

# 速率限制
rate_limit_storage = defaultdict(list)
RATE_LIMIT_WINDOW = 60  # 60秒
RATE_LIMIT_MAX_REQUESTS = 10  # 每分鐘最多10次請求

def check_rate_limit(ip_address):
    """檢查速率限制"""
    current_time = time.time()
    # 清理過期的請求記錄
    rate_limit_storage[ip_address] = [
        req_time for req_time in rate_limit_storage[ip_address]
        if current_time - req_time < RATE_LIMIT_WINDOW
    ]
    
    # 檢查是否超過限制
    if len(rate_limit_storage[ip_address]) >= RATE_LIMIT_MAX_REQUESTS:
        return False
    
    # 記錄當前請求
    rate_limit_storage[ip_address].append(current_time)
    return True

def validate_email(email):
    """驗證電子郵件格式"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# 密碼雜湊函數
def hash_password(password):
    """使用 PBKDF2 雜湊密碼"""
    salt = secrets.token_hex(16)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}:{pwdhash.hex()}"

def verify_password(stored_password, provided_password):
    """驗證密碼"""
    try:
        salt, pwdhash = stored_password.split(':')
        pwdhash_bytes = bytes.fromhex(pwdhash)
        new_pwdhash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return pwdhash_bytes == new_pwdhash
    except:
        return False

# 管理員認證裝飾器
def require_admin_auth(f):
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
        
        session_id = auth_header.split(' ')[1]
        session = db.get_admin_session(session_id)
        
        if not session or session['expires_at'] < datetime.now():
            return jsonify({'ok': False, 'error': 'Session expired'}), 401
        
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# 基本健康檢查
@app.route('/health', methods=['GET'])
def health_check():
    try:
        # 檢查資料庫連接
        db_status = "healthy"
        try:
            if db:
                users_count = db.get_users_count()
                profiles_count = db.get_profiles_count()
                messages_count = db.get_messages_count()
                today_active = db.get_today_active_users()
            else:
                db_status = "database_not_initialized"
                users_count = profiles_count = messages_count = today_active = 0
        except Exception as e:
            db_status = f"error: {str(e)}"
            users_count = profiles_count = messages_count = today_active = 0
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'uptime': 'N/A',
            'version': '1.0.0',
            'database': {
                'status': db_status,
                'users_count': users_count,
                'profiles_count': profiles_count,
                'messages_count': messages_count,
                'today_active_users': today_active
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

# API 版本健康檢查（向後相容）
@app.route('/api/v1/health', methods=['GET'])
def api_health_check():
    return health_check()

# Google verify 端點已移除，改用直接的 OAuth 回調流程

@app.route('/auth/google/callback', methods=['GET'])
def google_callback():
    """處理 Google OAuth 回調"""
    try:
        code = request.args.get('code')
        state = request.args.get('state')
        error = request.args.get('error')
        
        if error:
            return redirect('https://aistudent.zeabur.app?error=' + error)
        
        if not code:
            return redirect('https://aistudent.zeabur.app?error=missing_code')
        
        # 交換 access token
        token_url = 'https://oauth2.googleapis.com/token'
        token_data = {
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://aistudentbackend.zeabur.app/auth/google/callback'
        }
        
        token_response = requests.post(token_url, data=token_data)
        token_result = token_response.json()
        
        if 'access_token' not in token_result:
            return redirect('https://aistudent.zeabur.app?error=token_exchange_failed')
        
        access_token = token_result['access_token']
        
        # 獲取用戶資料
        user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo'
        headers = {'Authorization': 'Bearer ' + access_token}
        user_response = requests.get(user_info_url, headers=headers)
        user_data = user_response.json()
        
        if 'id' not in user_data:
            return redirect('https://aistudent.zeabur.app?error=user_info_failed')
        
        # 儲存用戶資料
        user_info = {
            'userId': user_data['id'],  # 使用 userId 而不是 user_id
            'email': user_data.get('email', ''),
            'name': user_data.get('name', ''),
            'avatar': user_data.get('picture', ''),  # 使用 avatar 而不是 picture
        }
        
        # 檢查用戶是否已存在
        existing_user = db.get_user_by_provider_id('google', user_data['id'])
        if not existing_user:
            db.save_user(user_info)
        else:
            # 更新現有用戶資料
            db.update_user(user_data['id'], user_info)
        
        # 生成 JWT token
        token_payload = {
            'user_id': user_info['userId'],
            'email': user_info['email'],
            'name': user_info['name'],
            'provider': 'google',
            'exp': datetime.utcnow() + timedelta(days=7)
        }
        
        jwt_token = jwt.encode(token_payload, SESSION_SECRET, algorithm='HS256')
        
        # 檢查是否來自彈出視窗
        state = request.args.get('state', '')
        
        if state == 'popup_login':
            # 彈出視窗登入：使用 JavaScript 關閉彈出視窗並傳遞 token
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>登入成功</title>
                <meta charset="UTF-8">
            </head>
            <body>
                <script>
                    // 將 token 傳遞給父視窗
                    // 設置安全的 JWT Cookie
                    function setSecureCookie(name, value) {{
                        const isSecure = window.location.protocol === 'https:';
                        let cookieAttributes = [
                            `${{name}}=${{value}}`,
                            'path=/',
                            'max-age=86400',
                            'SameSite=Lax',
                            'HttpOnly=false'
                        ];
                        if (isSecure) {{
                            cookieAttributes.push('Secure');
                        }}
                        document.cookie = cookieAttributes.join('; ');
                    }}
                    
                    // 設置 JWT Cookie
                    setSecureCookie('jwt', '{jwt_token}');
                    
                    if (window.opener) {{
                        window.opener.postMessage({{
                            type: 'GOOGLE_LOGIN_SUCCESS',
                            token: '{jwt_token}',
                            user: {{
                                userId: '{user_info['userId']}',
                                email: '{user_info['email']}',
                                name: '{user_info['name']}',
                                avatar: '{user_info['avatar']}'
                            }}
                        }}, 'https://aistudent.zeabur.app');
                        window.close();
                    }} else {{
                        // 如果沒有父視窗，直接跳轉
                        window.location.href = 'https://aistudent.zeabur.app?token={jwt_token}';
                    }}
                </script>
                <div style="text-align: center; padding: 50px; font-family: Arial, sans-serif;">
                    <h2>登入成功！</h2>
                    <p>正在關閉視窗...</p>
                </div>
            </body>
            </html>
            """
            return html_content
        else:
            # 一般登入：重定向到前端並帶上 token，同時設置安全的 Cookie
            response = make_response(redirect('https://aistudent.zeabur.app?token=' + jwt_token))
            set_secure_cookie(response, 'jwt', jwt_token)
            return response
        
    except Exception as e:
        logger.error('Google callback error: {}'.format(e))
        return redirect('https://aistudent.zeabur.app?error=callback_failed')

# LINE 登入相關
@app.route('/api/v1/auth/line/login', methods=['GET'])
def line_login():
    """獲取 LINE 登入 URL"""
    try:
        # LINE Login 配置
        line_client_id = LINE_CHANNEL_ID
        line_redirect_uri = f"{API_BASE_URL}/auth/line/callback"
        
        # 生成隨機 state
        import secrets
        line_state = 'line_login_' + secrets.token_urlsafe(16)
        
        logger.info(f'LINE_CHANNEL_ID: {line_client_id}')
        logger.info(f'Redirect URI: {line_redirect_uri}')
        
        if not line_client_id:
            logger.error('LINE_CHANNEL_ID not configured')
            return jsonify({'ok': False, 'error': 'LINE_CHANNEL_ID not configured'}), 500
        
        # 構建 LINE Login URL - 針對 LINE 內建瀏覽器優化
        line_auth_url = (
            f"https://access.line.me/oauth2/v2.1/authorize?"
            f"response_type=code&"
            f"client_id={line_client_id}&"
            f"redirect_uri={urllib.parse.quote(line_redirect_uri)}&"
            f"state={line_state}&"
            f"scope=profile%20openid%20email&"
            f"bot_prompt=normal&"
            f"prompt=consent&"
            f"nonce=line_login_{int(time.time())}"
        )
        
        logger.info(f'Generated LINE login URL: {line_auth_url}')
        
        return jsonify({
            'ok': True,
            'login_url': line_auth_url,
            'state': line_state
        })
        
    except Exception as e:
        logger.error(f'LINE login URL generation error: {e}')
        return jsonify({'ok': False, 'error': f'Failed to generate LINE login URL: {str(e)}'}), 500

@app.route('/auth/line/callback', methods=['GET'])
def line_callback():
    """處理 LINE OAuth 回調"""
    try:
        code = request.args.get('code')
        state = request.args.get('state')
        error = request.args.get('error')
        
        if error:
            logger.error(f'LINE callback error: {error}')
            return redirect(f'{FRONTEND_URL}/?error=line_{error}')
        
        if not code:
            logger.error('LINE callback: No authorization code received')
            return redirect(f'{FRONTEND_URL}/?error=line_no_code')
        
        # 交換 access token
        line_client_id = LINE_CHANNEL_ID
        line_client_secret = LINE_CHANNEL_SECRET
        line_redirect_uri = f"{API_BASE_URL}/auth/line/callback"
        
        if not line_client_id or not line_client_secret:
            logger.error('LINE credentials not configured')
            return redirect(f'{FRONTEND_URL}/?error=line_config_error')
        
        # 獲取 access token
        token_url = 'https://api.line.me/oauth2/v2.1/token'
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': line_redirect_uri,
            'client_id': line_client_id,
            'client_secret': line_client_secret
        }
        
        token_response = requests.post(token_url, data=token_data)
        token_result = token_response.json()
        
        if 'access_token' not in token_result:
            logger.error(f'LINE token exchange failed: {token_result}')
            return redirect(f'{FRONTEND_URL}/?error=line_token_failed')
        
        access_token = token_result['access_token']
        
        # 獲取用戶資料
        profile_url = 'https://api.line.me/v2/profile'
        headers = {'Authorization': f'Bearer {access_token}'}
        profile_response = requests.get(profile_url, headers=headers)
        profile_data = profile_response.json()
        
        if 'userId' not in profile_data:
            logger.error(f'LINE profile fetch failed: {profile_data}')
            return redirect(f'{FRONTEND_URL}/?error=line_profile_failed')
        
        # 構建用戶資訊
        user_info = {
            'userId': profile_data['userId'],
            'email': profile_data.get('email', ''),
            'name': profile_data.get('displayName', ''),
            'avatar': profile_data.get('pictureUrl', ''),
        }
        
        # 檢查用戶是否已存在
        existing_user = db.get_user_by_provider_id('line', profile_data['userId'])
        if not existing_user:
            db.save_user(user_info)
            logger.info(f'New LINE user created: {user_info["name"]} ({user_info["userId"]})')
        else:
            # 更新現有用戶資料
            db.update_user(profile_data['userId'], user_info)
            logger.info(f'Existing LINE user logged in: {user_info["name"]} ({user_info["userId"]})')
        
        # 生成 JWT token
        token_payload = {
            'user_id': user_info['userId'],
            'email': user_info['email'],
            'name': user_info['name'],
            'provider': 'line',
            'exp': datetime.utcnow() + timedelta(days=7)
        }
        
        jwt_token = jwt.encode(token_payload, SESSION_SECRET, algorithm='HS256')
        
        # 重定向到前端並設置安全的 Cookie
        response = make_response(redirect(f'{FRONTEND_URL}/?token={jwt_token}&provider=line'))
        set_secure_cookie(response, 'jwt', jwt_token)
        return response
        
    except Exception as e:
        logger.error(f'LINE callback error: {e}')
        return redirect(f'{FRONTEND_URL}/?error=line_callback_failed')

# 跨設備用戶同步
@app.route('/api/v1/user/sync', methods=['GET'])
@verify_jwt_token
def sync_user_data():
    """跨設備用戶資料同步"""
    try:
        user_id = request.user.get('user_id')
        logger.info(f"User sync request from user_id: {user_id}")
        
        # 獲取用戶基本資料
        user_data = db.get_user_by_id(user_id)
        if not user_data:
            return jsonify({'ok': False, 'error': 'User not found'}), 404
        
        # 獲取用戶的最新 profile 資料
        profiles = db.get_user_profiles(user_id)
        latest_profile = None
        if profiles:
            # 取最新的 profile
            latest_profile = max(profiles, key=lambda p: p.get('created_at', ''))
        
        # 構建同步資料
        sync_data = {
            'user': {
                'userId': user_data.get('user_id'),
                'email': user_data.get('email'),
                'name': user_data.get('name'),
                'avatar': user_data.get('avatar'),
                'provider': user_data.get('provider')
            },
            'profileId': latest_profile.get('profile_id') if latest_profile else None,
            'lastSync': datetime.utcnow().isoformat()
        }
        
        logger.info(f"User sync successful for user_id: {user_id}")
        return jsonify({'ok': True, 'data': sync_data})
        
    except Exception as e:
        logger.error(f'User sync error: {e}')
        return jsonify({'ok': False, 'error': 'Sync failed'}), 500

# 用戶資料檢索
@app.route('/api/v1/user/profile/<profile_id>', methods=['GET'])
def get_user_profile_data(profile_id):
    """獲取用戶設定資料"""
    try:
        # 從 JWT token 中獲取用戶資訊
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'ok': False, 'error': 'Missing or invalid authorization header'}), 401
        
        token = auth_header.split(' ')[1]
        try:
            payload = jwt.decode(token, SESSION_SECRET, algorithms=['HS256'])
            user_id = payload.get('user_id')
        except jwt.ExpiredSignatureError:
            return jsonify({'ok': False, 'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'ok': False, 'error': 'Invalid token'}), 401
        
        # 獲取用戶設定資料
        profile_data = db.get_user_profile(profile_id)
        if not profile_data:
            return jsonify({'ok': False, 'error': 'Profile not found'}), 404
        
        # 驗證 profile 是否屬於該用戶
        if profile_data.get('user_id') != user_id:
            return jsonify({'ok': False, 'error': 'Access denied'}), 403
        
        return jsonify({'ok': True, 'data': profile_data})
        
    except Exception as e:
        logger.error(f'Error retrieving user profile: {e}')
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@app.route('/api/v1/user/check-profile', methods=['GET'])
@verify_jwt_token
def check_user_profile():
    """檢查用戶是否有設定資料"""
    try:
        user_id = request.user['user_id']
        
        # 查找用戶的所有 profile
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT profile_id, user_role, student_name, parent_name, created_at 
            FROM user_profiles 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        ''', (user_id,))
        
        profiles = cursor.fetchall()
        conn.close()
        
        if profiles:
            # 返回最新的 profile 資料
            latest_profile = profiles[0]
            return jsonify({
                'ok': True, 
                'has_profile': True,
                'profile_id': latest_profile[0],
                'user_role': latest_profile[1],
                'profile_data': {
                    'profile_id': latest_profile[0],
                    'user_role': latest_profile[1],
                    'student_name': latest_profile[2],
                    'parent_name': latest_profile[3],
                    'created_at': latest_profile[4]
                }
            })
        else:
            return jsonify({
                'ok': True,
                'has_profile': False
            })
            
    except Exception as e:
        logger.error(f'Error checking user profile: {e}')
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@app.route('/api/v1/user/update-profile/<profile_id>', methods=['PUT'])
@verify_jwt_token
def update_user_profile(profile_id):
    """更新用戶設定資料"""
    try:
        user_id = request.user['user_id']
        data = request.get_json()
        
        # 驗證 profile 是否屬於該用戶
        existing_profile = db.get_user_profile(profile_id)
        if not existing_profile:
            return jsonify({'ok': False, 'error': 'Profile not found'}), 404
            
        if existing_profile.get('user_id') != user_id:
            return jsonify({'ok': False, 'error': 'Access denied'}), 403
        
        # 更新資料庫
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # 準備更新資料
        update_fields = []
        update_values = []
        
        if 'student_name' in data:
            update_fields.append('student_name = ?')
            update_values.append(data['student_name'])
        if 'student_email' in data:
            update_fields.append('student_email = ?')
            update_values.append(data['student_email'])
        if 'parent_name' in data:
            update_fields.append('parent_name = ?')
            update_values.append(data['parent_name'])
        if 'parent_email' in data:
            update_fields.append('parent_email = ?')
            update_values.append(data['parent_email'])
        if 'relationship' in data:
            update_fields.append('relationship = ?')
            update_values.append(data['relationship'])
        if 'child_name' in data:
            update_fields.append('child_name = ?')
            update_values.append(data['child_name'])
        if 'child_email' in data:
            update_fields.append('child_email = ?')
            update_values.append(data['child_email'])
        if 'citizenship' in data:
            update_fields.append('citizenship = ?')
            update_values.append(data['citizenship'])
        if 'gpa' in data:
            update_fields.append('gpa = ?')
            update_values.append(data['gpa'])
        if 'degree' in data:
            update_fields.append('degree = ?')
            update_values.append(data['degree'])
        if 'countries' in data:
            update_fields.append('countries = ?')
            update_values.append(json.dumps(data['countries']))
        if 'budget' in data:
            update_fields.append('budget = ?')
            update_values.append(data['budget'])
        if 'target_intake' in data:
            update_fields.append('target_intake = ?')
            update_values.append(data['target_intake'])
        if 'user_role' in data:
            update_fields.append('user_role = ?')
            update_values.append(data['user_role'])
        
        # 添加更新時間
        update_fields.append('updated_at = ?')
        update_values.append(datetime.now().isoformat())
        
        # 添加 WHERE 條件
        update_values.append(profile_id)
        
        if update_fields:
            sql = f"UPDATE user_profiles SET {', '.join(update_fields)} WHERE profile_id = ?"
            cursor.execute(sql, update_values)
            conn.commit()
            
            logger.info(f"User profile updated: {profile_id}")
            
        conn.close()
        
        return jsonify({'ok': True, 'message': 'Profile updated successfully'})
        
    except Exception as e:
        logger.error(f'Error updating user profile: {e}')
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@app.route('/api/v1/user/notification-settings', methods=['GET', 'POST'])
@verify_jwt_token
def user_notification_settings():
    """獲取或更新用戶通知設定"""
    try:
        user_id = request.user['user_id']
        
        if request.method == 'GET':
            # 獲取通知設定
            conn = db.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT email_notifications, push_notifications, notification_frequency
                FROM user_settings 
                WHERE user_id = ?
            ''', (user_id,))
            
            settings = cursor.fetchone()
            conn.close()
            
            if settings:
                return jsonify({
                    'ok': True,
                    'data': {
                        'email_notifications': bool(settings[0]),
                        'push_notifications': bool(settings[1]),
                        'notification_frequency': settings[2] or 'daily'
                    }
                })
            else:
                return jsonify({
                    'ok': True,
                    'data': {
                        'email_notifications': False,
                        'push_notifications': True,
                        'notification_frequency': 'daily'
                    }
                })
                
        elif request.method == 'POST':
            # 更新通知設定
            data = request.get_json()
            
            conn = db.get_connection()
            cursor = conn.cursor()
            
            # 檢查是否已有設定
            cursor.execute('SELECT user_id FROM user_settings WHERE user_id = ?', (user_id,))
            exists = cursor.fetchone()
            
            if exists:
                # 更新現有設定
                cursor.execute('''
                    UPDATE user_settings 
                    SET email_notifications = ?, 
                        push_notifications = ?, 
                        notification_frequency = ?,
                        updated_at = ?
                    WHERE user_id = ?
                ''', (
                    data.get('email_notifications', False),
                    data.get('push_notifications', True),
                    data.get('notification_frequency', 'daily'),
                    datetime.now().isoformat(),
                    user_id
                ))
            else:
                # 創建新設定
                cursor.execute('''
                    INSERT INTO user_settings 
                    (user_id, email_notifications, push_notifications, notification_frequency, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    user_id,
                    data.get('email_notifications', False),
                    data.get('push_notifications', True),
                    data.get('notification_frequency', 'daily'),
                    datetime.now().isoformat(),
                    datetime.now().isoformat()
                ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Notification settings updated for user: {user_id}")
            
            return jsonify({'ok': True, 'message': 'Notification settings updated successfully'})
            
    except Exception as e:
        logger.error(f'Error handling notification settings: {e}')
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@app.route('/api/v1/parent/student-progress', methods=['GET'])
@verify_jwt_token
def get_student_progress():
    """家長查詢學生諮詢進度"""
    try:
        user_id = request.user['user_id']
        
        # 檢查用戶是否為家長
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # 獲取家長的 profile
        cursor.execute('''
            SELECT profile_id, user_role, child_email, child_name
            FROM user_profiles 
            WHERE user_id = ? AND user_role = 'parent'
            ORDER BY created_at DESC
            LIMIT 1
        ''', (user_id,))
        
        parent_profile = cursor.fetchone()
        if not parent_profile:
            conn.close()
            return jsonify({'ok': False, 'error': 'Parent profile not found'}), 404
        
        parent_profile_id, user_role, child_email, child_name = parent_profile
        
        # 查找學生的 profile（通過 email 匹配）
        cursor.execute('''
            SELECT profile_id, student_name, student_email, created_at, updated_at
            FROM user_profiles 
            WHERE student_email = ? AND user_role = 'student'
            ORDER BY created_at DESC
            LIMIT 1
        ''', (child_email,))
        
        student_profile = cursor.fetchone()
        if not student_profile:
            conn.close()
            return jsonify({
                'ok': True,
                'data': {
                    'student_found': False,
                    'message': 'Student profile not found. Please ensure the student has completed their profile setup.'
                }
            })
        
        student_profile_id, student_name, student_email, student_created_at, student_updated_at = student_profile
        
        # 獲取學生的聊天記錄統計
        cursor.execute('''
            SELECT 
                COUNT(*) as total_messages,
                COUNT(DISTINCT DATE(created_at)) as active_days,
                MAX(created_at) as last_activity
            FROM chat_messages 
            WHERE profile_id = ? AND message_type = 'user'
        ''', (student_profile_id,))
        
        chat_stats = cursor.fetchone()
        
        # 獲取最近的聊天主題（通過 AI 回覆分析）
        cursor.execute('''
            SELECT message_content, created_at
            FROM chat_messages 
            WHERE profile_id = ? AND message_type = 'ai'
            ORDER BY created_at DESC
            LIMIT 5
        ''', (student_profile_id,))
        
        recent_topics = cursor.fetchall()
        
        # 獲取使用統計
        cursor.execute('''
            SELECT action_type, COUNT(*) as count
            FROM usage_stats 
            WHERE profile_id = ?
            GROUP BY action_type
        ''', (student_profile_id,))
        
        usage_stats = cursor.fetchall()
        
        conn.close()
        
        # 分析諮詢進度
        progress_analysis = analyze_student_progress(
            chat_stats, 
            recent_topics, 
            usage_stats,
            student_created_at
        )
        
        return jsonify({
            'ok': True,
            'data': {
                'student_found': True,
                'student_info': {
                    'name': student_name,
                    'email': student_email,
                    'profile_created': student_created_at,
                    'last_updated': student_updated_at
                },
                'activity_stats': {
                    'total_messages': chat_stats[0] if chat_stats else 0,
                    'active_days': chat_stats[1] if chat_stats else 0,
                    'last_activity': chat_stats[2] if chat_stats else None
                },
                'recent_topics': [
                    {'content': topic[0][:100] + '...' if len(topic[0]) > 100 else topic[0], 'time': topic[1]} 
                    for topic in recent_topics
                ],
                'usage_stats': [
                    {'action': stat[0], 'count': stat[1]} for stat in usage_stats
                ],
                'progress_analysis': progress_analysis
            }
        })
        
    except Exception as e:
        logger.error(f'Error getting student progress: {e}')
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

def analyze_student_progress(chat_stats, recent_topics, usage_stats, profile_created):
    """分析學生諮詢進度"""
    try:
        from datetime import datetime, timedelta
        
        now = datetime.now()
        created_date = datetime.fromisoformat(profile_created.replace('Z', '+00:00')) if profile_created else now
        days_since_creation = (now - created_date).days
        
        total_messages = chat_stats[0] if chat_stats else 0
        active_days = chat_stats[1] if chat_stats else 0
        
        # 進度分析
        progress_level = "beginner"
        if total_messages > 20:
            progress_level = "advanced"
        elif total_messages > 10:
            progress_level = "intermediate"
        
        # 活躍度分析
        activity_level = "low"
        if active_days > 5:
            activity_level = "high"
        elif active_days > 2:
            activity_level = "medium"
        
        # 建議
        suggestions = []
        if total_messages < 5:
            suggestions.append("建議學生多與AI顧問互動，提出具體的留學問題")
        if active_days < 3:
            suggestions.append("建議學生保持定期諮詢，建立持續的留學規劃習慣")
        if days_since_creation > 7 and total_messages < 10:
            suggestions.append("建議學生積極利用AI顧問資源，加速留學規劃進度")
        
        return {
            'progress_level': progress_level,
            'activity_level': activity_level,
            'engagement_score': min(100, (total_messages * 5 + active_days * 10)),
            'suggestions': suggestions,
            'days_active': days_since_creation
        }
        
    except Exception as e:
        logger.error(f'Error analyzing student progress: {e}')
        return {
            'progress_level': 'unknown',
            'activity_level': 'unknown',
            'engagement_score': 0,
            'suggestions': ['無法分析進度，請稍後再試'],
            'days_active': 0
        }

# 認證配置
@app.route('/api/v1/auth/config', methods=['GET'])
def auth_config():
    return jsonify({
        'ok': True,
        'google': {
            'enabled': bool(GOOGLE_CLIENT_ID),
            'client_id': GOOGLE_CLIENT_ID if GOOGLE_CLIENT_ID else None
        },
        'line': {
            'enabled': bool(LINE_CHANNEL_ID),
            'channel_id': LINE_CHANNEL_ID if LINE_CHANNEL_ID else None
        }
    })

@app.route('/api/v1/auth/status', methods=['GET'])
@verify_jwt_token
def auth_status():
    return jsonify({'ok': True, 'user': request.user})

# 用戶登出
@app.route('/api/v1/auth/logout', methods=['POST'])
def user_logout():
    """用戶登出"""
    try:
        # 清除 JWT token (前端處理)
        return jsonify({'ok': True, 'message': '已登出'})
    except Exception as e:
        logger.error('User logout error: {}'.format(e))
        return jsonify({'error': '登出失敗'}), 500

# 用戶設定 API
@app.route('/api/v1/intake', methods=['POST'])
@verify_jwt_token
def intake():
    try:
        profile_id = "profile_{}_{}".format(int(datetime.now().timestamp()), hash(str(request.user)) % 10000)
        user_data = {
            'profile_id': profile_id,
            'user_id': request.user['user_id'],  # 修復字段名不匹配
            'created_at': datetime.now().isoformat()
        }
        user_data.update(request.get_json())
        
        # 儲存到資料庫
        db.save_user_profile(user_data)
        
        # 記錄使用統計
        db.save_usage_stat({
            'user_id': user_data['user_id'],
            'profile_id': profile_id,
            'action_type': 'profile_created',
            'action_details': {'role': user_data.get('user_role')}
        })
        
        print('User profile saved: {}, role: {}'.format(profile_id, user_data.get("user_role")))
        return jsonify({'ok': True, 'data': {'profile_id': profile_id}})
        
    except Exception as e:
        print('Intake error: {}'.format(e))
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

# 聊天 API
@app.route('/api/v1/chat', methods=['POST'])
@verify_jwt_token
def chat():
    try:
        data = request.get_json()
        message = data.get('message', '')
        user_role = data.get('user_role', 'student')
        profile_id = data.get('profile_id')
        language = data.get('language', 'zh')
        
        logger.info(f"Chat request - profile_id: {profile_id}, user_role: {user_role}, message length: {len(message)}")
        
        # 獲取用戶資料
        user_profile = {}
        if profile_id:
            user_profile = db.get_user_profile(profile_id)
            logger.info(f"User profile retrieved by profile_id: {bool(user_profile)}")
        else:
            # 如果沒有 profile_id，嘗試從用戶的所有 profile 中獲取最新的
            user_id = request.user.get('user_id')
            if user_id:
                conn = db.get_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT profile_id, user_role, student_name, parent_name, student_email, 
                           parent_email, relationship, child_name, child_email, citizenship, 
                           gpa, degree, countries, budget, target_intake, created_at, updated_at
                    FROM user_profiles 
                    WHERE user_id = ? 
                    ORDER BY created_at DESC
                    LIMIT 1
                ''', (user_id,))
                
                profile_data = cursor.fetchone()
                conn.close()
                
                if profile_data:
                    user_profile = {
                        'profile_id': profile_data[0],
                        'user_role': profile_data[1],
                        'student_name': profile_data[2],
                        'parent_name': profile_data[3],
                        'student_email': profile_data[4],
                        'parent_email': profile_data[5],
                        'relationship': profile_data[6],
                        'child_name': profile_data[7],
                        'child_email': profile_data[8],
                        'citizenship': profile_data[9],
                        'gpa': profile_data[10],
                        'degree': profile_data[11],
                        'countries': json.loads(profile_data[12]) if profile_data[12] else [],
                        'budget': profile_data[13],
                        'target_intake': profile_data[14],
                        'created_at': profile_data[15],
                        'updated_at': profile_data[16]
                    }
                    logger.info(f"User profile retrieved by user_id: {bool(user_profile)}")
                else:
                    logger.warning(f"No profile found for user_id: {user_id}")
        
        logger.info(f"Final user profile: {user_profile}")
        logger.info(f"User profile keys: {list(user_profile.keys()) if user_profile else 'No profile'}")
        
        # 構建 Gemini 提示
        # 載入知識庫內容
        knowledge_base = load_knowledge_base()
        
        if language == 'en':
            system_prompt = """You are a professional AI Study Abroad Advisor. You provide personalized, expert guidance for students and parents planning international education.

User Role: {}
User Profile: {}

KNOWLEDGE BASE:
{}

CRITICAL RESPONSE GUIDELINES:
1. Keep responses CONCISE and FOCUSED - answer the specific question asked
2. Use emojis to make content engaging (🎓📚💰🏠✈️📋)
3. MANDATORY: Each paragraph must be separated by blank lines
4. Use bullet points (•) for lists, each point on separate line
5. Use **bold** for important sections
6. Ask 1-2 follow-up questions to continue the conversation
7. Maximum 3-4 main points per response
8. FORCE: Each topic paragraph must have line breaks, never run together
9. Always reference the knowledge base when providing specific information
10. Format responses with proper line breaks and structure

Please respond in English and provide focused, actionable advice.""".format(
                user_role,
                json.dumps(user_profile, indent=2, ensure_ascii=False) if user_profile else 'No profile data available',
                knowledge_base
            )
            
            if message and message.strip():
                user_prompt = """User Question: "{}"

Provide a CONCISE, focused response that directly answers this question.

MANDATORY FORMATTING:
• Use emojis for visual appeal
• Each paragraph MUST be separated by blank lines
• Use bullet points (•) for lists, each on separate line
• Use **bold** for important sections
• **Focus: Provide rich, specific content with actual recommendations, school names, data**
• **Only ask questions when absolutely necessary, don't always ask questions**
• Keep under 200 words
• NEVER run paragraphs together - always add line breaks between topics""".format(message)
            else:
                user_prompt = """Provide a brief, welcoming message for this {} (under 100 words). 

Format requirements:
• Use emojis (🎓📚💰🏠✈️📋)
• Clear paragraphs with proper line breaks
• **Focus: Provide useful study abroad information and advice, don't always ask questions**
• Optionally ask 1 question to start conversation (only when truly needed)
• Keep concise and focused""".format(user_role)
        else:
            system_prompt = """你是一位專業的AI留學顧問。你為計劃國際教育的學生和家長提供個人化的專業指導。

用戶角色：{}
用戶資料：{}

**重要：你必須根據上述用戶資料來回答問題，不要重複詢問用戶已經提供的資訊！**

**用戶資料狀態檢查：**
- 如果用戶資料顯示完整資訊（包含姓名、預算、目標等），表示用戶已經建立過留學需求
- 此時絕對不要要求用戶重新填寫或建立資料
- 直接基於現有資料提供專業建議和指導

**用戶資料使用規則：**
- 如果有學生姓名，請直接使用姓名稱呼用戶
- 如果有家長姓名，請使用家長姓名稱呼
- 根據用戶的預算、目標國家、學歷背景提供針對性建議
- 絕對不要詢問用戶已經提供的資訊（如姓名、預算、國家偏好、學歷等）
- **用戶已有完整資料時，絕對不要要求重新建立或填寫**
- **直接使用現有資料提供建議，不要重複詢問已知資訊**

**對話風格規則：**
- **只在第一次對話時使用問候語**（如：Jacky您好！）
- **後續對話不要重複問候**，直接回答問題
- **保持對話連續性**，不要跳回開場白或重新介紹
- **如果無法回答特定問題，誠實說明並提供替代建議**
- **理解問題語境**：如果用戶問的是關於「您」的問題，要明確說明自己是AI，不能代替用戶回答
- **避免無意義回應**：不要給出明顯不合理或無關的回答

知識庫：
{}

重要回覆原則：
1. **優先提供具體內容** - 必須直接回答用戶問題並提供實用的具體資訊
2. **使用用戶資料** - 絕對不要詢問用戶已經提供的資訊（如預算、國家偏好、學歷等）
3. **重點：多提供內容，少問問題** - 盡可能提供詳細的具體建議和資訊
4. 使用 emoji 讓內容更生動 (🎓📚💰🏠✈️📋)
5. **強制要求**：每個段落之間必須有空行分隔，段落必須換行
6. 使用項目符號 (•) 列出要點，每個要點單獨一行
7. 使用 **粗體** 標示重要段落
8. **回答結構**：先回答問題 → 提供詳細資訊 → 只有在絕對必要時才問 1 個問題
9. 每次回覆提供豐富的具體內容，包含學校名稱、具體建議、實際數據等
10. **格式要求**：絕對不要讓段落連在一起，每個主題段落後必須換行
11. **段落分隔**：每個主要觀點後必須空一行，確保視覺上段落分明
12. 總是參考知識庫提供具體資訊和實際建議
13. **回覆格式範例**：
    **直接回答**
    [空行]
    詳細說明
    [空行]
    • 要點1
    • 要點2
    [空行]
    一個相關問題

請用中文回應，提供有針對性的建議。""".format(
                user_role,
                json.dumps(user_profile, indent=2, ensure_ascii=False) if user_profile else '無資料',
                knowledge_base
            )
            
            if message and message.strip():
                # 獲取用戶姓名
                user_name = ""
                if user_profile:
                    if user_profile.get('user_role') == 'student':
                        user_name = user_profile.get('student_name', '')
                    elif user_profile.get('user_role') == 'parent':
                        user_name = user_profile.get('parent_name', '')
                
                user_prompt = """用戶問題：「{}」

請提供簡潔、有針對性的回覆，直接回答這個問題。

**重要提醒：**
• 如果用戶問的是關於「您」的問題，要明確說明自己是AI顧問，不能代替用戶回答
• 理解問題的實際含義，不要給出無意義的回應
• 直接使用用戶已有的資料，不要要求重新填寫

強制格式要求：
• 使用 emoji 增加視覺吸引力
• **對話連續性：不要重複問候，直接回答問題**
• **如果有用戶姓名，請使用姓名稱呼用戶**
• 每個段落之間必須有空行分隔
• 使用項目符號 (•) 列出要點，每個要點單獨一行
• 使用 **粗體** 標示重要段落
• **重點：提供豐富的具體內容，包含實際建議、學校名稱、數據等**
• **只有在絕對必要時才問問題，不要總是問問題**
• 控制在 200 字以內
• 絕對不要讓段落連在一起 - 主題段落間必須換行
• **保持對話流暢，不要跳回開場白**""".format(message)
            else:
                # 獲取用戶姓名
                user_name = ""
                if user_profile:
                    if user_profile.get('user_role') == 'student':
                        user_name = user_profile.get('student_name', '')
                    elif user_profile.get('user_role') == 'parent':
                        user_name = user_profile.get('parent_name', '')
                
                user_prompt = """請為這位{}{}提供簡短的歡迎訊息（100字以內）。

格式要求：
• 使用 emoji (🎓📚💰🏠✈️📋)
• 段落分明，適當換行
• **重點：提供有用的留學資訊和建議，不要總是問問題**
• 可選提出 1 個問題開始對話（只有在真正需要時）
• 保持簡潔有重點
• **只在歡迎訊息中使用問候語，後續對話不再重複問候**""".format(user_role, f" {user_name}" if user_name else "")
        
        full_prompt = "{}\n\n{}".format(system_prompt, user_prompt)
        
        # 呼叫 Gemini AI
        logger.info(f"Calling Gemini AI with prompt length: {len(full_prompt)}")
        if use_gemini():
            reply = gemini_generate_text(full_prompt)
            if not reply or not reply.strip():
                # 如果 Gemini 返回空回應，使用備用回覆
                logger.warning("Gemini returned empty response, using fallback")
                if language == 'en':
                    reply = 'I apologize, but I\'m currently experiencing technical difficulties. Please try again in a moment or contact our support team for assistance.'
                else:
                    reply = '抱歉，我目前遇到技術問題。請稍後再試，或聯繫我們的支援團隊獲得協助。'
        else:
            # 備用回覆
            logger.warning("Gemini API key not configured, using fallback")
            if language == 'en':
                reply = 'AI service is temporarily unavailable. Please check your GEMINI_API_KEY configuration.'
            else:
                reply = 'AI服務暫時不可用，請檢查GEMINI_API_KEY配置。'
        
        logger.info(f"Generated reply length: {len(reply) if reply else 0}")
        
        # 儲存聊天記錄到資料庫（只有在有 profile_id 時才儲存）
        if message and message.strip() and profile_id:
            try:
            # 儲存用戶訊息
            db.save_chat_message({
                'profile_id': profile_id,
                    'user_id': request.user['user_id'],  # 修復字段名
                'message_type': 'user',
                'message_content': message,
                'language': language,
                'user_role': user_role
            })
            
            # 儲存 AI 回覆
            db.save_chat_message({
                'profile_id': profile_id,
                    'user_id': request.user['user_id'],  # 修復字段名
                'message_type': 'ai',
                'message_content': reply,
                'language': language,
                'user_role': user_role
            })
            
            # 記錄使用統計
            db.save_usage_stat({
                    'user_id': request.user['user_id'],  # 修復字段名
                'profile_id': profile_id,
                'action_type': 'chat_message',
                'action_details': {'language': language, 'user_role': user_role}
            })
                logger.info(f"Chat messages saved successfully for profile_id: {profile_id}")
            except Exception as e:
                logger.error(f"Error saving chat messages: {e}")
                # 不影響聊天功能，繼續返回 AI 回覆
        else:
            logger.info(f"Skipping chat message save - message: {bool(message and message.strip())}, profile_id: {bool(profile_id)}")
        
        return jsonify({'ok': True, 'reply': reply})
        
    except Exception as e:
        print('Gemini AI error: {}'.format(e))
        
        # 備用回覆
        if language == 'en':
            fallback_reply = 'I apologize, but I\'m currently experiencing technical difficulties. Please try again in a moment or contact our support team for assistance.'
        else:
            fallback_reply = '抱歉，我目前遇到技術問題。請稍後再試，或聯繫我們的支援團隊獲得協助。'
        
        return jsonify({'ok': True, 'reply': fallback_reply})

# 串流聊天 API
@app.route('/api/v1/chat/stream', methods=['GET'])
@verify_jwt_token
def chat_stream():
    """SSE 串流聊天端點"""
    try:
        # 從 URL 參數獲取數據
        message = request.args.get('message', '')
        profile_id = request.args.get('profile_id')
        language = request.args.get('language', 'zh')
        user_role = request.args.get('user_role', 'student')
        
        if not message.strip():
            def error_generator():
                yield "data: 請輸入有效的訊息。\n\n"
                yield "data: [DONE]\n\n"
            return Response(stream_with_context(error_generator()), 
                          mimetype='text/event-stream',
                          headers={
                              'Cache-Control': 'no-cache',
                              'X-Accel-Buffering': 'no',
                              'Content-Type': 'text/event-stream; charset=utf-8'
                          })
        
        def generator():
            try:
                # 1. 驗證 JWT 和參數
                user_id = request.user.get('user_id')
                logger.info(f"Stream chat request - user_id: {user_id}, profile_id: {profile_id}, message: {message[:50]}...")
                
                # 2. 查詢最近 20 則對話
                recent_messages = []
                if profile_id:
                    try:
                        conn = db.get_connection()
                        cursor = conn.cursor()
                        cursor.execute('''
                            SELECT message_type, message_content, created_at
                            FROM chat_messages 
                            WHERE profile_id = ? 
                            ORDER BY created_at DESC 
                            LIMIT 20
                        ''', (profile_id,))
                        
                        messages_data = cursor.fetchall()
                        for msg in messages_data:
                            recent_messages.append({
                                'type': msg[0],
                                'content': msg[1],
                                'created_at': msg[2]
                            })
                        conn.close()
                        
                        # 反轉順序，讓最早的訊息在前面
                        recent_messages.reverse()
                        logger.info(f"Retrieved {len(recent_messages)} recent messages")
                    except Exception as e:
                        logger.error(f"Error retrieving chat history: {e}")
                
                # 3. 查詢最近一次摘要（暫時跳過，因為沒有 chat_summaries 表）
                latest_summary = ""
                
                # 4. RAG 檢索
                knowledge_base = load_knowledge_base()
                rag_content = rag_search(message, knowledge_base, top_k=3)
                logger.info(f"RAG retrieved {len(rag_content)} characters")
                
                # 5. 組建 System Prompt
                # 獲取用戶資料
                user_profile = {}
                if profile_id:
                    try:
                        user_profile = db.get_user_profile(profile_id)
                    except Exception as e:
                        logger.error(f"Error getting user profile: {e}")
                
                # 構建精簡歷史
                history_text = ""
                for msg in recent_messages[-10:]:  # 只取最近 10 條
                    role = "用戶" if msg['type'] == 'user' else "AI"
                    history_text += f"{role}: {msg['content']}\n"
                
                # 系統提示詞
                system_prompt = f"""你是一位專業的AI留學顧問。你為計劃國際教育的學生和家長提供個人化的專業指導。

用戶角色：{user_role}
用戶資料：{json.dumps(user_profile, indent=2, ensure_ascii=False) if user_profile else '無資料'}

**重要：你必須根據上述用戶資料來回答問題，不要重複詢問用戶已經提供的資訊！**

**用戶資料狀態檢查：**
- 如果用戶資料顯示完整資訊（包含姓名、預算、目標等），表示用戶已經建立過留學需求
- 此時絕對不要要求用戶重新填寫或建立資料
- 直接基於現有資料提供專業建議和指導

**用戶資料使用規則：**
- 如果有學生姓名，請直接使用姓名稱呼用戶
- 如果有家長姓名，請使用家長姓名稱呼
- 根據用戶的預算、目標國家、學歷背景提供針對性建議
- 絕對不要詢問用戶已經提供的資訊（如姓名、預算、國家偏好、學歷等）
- **用戶已有完整資料時，絕對不要要求重新建立或填寫**
- **直接使用現有資料提供建議，不要重複詢問已知資訊**

**對話風格規則：**
- **只在第一次對話時使用問候語**（如：Jacky您好！）
- **後續對話不要重複問候**，直接回答問題
- **保持對話連續性**，不要跳回開場白或重新介紹
- **如果無法回答特定問題，誠實說明並提供替代建議**
- **理解問題語境**：如果用戶問的是關於「您」的問題，要明確說明自己是AI，不能代替用戶回答
- **避免無意義回應**：不要給出明顯不合理或無關的回答

對話歷史：
{history_text}

最新摘要：{latest_summary}

相關知識庫內容：
{rag_content}

重要回覆原則：
1. **優先提供具體內容** - 必須直接回答用戶問題並提供實用的具體資訊
2. **使用用戶資料** - 絕對不要詢問用戶已經提供的資訊（如預算、國家偏好、學歷等）
3. **重點：多提供內容，少問問題** - 盡可能提供詳細的具體建議和資訊
4. 使用 emoji 讓內容更生動 (🎓📚💰🏠✈️📋)
5. **強制要求**：每個段落之間必須有空行分隔，段落必須換行
6. 使用項目符號 (•) 列出要點，每個要點單獨一行
7. 使用 **粗體** 標示重要段落
8. **回答結構**：先回答問題 → 提供詳細資訊 → 只有在絕對必要時才問 1 個問題
9. 每次回覆提供豐富的具體內容，包含學校名稱、具體建議、實際數據等
10. **格式要求**：絕對不要讓段落連在一起，每個主題段落後必須換行
11. **段落分隔**：每個主要觀點後必須空一行，確保視覺上段落分明
12. 總是參考知識庫提供具體資訊和實際建議
13. **回覆格式範例**：
    **直接回答**
    [空行]
    詳細說明
    [空行]
    • 要點1
    • 要點2
    [空行]
    一個相關問題

請用中文回應，提供有針對性的建議。"""
                
                # 6. 呼叫串流生成
                logger.info("Starting stream generation...")
                full_response = ""
                
                for chunk in gemini_generate_stream(system_prompt):
                    chunk_text = chunk.replace("data: ", "").replace("\n\n", "")
                    if chunk_text and chunk_text != "[DONE]":
                        full_response += chunk_text
                    yield chunk
                
                # 7. 結束標記
                yield "data: [DONE]\n\n"
                
                # 8. 保存對話記錄
                if profile_id and full_response:
                    try:
                        # 保存用戶訊息
                        db.save_chat_message({
                            'profile_id': profile_id,
                            'user_id': user_id,
                            'message_type': 'user',
                            'message_content': message,
                            'language': language,
                            'user_role': user_role
                        })
                        
                        # 保存 AI 回應
                        db.save_chat_message({
                            'profile_id': profile_id,
                            'user_id': user_id,
                            'message_type': 'ai',
                            'message_content': full_response.strip(),
                            'language': language,
                            'user_role': user_role
                        })
                        
                        logger.info("Chat messages saved successfully")
                    except Exception as e:
                        logger.error(f"Error saving chat messages: {e}")
                
                # 9. 生成並保存摘要（暫時跳過，因為沒有 chat_summaries 表）
                
            except Exception as e:
                logger.error(f'Stream generator error: {e}')
                yield "data: 抱歉，發生技術錯誤，請稍後再試。\n\n"
                yield "data: [DONE]\n\n"
        
        return Response(stream_with_context(generator()), 
                       mimetype='text/event-stream',
                       headers={
                           'Cache-Control': 'no-cache',
                           'X-Accel-Buffering': 'no',
                           'Content-Type': 'text/event-stream; charset=utf-8'
                       })
        
    except Exception as e:
        logger.error(f'Stream chat error: {e}')
        def error_generator():
            yield "data: 抱歉，發生技術錯誤，請稍後再試。\n\n"
            yield "data: [DONE]\n\n"
        return Response(stream_with_context(error_generator()), 
                       mimetype='text/event-stream',
                       headers={
                           'Cache-Control': 'no-cache',
                           'X-Accel-Buffering': 'no',
                           'Content-Type': 'text/event-stream; charset=utf-8'
                       })

# 管理員登入
@app.route('/api/v1/admin/login', methods=['POST'])
def admin_login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'ok': False, 'error': 'Username and password required'}), 400
        
        # 檢查管理員
        admin = db.get_admin_by_username(username)
        if not admin or not verify_password(admin['password_hash'], password):
            return jsonify({'ok': False, 'error': 'Invalid credentials'}), 401
        
        if not admin['is_active']:
            return jsonify({'ok': False, 'error': 'Account disabled'}), 401
        
        # 更新登入時間
        db.update_admin_login(admin['admin_id'])
        
        # 創建會話
        session_id = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=24)
        
        db.create_admin_session(session_id, admin['admin_id'], expires_at, 
                              request.remote_addr, request.headers.get('User-Agent', ''))
        
        return jsonify({
            'ok': True,
            'session_id': session_id,
            'admin': {
                'admin_id': admin['admin_id'],
                'username': admin['username'],
                'email': admin['email'],
                'role': admin['role'],
                'permissions': admin['permissions']
            }
        })
        
    except Exception as e:
        logger.error(f"Admin login error: {e}")
        return jsonify({'ok': False, 'error': 'Login failed'}), 500

# 管理員登出
@app.route('/api/v1/admin/logout', methods=['POST'])
def admin_logout():
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
        
        session_id = auth_header.split(' ')[1]
        db.delete_admin_session(session_id)
        
        return jsonify({'ok': True, 'message': 'Logged out successfully'})
        
    except Exception as e:
        logger.error(f"Admin logout error: {e}")
        return jsonify({'ok': False, 'error': 'Logout failed'}), 500

# 初始化超級管理員
def init_super_admin():
    try:
        # 檢查是否已有超級管理員
        admins = db.get_all_admins()
        super_admins = [admin for admin in admins if admin['role'] == 'super_admin']
        
        if not super_admins:
            # 創建默認超級管理員
            admin_data = {
                'username': 'admin',
                'password_hash': hash_password('admin123'),
                'email': 'admin@example.com',
                'role': 'super_admin',
                'permissions': 'full_access',
                'is_active': True,
                'created_by': None
            }
            db.create_admin(admin_data)
            logger.info("Created default super admin: admin/admin123")
    except Exception as e:
        logger.error(f"Failed to init super admin: {e}")

@app.route('/', methods=['GET'])
def root():
    return jsonify({
        'message': 'AI 留學顧問後端服務運行中',
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'environment': {
            'GEMINI_API_KEY': bool(GEMINI_API_KEY),
            'SESSION_SECRET': bool(SESSION_SECRET),
            'GOOGLE_CLIENT_ID': bool(GOOGLE_CLIENT_ID),
            'GOOGLE_CLIENT_SECRET': bool(GOOGLE_CLIENT_SECRET),
            'LINE_CHANNEL_ID': bool(LINE_CHANNEL_ID)
        }
    })

@app.route('/admin.html')
def admin():
    """後台管理系統"""
    try:
        admin_path = os.path.join(os.path.dirname(__file__), 'admin.html')
        if os.path.exists(admin_path):
            return send_file(admin_path)
        else:
            return jsonify({'error': 'Admin page not found'}), 404
    except Exception as e:
        logger.error(f"Error serving admin page: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin-new.html')
def admin_new():
    """新版後台管理系統"""
    try:
        admin_path = os.path.join(os.path.dirname(__file__), 'admin-new.html')
        if os.path.exists(admin_path):
            return send_file(admin_path)
        else:
            return jsonify({'error': 'Admin page not found'}), 404
    except Exception as e:
        logger.error(f"Error serving admin page: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/debug/database', methods=['GET'])
def debug_database():
    """調試用：查看資料庫內容"""
    try:
        # 檢查資料庫狀態
        db_info = {
            'database_path': db.db_path,
            'database_exists': os.path.exists(db.db_path),
            'database_size': os.path.getsize(db.db_path) if os.path.exists(db.db_path) else 0,
            'persistent_dir': os.path.dirname(db.db_path),
            'persistent_dir_exists': os.path.exists(os.path.dirname(db.db_path))
        }
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # 查詢所有用戶
        cursor.execute('SELECT * FROM users')
        users = cursor.fetchall()
        
        # 調試：檢查用戶數據結構
        if users:
            logger.info(f"User data structure: {users[0]}")
            logger.info(f"User data length: {len(users[0])}")
        
        # 查詢所有 profile
        cursor.execute('SELECT * FROM user_profiles')
        profiles = cursor.fetchall()
        
        # 調試：檢查 profile 數據結構
        if profiles:
            logger.info(f"Profile data structure: {profiles[0]}")
            logger.info(f"Profile data length: {len(profiles[0])}")
        
        # 查詢所有聊天記錄
        cursor.execute('SELECT * FROM chat_messages LIMIT 10')
        messages = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            'ok': True,
            'database_info': db_info,
            'data': {
                'users': [
                    {
                        'id': user[0],
                        'user_id': user[1], 
                        'email': user[2],
                        'name': user[3],
                        'avatar': user[4],
                        'provider': 'google',  # 默認為 google，因為目前只有 Google 登入
                        'created_at': user[5],
                        'updated_at': user[6] if len(user) > 6 else user[5]
                    } for user in users
                ],
                'profiles': [
                    {
                        'id': profile[0],
                        'profile_id': profile[1],
                        'user_id': profile[2],
                        'user_role': profile[3],
                        'student_name': profile[4],
                        'student_email': profile[5],
                        'parent_name': profile[6],
                        'parent_email': profile[7],
                        'relationship': profile[8],
                        'child_name': profile[9],
                        'child_email': profile[10],
                        'citizenship': profile[11],
                        'gpa': profile[12],
                        'degree': profile[13],
                        'countries': profile[14],
                        'budget': profile[15],
                        'target_intake': profile[16],
                        'created_at': profile[17],
                        'updated_at': profile[18]
                    } for profile in profiles
                ],
                'recent_messages': [
                    {
                        'id': msg[0],
                        'profile_id': msg[1],
                        'message_type': msg[2],
                        'message_content': msg[3][:100] + '...' if len(msg[3]) > 100 else msg[3],
                        'created_at': msg[4]
                    } for msg in messages
                ],
                'env_vars': {
                    'LINE_CHANNEL_ID': bool(LINE_CHANNEL_ID),
                    'LINE_CHANNEL_SECRET': bool(LINE_CHANNEL_SECRET),
                    'GOOGLE_CLIENT_ID': bool(GOOGLE_CLIENT_ID),
                    'GOOGLE_CLIENT_SECRET': bool(GOOGLE_CLIENT_SECRET),
                    'GEMINI_API_KEY': bool(GEMINI_API_KEY),
                    'SESSION_SECRET': bool(SESSION_SECRET)
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Debug database error: {e}")
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/v1/admin/search-user', methods=['POST'])
def admin_search_user():
    """管理員搜尋用戶並分析"""
    try:
        data = request.get_json()
        search_term = data.get('search_term', '').strip()
        
        if not search_term:
            return jsonify({'ok': False, 'error': '搜尋關鍵字不能為空'}), 400
        
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # 搜尋用戶 profile（根據姓名搜尋）
        cursor.execute('''
            SELECT profile_id, user_id, user_role, student_name, parent_name, 
                   student_email, parent_email, relationship, child_name, child_email, 
                   citizenship, gpa, degree, countries, budget, target_intake, 
                   created_at, updated_at
            FROM user_profiles 
            WHERE student_name LIKE ? OR parent_name LIKE ? OR child_name LIKE ?
            LIMIT 1
        ''', (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%'))
        
        profile_data = cursor.fetchone()
        
        if not profile_data:
            conn.close()
            return jsonify({'ok': True, 'data': None})
        
        # 構建 profile 資料
        profile = {
            'profile_id': profile_data[0],
            'user_id': profile_data[1],
            'user_role': profile_data[2],
            'student_name': profile_data[3],
            'parent_name': profile_data[4],
            'student_email': profile_data[5],
            'parent_email': profile_data[6],
            'relationship': profile_data[7],
            'child_name': profile_data[8],
            'child_email': profile_data[9],
            'citizenship': profile_data[10],
            'gpa': profile_data[11],
            'degree': profile_data[12],
            'countries': json.loads(profile_data[13]) if profile_data[13] else [],
            'budget': profile_data[14],
            'target_intake': profile_data[15],
            'created_at': profile_data[16],
            'updated_at': profile_data[17]
        }
        
        # 獲取聊天記錄統計
        cursor.execute('''
            SELECT 
                COUNT(*) as total_messages,
                COUNT(DISTINCT DATE(created_at)) as active_days,
                MAX(created_at) as last_activity
            FROM chat_messages 
            WHERE profile_id = ? AND message_type = 'user'
        ''', (profile['profile_id'],))
        
        chat_stats = cursor.fetchone()
        
        # 獲取最近的聊天主題
        cursor.execute('''
            SELECT message_content, created_at
            FROM chat_messages 
            WHERE profile_id = ? AND message_type = 'ai'
            ORDER BY created_at DESC
            LIMIT 5
        ''', (profile['profile_id'],))
        
        recent_topics = cursor.fetchall()
        
        # 獲取使用統計
        cursor.execute('''
            SELECT action_type, COUNT(*) as count
            FROM usage_stats 
            WHERE profile_id = ?
            GROUP BY action_type
        ''', (profile['profile_id'],))
        
        usage_stats = cursor.fetchall()
        
        conn.close()
        
        # 分析用戶進度
        analysis = analyze_student_progress(
            chat_stats, 
            recent_topics, 
            usage_stats,
            profile['created_at']
        )
        
        return jsonify({
            'ok': True,
            'data': {
                'profile': profile,
                'analysis': {
                    'total_messages': chat_stats[0] if chat_stats else 0,
                    'active_days': chat_stats[1] if chat_stats else 0,
                    'last_activity': chat_stats[2].strftime('%Y-%m-%d %H:%M') if chat_stats and chat_stats[2] else '未知',
                    'recent_topics': [topic[0][:100] + '...' if len(topic[0]) > 100 else topic[0] for topic in recent_topics],
                    'usage_stats': [{'action': stat[0], 'count': stat[1]} for stat in usage_stats],
                    'progress': analysis.get('progress_summary', '分析中...'),
                    'main_topics': analysis.get('main_topics', '分析中...'),
                    'recommendations': analysis.get('recommendations', '分析中...')
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Admin search user error: {e}")
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@app.route('/api/v1/admin/backup', methods=['POST'])
def admin_backup_database():
    """管理員手動創建資料庫備份"""
    try:
        db.create_backup()
        return jsonify({'ok': True, 'message': 'Backup created successfully'})
    except Exception as e:
        logger.error(f"Backup creation error: {e}")
        return jsonify({'ok': False, 'error': 'Backup creation failed'}), 500

@app.route('/api/v1/admin/restore', methods=['POST'])
def admin_restore_database():
    """管理員從備份恢復資料庫"""
    try:
        success = db.restore_from_backup()
        if success:
            return jsonify({'ok': True, 'message': 'Database restored successfully'})
        else:
            return jsonify({'ok': False, 'error': 'No backup found or restoration failed'}), 404
    except Exception as e:
        logger.error(f"Database restoration error: {e}")
        return jsonify({'ok': False, 'error': 'Database restoration failed'}), 500

@app.route('/api/v1/admin/database-status', methods=['GET'])
def admin_database_status():
    """檢查資料庫狀態和備份情況"""
    try:
        import os
        
        # 基本資料庫資訊
        db_info = {
            'database_path': db.db_path,
            'database_exists': os.path.exists(db.db_path),
            'database_size': os.path.getsize(db.db_path) if os.path.exists(db.db_path) else 0,
            'persistent_dir': os.path.dirname(db.db_path),
            'persistent_dir_exists': os.path.exists(os.path.dirname(db.db_path))
        }
        
        # 備份資訊
        backup_dir = os.path.join(os.path.dirname(db.db_path), 'backups')
        backup_info = {
            'backup_dir': backup_dir,
            'backup_dir_exists': os.path.exists(backup_dir),
            'backup_count': 0,
            'latest_backup': None,
            'backup_files': []
        }
        
        if os.path.exists(backup_dir):
            backup_files = [f for f in os.listdir(backup_dir) if f.startswith('ai_study_advisor_backup_')]
            backup_info['backup_count'] = len(backup_files)
            backup_info['backup_files'] = sorted(backup_files)
            if backup_files:
                backup_info['latest_backup'] = sorted(backup_files)[-1]
        
        return jsonify({
            'ok': True,
            'database_info': db_info,
            'backup_info': backup_info
        })
        
    except Exception as e:
        logger.error(f"Database status check error: {e}")
        return jsonify({'ok': False, 'error': 'Failed to check database status'}), 500

def analyze_student_progress(chat_stats, recent_topics, usage_stats, created_at):
    """分析學生諮詢進度"""
    try:
        total_messages = chat_stats[0] if chat_stats else 0
        active_days = chat_stats[1] if chat_stats else 0
        last_activity = chat_stats[2] if chat_stats else None
        
        # 計算註冊天數
        from datetime import datetime
        if created_at:
            if isinstance(created_at, str):
                created_date = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            else:
                created_date = created_at
            days_since_registration = (datetime.now() - created_date).days
        else:
            days_since_registration = 0
        
        # 分析進度
        progress_summary = ""
        if total_messages == 0:
            progress_summary = "尚未開始諮詢"
        elif total_messages < 5:
            progress_summary = "諮詢初期階段"
        elif total_messages < 20:
            progress_summary = "諮詢進行中"
        else:
            progress_summary = "深度諮詢階段"
        
        # 分析主要話題
        main_topics = []
        if recent_topics:
            # 簡單的關鍵字分析
            topic_keywords = {
                '學校申請': ['學校', '申請', '錄取', '大學', '學院'],
                '費用相關': ['費用', '學費', '生活費', '預算', '獎學金'],
                '簽證問題': ['簽證', 'visa', '移民', '身份'],
                '住宿安排': ['住宿', '宿舍', '租房', 'homestay'],
                '語言考試': ['雅思', '托福', '語言', '考試', 'IELTS', 'TOEFL']
            }
            
            for topic in recent_topics[:3]:  # 只看前3個話題
                content = topic[0].lower()
                for category, keywords in topic_keywords.items():
                    if any(keyword in content for keyword in keywords):
                        if category not in main_topics:
                            main_topics.append(category)
        
        main_topics_text = ', '.join(main_topics) if main_topics else '一般諮詢'
        
        # 生成建議
        recommendations = []
        if total_messages < 5:
            recommendations.append("建議增加諮詢頻率，深入了解留學需求")
        if active_days < 3:
            recommendations.append("建議保持定期諮詢，建立持續的留學規劃")
        if not main_topics:
            recommendations.append("建議明確留學目標，聚焦具體問題")
        
        recommendations_text = '; '.join(recommendations) if recommendations else '繼續保持目前的諮詢進度'
        
        return {
            'progress_summary': progress_summary,
            'main_topics': main_topics_text,
            'recommendations': recommendations_text,
            'days_since_registration': days_since_registration
        }
        
    except Exception as e:
        logger.error(f"Analyze student progress error: {e}")
        return {
            'progress_summary': '分析中...',
            'main_topics': '分析中...',
            'recommendations': '分析中...'
        }

if __name__ == '__main__':
    try:
    # 初始化超級管理員
    init_super_admin()
    
    # 啟動應用
    port = int(os.getenv('PORT', 5000))
        logger.info(f"Starting Flask app on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
    except Exception as e:
        logger.error(f"Failed to start Flask app: {e}")
        raise
