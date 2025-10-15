# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
import os
import jwt
import json
from datetime import datetime, timedelta
import google.generativeai as genai
from google.oauth2 import id_token
from google.auth.transport import requests
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
LINE_CHANNEL_ID = os.getenv('LINE_CHANNEL_ID')
LINE_CHANNEL_SECRET = os.getenv('LINE_CHANNEL_SECRET')

# 初始化 Gemini AI
def use_gemini():
    return bool(GEMINI_API_KEY)

def gemini_generate_text(prompt):
    """使用 Gemini AI 生成文本"""
    if not use_gemini():
        return ""
    
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        res = model.generate_content(prompt)
        return res.text if res.text else ""
    except Exception as e:
        logger.error(f"Gemini API error: {e}")
        return ""

# 初始化資料庫
db = DatabaseManager()

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
            users_count = db.get_users_count()
            profiles_count = db.get_profiles_count()
            messages_count = db.get_messages_count()
        except Exception as e:
            db_status = f"error: {str(e)}"
            users_count = profiles_count = messages_count = 0
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'uptime': 'N/A',
            'version': '1.0.0',
            'database': {
                'status': db_status,
                'users_count': users_count,
                'profiles_count': profiles_count,
                'messages_count': messages_count
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

# Google OAuth 驗證
@app.route('/api/v1/auth/google/verify', methods=['POST'])
def verify_google_token():
    # 速率限制
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    if not check_rate_limit(client_ip):
        return jsonify({'ok': False, 'error': 'rate_limit_exceeded'}), 429
    
    try:
        data = request.get_json()
        id_token_str = data.get('idToken')
        
        if not id_token_str:
            return jsonify({'ok': False, 'error': 'missing idToken'}), 400
        
        # 驗證 Google ID Token
        idinfo = id_token.verify_oauth2_token(
            id_token_str, requests.Request(), GOOGLE_CLIENT_ID)
        
        user = {
            'userId': idinfo['sub'],
            'email': idinfo['email'],
            'name': idinfo['name'],
            'avatar': idinfo.get('picture')
        }
        
        # 儲存用戶資料到資料庫
        db.save_user(user)
        
        # 記錄使用統計
        db.save_usage_stat({
            'user_id': user['userId'],
            'action_type': 'login',
            'action_details': {'method': 'google'}
        })
        
        # 簽發 JWT
        payload = user.copy()
        payload['exp'] = datetime.utcnow() + timedelta(days=7)
        token = jwt.encode(payload, SESSION_SECRET, algorithm='HS256')
        
        return jsonify({'ok': True, 'token': token, 'user': user})
        
    except Exception as e:
        logger.error('Google verify error: {}'.format(e))
        return jsonify({'ok': False, 'error': 'verify_failed'}), 401

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
            'user_id': user_data['id'],
            'email': user_data.get('email', ''),
            'name': user_data.get('name', ''),
            'picture': user_data.get('picture', ''),
            'provider': 'google',
            'created_at': datetime.now().isoformat()
        }
        
        # 檢查用戶是否已存在
        existing_user = db.get_user_by_provider_id('google', user_data['id'])
        if not existing_user:
            db.save_user(user_info)
        else:
            # 更新現有用戶資料
            db.update_user(existing_user['user_id'], user_info)
        
        # 生成 JWT token
        token_payload = {
            'user_id': user_info['user_id'],
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
                    if (window.opener) {{
                        window.opener.postMessage({{
                            type: 'GOOGLE_LOGIN_SUCCESS',
                            token: '{jwt_token}',
                            user: {{
                                userId: '{user_info['user_id']}',
                                email: '{user_info['email']}',
                                name: '{user_info['name']}',
                                avatar: '{user_info['picture']}'
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
            # 一般登入：重定向到前端並帶上 token
            return redirect('https://aistudent.zeabur.app?token=' + jwt_token)
        
    except Exception as e:
        logger.error('Google callback error: {}'.format(e))
        return redirect('https://aistudent.zeabur.app?error=callback_failed')

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

def verify_jwt_token(f):
    """JWT 驗證裝飾器"""
    def wrapper(*args, **kwargs):
        try:
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return jsonify({'ok': False, 'error': 'unauthorized'}), 401
            
            token = auth_header.split(' ')[1]
            
            # 處理測試用的假 token
            if token == 'fake-jwt-token-for-testing':
                request.user = {
                    'userId': 'test-user',
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
            'user_id': request.user['userId'],
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
        
        # 獲取用戶資料
        user_profile = db.get_user_profile(profile_id) if profile_id else {}
        
        # 構建 Gemini 提示
        if language == 'en':
            system_prompt = """You are a professional AI Study Abroad Advisor. You provide personalized, expert guidance for students and parents planning international education.

User Role: {}
User Profile: {}

CRITICAL RESPONSE GUIDELINES:
1. Keep responses CONCISE and FOCUSED - answer the specific question asked
2. Use emojis to make content engaging (🎓📚💰🏠✈️📋)
3. MANDATORY: Each paragraph must be separated by blank lines
4. Use bullet points (•) for lists, each point on separate line
5. Use **bold** for important sections
6. Ask 1-2 follow-up questions to continue the conversation
7. Maximum 3-4 main points per response
8. FORCE: Each topic paragraph must have line breaks, never run together

Please respond in English and provide focused, actionable advice.""".format(
                user_role,
                json.dumps(user_profile, indent=2) if user_profile else 'No profile data available'
            )
            
            if message and message.strip():
                user_prompt = """User Question: "{}"

Provide a CONCISE, focused response that directly answers this question.

MANDATORY FORMATTING:
• Use emojis for visual appeal
• Each paragraph MUST be separated by blank lines
• Use bullet points (•) for lists, each on separate line
• Use **bold** for important sections
• Ask 1-2 follow-up questions
• Keep under 200 words
• NEVER run paragraphs together - always add line breaks between topics""".format(message)
            else:
                user_prompt = """Provide a brief, welcoming message for this {} (under 100 words). Use emojis and ask 1-2 questions to start the conversation.""".format(user_role)
        else:
            system_prompt = """你是一位專業的AI留學顧問。你為計劃國際教育的學生和家長提供個人化的專業指導。

用戶角色：{}
用戶資料：{}

重要回覆原則：
1. 回覆要簡潔有重點 - 直接回答用戶的具體問題
2. 使用 emoji 讓內容更生動 (🎓📚💰🏠✈️📋)
3. 每個段落之間必須有空行分隔
4. 使用項目符號 (•) 列出要點，每個要點單獨一行
5. 使用 **粗體** 標示重要段落
6. 提出 1-2 個後續問題延續對話
7. 每次回覆最多 3-4 個重點
8. 強制要求：每個主題段落後必須換行，不要連在一起

請用中文回應，提供有針對性的建議。""".format(
                user_role,
                json.dumps(user_profile, indent=2) if user_profile else '無資料'
            )
            
            if message and message.strip():
                user_prompt = """用戶問題：「{}」

請提供簡潔、有針對性的回覆，直接回答這個問題。

強制格式要求：
• 使用 emoji 增加視覺吸引力
• 每個段落之間必須有空行分隔
• 使用項目符號 (•) 列出要點，每個要點單獨一行
• 使用 **粗體** 標示重要段落
• 提出 1-2 個後續問題延續對話
• 控制在 200 字以內
• 絕對不要讓段落連在一起 - 主題段落間必須換行""".format(message)
            else:
                user_prompt = """請為這位{}提供簡短的歡迎訊息（100字以內）。

格式要求：
• 使用 emoji (🎓📚💰🏠✈️📋)
• 段落分明，適當換行
• 提出 1-2 個問題開始對話
• 保持簡潔有重點""".format(user_role)
        
        full_prompt = "{}\n\n{}".format(system_prompt, user_prompt)
        
        # 呼叫 Gemini AI
        if use_gemini():
            reply = gemini_generate_text(full_prompt)
        else:
            # 備用回覆
            if language == 'en':
                reply = 'AI service is temporarily unavailable. Please check your GEMINI_API_KEY configuration.'
            else:
                reply = 'AI服務暫時不可用，請檢查GEMINI_API_KEY配置。'
        
        # 儲存聊天記錄到資料庫
        if message and message.strip():
            # 儲存用戶訊息
            db.save_chat_message({
                'profile_id': profile_id,
                'user_id': request.user['userId'],
                'message_type': 'user',
                'message_content': message,
                'language': language,
                'user_role': user_role
            })
            
            # 儲存 AI 回覆
            db.save_chat_message({
                'profile_id': profile_id,
                'user_id': request.user['userId'],
                'message_type': 'ai',
                'message_content': reply,
                'language': language,
                'user_role': user_role
            })
            
            # 記錄使用統計
            db.save_usage_stat({
                'user_id': request.user['userId'],
                'profile_id': profile_id,
                'action_type': 'chat_message',
                'action_details': {'language': language, 'user_role': user_role}
            })
        
        return jsonify({'ok': True, 'data': {'response': reply}})
        
    except Exception as e:
        print('Gemini AI error: {}'.format(e))
        
        # 備用回覆
        if language == 'en':
            fallback_reply = 'I apologize, but I\'m currently experiencing technical difficulties. Please try again in a moment or contact our support team for assistance.'
        else:
            fallback_reply = '抱歉，我目前遇到技術問題。請稍後再試，或聯繫我們的支援團隊獲得協助。'
        
        return jsonify({'ok': True, 'data': {'response': fallback_reply}})

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

if __name__ == '__main__':
    # 初始化超級管理員
    init_super_admin()
    
    # 啟動應用
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
