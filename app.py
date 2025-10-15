# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, redirect
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
LINE_CHANNEL_ID = os.getenv('LINE_CHANNEL_ID')
LINE_CHANNEL_SECRET = os.getenv('LINE_CHANNEL_SECRET')

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
        
        if res.text:
            logger.info(f"Gemini response generated successfully, length: {len(res.text)}")
            return res.text
        else:
            logger.warning("Gemini returned empty response")
            return ""
    except Exception as e:
        logger.error(f"Gemini API error: {e}")
        return ""

# 初始化資料庫
try:
    db = DatabaseManager()
    logger.info("Database initialized successfully")
except Exception as e:
    logger.error(f"Database initialization failed: {e}")
    db = None

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
            else:
                db_status = "database_not_initialized"
                users_count = profiles_count = messages_count = 0
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
            # 一般登入：重定向到前端並帶上 token
            return redirect('https://aistudent.zeabur.app?token=' + jwt_token)
        
    except Exception as e:
        logger.error('Google callback error: {}'.format(e))
        return redirect('https://aistudent.zeabur.app?error=callback_failed')

# LINE 登入相關
@app.route('/api/v1/auth/line/login', methods=['GET'])
def line_login():
    """獲取 LINE 登入 URL"""
    try:
        # LINE Login 配置
        line_client_id = os.getenv('LINE_CLIENT_ID')
        line_redirect_uri = f"{API_BASE_URL}/auth/line/callback"
        line_state = 'line_login_' + str(int(time.time()))
        
        if not line_client_id:
            return jsonify({'ok': False, 'error': 'LINE_CLIENT_ID not configured'}), 500
        
        # 構建 LINE Login URL
        line_auth_url = (
            f"https://access.line.me/oauth2/v2.1/authorize?"
            f"response_type=code&"
            f"client_id={line_client_id}&"
            f"redirect_uri={line_redirect_uri}&"
            f"state={line_state}&"
            f"scope=profile%20openid%20email"
        )
        
        return jsonify({
            'ok': True,
            'login_url': line_auth_url,
            'state': line_state
        })
        
    except Exception as e:
        logger.error(f'LINE login URL generation error: {e}')
        return jsonify({'ok': False, 'error': 'Failed to generate LINE login URL'}), 500

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
        line_client_id = os.getenv('LINE_CLIENT_ID')
        line_client_secret = os.getenv('LINE_CLIENT_SECRET')
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
        
        # 重定向到前端
        return redirect(f'{FRONTEND_URL}/?token={jwt_token}&provider=line')
        
    except Exception as e:
        logger.error(f'LINE callback error: {e}')
        return redirect(f'{FRONTEND_URL}/?error=line_callback_failed')

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
        user_profile = db.get_user_profile(profile_id) if profile_id else {}
        logger.info(f"User profile retrieved: {bool(user_profile)}")
        
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
        
        # 儲存聊天記錄到資料庫
        if message and message.strip():
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
        
        return jsonify({'ok': True, 'reply': reply})
        
    except Exception as e:
        print('Gemini AI error: {}'.format(e))
        
        # 備用回覆
        if language == 'en':
            fallback_reply = 'I apologize, but I\'m currently experiencing technical difficulties. Please try again in a moment or contact our support team for assistance.'
        else:
            fallback_reply = '抱歉，我目前遇到技術問題。請稍後再試，或聯繫我們的支援團隊獲得協助。'
        
        return jsonify({'ok': True, 'reply': fallback_reply})

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
