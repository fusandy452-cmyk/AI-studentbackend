# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify
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
import schedule

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
        return (res.text or "").strip()
    except Exception as e:
        print('Gemini AI error: {}'.format(e))
        return ""

# 簡單的記憶體資料庫
user_profiles = {}

# 知識庫載入
def load_knowledge_base():
    """載入知識庫檔案"""
    knowledge_content = ""
    try:
        # 載入 Markdown 知識庫
        md_path = os.path.join(os.path.dirname(__file__), 'knowledge', 'AI留學顧問_KB_美國大學申請_v2025-10-14.md')
        if os.path.exists(md_path):
            with open(md_path, 'r', encoding='utf-8') as f:
                knowledge_content += f.read() + "\n\n"
        
        # 載入 JSONL 知識庫
        jsonl_path = os.path.join(os.path.dirname(__file__), 'knowledge', 'AI留學顧問_FAQ_美國大學申請_v2025-10-14.jsonl')
        if os.path.exists(jsonl_path):
            with open(jsonl_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            if 'question' in data and 'answer' in data:
                                knowledge_content += "Q: " + data['question'] + "\nA: " + data['answer'] + "\n\n"
                        except:
                            continue
        
        print('Knowledge base loaded, content length: {}'.format(len(knowledge_content)))
        return knowledge_content
    except Exception as e:
        print('Error loading knowledge base: {}'.format(e))
        return ""

# 檢索相關知識
def retrieve_relevant_knowledge(query, knowledge_base, max_chars=1500):
    """從知識庫中檢索相關內容"""
    if not knowledge_base or not query:
        return ""
    
    # 簡單的關鍵字匹配
    query_words = query.lower().split()
    lines = knowledge_base.split('\n')
    relevant_lines = []
    
    for line in lines:
        line_lower = line.lower()
        score = sum(1 for word in query_words if word in line_lower)
        if score > 0:
            relevant_lines.append((score, line))
    
    # 按相關性排序
    relevant_lines.sort(key=lambda x: x[0], reverse=True)
    
    # 選擇最相關的內容
    selected_content = []
    total_chars = 0
    for score, line in relevant_lines:
        if total_chars + len(line) > max_chars:
            break
        selected_content.append(line)
        total_chars += len(line)
    
    return '\n'.join(selected_content)

# 載入知識庫
KNOWLEDGE_BASE = load_knowledge_base()

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

def sanitize_input(text, max_length=1000):
    """清理和驗證用戶輸入"""
    if not text:
        return ""
    
    # 限制長度
    text = text[:max_length]
    
    # HTML 轉義
    text = html.escape(text)
    
    # 移除潛在危險字符
    text = re.sub(r'[<>"\']', '', text)
    
    return text.strip()

def validate_email(email):
    """驗證電子郵件格式"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# 管理員認證相關函數
def hash_password(password):
    """密碼雜湊"""
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return salt + password_hash.hex()

def verify_password(password, password_hash):
    """驗證密碼"""
    if len(password_hash) < 32:
        return False
    salt = password_hash[:32]
    stored_hash = password_hash[32:]
    password_hash_check = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return password_hash_check.hex() == stored_hash

def require_admin_auth(f):
    """管理員認證裝飾器"""
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Unauthorized', 'message': '需要管理員認證'}), 401
        
        session_id = auth_header.split(' ')[1]
        session = db.get_admin_session(session_id)
        
        if not session:
            return jsonify({'error': 'Unauthorized', 'message': '會話已過期'}), 401
        
        # 將管理員資訊添加到請求上下文
        request.admin = session
        return f(*args, **kwargs)
    
    wrapper.__name__ = f.__name__
    return wrapper

def require_super_admin(f):
    """超級管理員認證裝飾器"""
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Unauthorized', 'message': '需要管理員認證'}), 401
        
        session_id = auth_header.split(' ')[1]
        session = db.get_admin_session(session_id)
        
        if not session:
            return jsonify({'error': 'Unauthorized', 'message': '會話已過期'}), 401
        
        if session['role'] != 'super_admin':
            return jsonify({'error': 'Forbidden', 'message': '需要超級管理員權限'}), 403
        
        request.admin = session
        return f(*args, **kwargs)
    
    wrapper.__name__ = f.__name__
    return wrapper

def format_ai_response(text, language):
    """強制格式化 AI 回覆，確保段落分明"""
    if not text:
        return text
    
    # 基本清理
    text = text.strip()
    
    # 強制在特定標點後添加換行
    import re
    
    # 在句號、問號、驚嘆號後添加雙換行（段落分隔）
    text = re.sub(r'([。！？])\s*', r'\1\n\n', text)
    text = re.sub(r'([.!?])\s*', r'\1\n\n', text)
    
    # 在冒號後添加單換行
    text = re.sub(r'([：:])\s*', r'\1\n', text)
    text = re.sub(r'([：:])\s*', r'\1\n', text)
    
    # 確保項目符號後有換行
    text = re.sub(r'([•·])\s*', r'\1 ', text)
    
    # 清理多餘的空白行
    text = re.sub(r'\n{3,}', '\n\n', text)
    
    # 確保每行開頭沒有多餘空格
    lines = text.split('\n')
    formatted_lines = []
    for line in lines:
        formatted_lines.append(line.strip())
    
    return '\n'.join(formatted_lines)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'uptime': 'running',
        'version': '1.0.0'
    })

@app.route('/api/v1/health', methods=['GET'])
def api_health():
    # 檢查資料庫狀態
    try:
        users = db.get_all_users()
        profiles = db.get_user_profiles()
        messages = db.get_chat_messages(limit=10)
        
        return jsonify({
            'status': 'ok',
            'message': 'API 服務正常',
            'timestamp': datetime.now().isoformat(),
            'database': {
                'status': 'connected',
                'users_count': len(users),
                'profiles_count': len(profiles),
                'messages_count': len(messages)
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': 'API 服務異常',
            'timestamp': datetime.now().isoformat(),
            'database': {
                'status': 'error',
                'error': str(e)
            }
        }), 500

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
        
        # 重定向到前端並帶上 token
        return redirect('https://aistudent.zeabur.app?token=' + jwt_token)
        
    except Exception as e:
        logger.error('Google callback error: {}'.format(e))
        return redirect('https://aistudent.zeabur.app?error=callback_failed')

@app.route('/api/v1/auth/logout', methods=['POST'])
def user_logout():
    """用戶登出"""
    try:
        # 清除 JWT token (前端處理)
        return jsonify({'ok': True, 'message': '已登出'})
    except Exception as e:
        logger.error('User logout error: {}'.format(e))
        return jsonify({'error': '登出失敗'}), 500

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
        
        # 儲存到記憶體（保持向後相容）
        user_profiles[profile_id] = user_data
        
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
        user_profile = user_profiles.get(profile_id, {})
        
        # 檢索相關知識庫內容
        relevant_knowledge = ""
        if message and message.strip():
            relevant_knowledge = retrieve_relevant_knowledge(message, KNOWLEDGE_BASE)
        
        # 構建 Gemini 提示
        if language == 'en':
            system_prompt = """You are a professional AI Study Abroad Advisor. You provide personalized, expert guidance for students and parents planning international education.

User Role: {}
User Profile: {}

Knowledge Base Context:
{}

CRITICAL RESPONSE GUIDELINES:
1. Keep responses CONCISE and FOCUSED - answer the specific question asked
2. Use emojis to make content engaging (🎓📚💰🏠✈️📋)
3. MANDATORY: Each paragraph must be separated by blank lines
4. Use bullet points (•) for lists, each point on separate line
5. Use **bold** for important sections
6. Ask 1-2 follow-up questions to continue the conversation
7. Maximum 3-4 main points per response
8. Reference knowledge base when relevant
9. FORCE: Each topic paragraph must have line breaks, never run together

Please respond in English and provide focused, actionable advice.""".format(
                user_role,
                json.dumps(user_profile, indent=2) if user_profile else 'No profile data available',
                relevant_knowledge if relevant_knowledge else 'No relevant knowledge found'
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

知識庫內容：
{}

重要回覆原則：
1. 回覆要簡潔有重點 - 直接回答用戶的具體問題
2. 使用 emoji 讓內容更生動 (🎓📚💰🏠✈️📋)
3. 每個段落之間必須有空行分隔
4. 使用項目符號 (•) 列出要點，每個要點單獨一行
5. 使用 **粗體** 標示重要段落
6. 提出 1-2 個後續問題延續對話
7. 每次回覆最多 3-4 個重點
8. 適時引用知識庫內容
9. 強制要求：每個主題段落後必須換行，不要連在一起

請用中文回應，提供有針對性的建議。""".format(
                user_role,
                json.dumps(user_profile, indent=2) if user_profile else '無資料',
                relevant_knowledge if relevant_knowledge else '無相關知識內容'
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
            # 強制格式化回覆
            reply = format_ai_response(reply, language)
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

# ======== 後台管理 API ========

@app.route('/api/v1/admin/users', methods=['GET'])
@verify_jwt_token
def admin_get_users():
    """獲取所有用戶資料"""
    try:
        users = db.get_all_users()
        return jsonify({'ok': True, 'data': users})
    except Exception as e:
        print('Admin get users error: {}'.format(e))
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@app.route('/api/v1/admin/profiles', methods=['GET'])
@verify_jwt_token
def admin_get_profiles():
    """獲取所有用戶設定資料"""
    try:
        user_id = request.args.get('user_id')
        profiles = db.get_user_profiles(user_id)
        return jsonify({'ok': True, 'data': profiles})
    except Exception as e:
        print('Admin get profiles error: {}'.format(e))
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@app.route('/api/v1/admin/messages', methods=['GET'])
@verify_jwt_token
def admin_get_messages():
    """獲取聊天記錄"""
    try:
        profile_id = request.args.get('profile_id')
        limit = int(request.args.get('limit', 100))
        messages = db.get_chat_messages(profile_id, limit)
        return jsonify({'ok': True, 'data': messages})
    except Exception as e:
        print('Admin get messages error: {}'.format(e))
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@app.route('/api/v1/admin/stats', methods=['GET'])
@verify_jwt_token
def admin_get_stats():
    """獲取使用統計"""
    try:
        days = int(request.args.get('days', 30))
        stats = db.get_usage_stats(days)
        return jsonify({'ok': True, 'data': stats})
    except Exception as e:
        print('Admin get stats error: {}'.format(e))
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@app.route('/api/v1/admin/export', methods=['GET'])
@verify_jwt_token
def admin_export_data():
    """匯出用戶資料"""
    try:
        user_id = request.args.get('user_id')
        data = db.export_user_data(user_id)
        return jsonify({'ok': True, 'data': data})
    except Exception as e:
        print('Admin export error: {}'.format(e))
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@app.route('/api/v1/admin/dashboard', methods=['GET'])
@verify_jwt_token
def admin_dashboard():
    """後台儀表板數據"""
    try:
        # 獲取基本統計
        users = db.get_all_users()
        profiles = db.get_user_profiles()
        messages = db.get_chat_messages(limit=1000)
        stats = db.get_usage_stats(days=30)
        study_progress = db.get_study_progress()
        chat_summaries = db.get_chat_summaries()
        role_summary = db.get_user_role_summary()
        
        # 計算統計數據
        total_users = len(users)
        total_profiles = len(profiles)
        total_messages = len(messages)
        
        # 按角色統計
        student_count = len([p for p in profiles if p.get('user_role') == 'student'])
        parent_count = len([p for p in profiles if p.get('user_role') == 'parent'])
        
        # 按語言統計
        zh_messages = len([m for m in messages if m.get('language') == 'zh'])
        en_messages = len([m for m in messages if m.get('language') == 'en'])
        
        # 最近活動
        recent_users = users[:10]  # 最近10個用戶
        recent_messages = messages[:20]  # 最近20條訊息
        
        dashboard_data = {
            'summary': {
                'total_users': total_users,
                'total_profiles': total_profiles,
                'total_messages': total_messages,
                'student_count': student_count,
                'parent_count': parent_count,
                'zh_messages': zh_messages,
                'en_messages': en_messages
            },
            'recent_users': recent_users,
            'recent_messages': recent_messages,
            'usage_stats': stats,
            'study_progress': study_progress,
            'chat_summaries': chat_summaries,
            'role_summary': role_summary
        }
        
        return jsonify({'ok': True, 'data': dashboard_data})
    except Exception as e:
        print('Admin dashboard error: {}'.format(e))
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@app.route('/api/v1/admin/progress', methods=['GET'])
@verify_jwt_token
def admin_get_progress():
    """獲取留學進度"""
    try:
        profile_id = request.args.get('profile_id')
        progress = db.get_study_progress(profile_id)
        return jsonify({'ok': True, 'data': progress})
    except Exception as e:
        print('Admin get progress error: {}'.format(e))
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@app.route('/api/v1/admin/progress', methods=['POST'])
@verify_jwt_token
def admin_save_progress():
    """儲存留學進度"""
    try:
        progress_data = request.get_json()
        success = db.save_study_progress(progress_data)
        if success:
            return jsonify({'ok': True, 'message': 'Progress saved successfully'})
        else:
            return jsonify({'ok': False, 'error': 'Failed to save progress'}), 500
    except Exception as e:
        print('Admin save progress error: {}'.format(e))
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@app.route('/api/v1/admin/summaries', methods=['GET'])
@verify_jwt_token
def admin_get_summaries():
    """獲取聊天摘要"""
    try:
        profile_id = request.args.get('profile_id')
        summaries = db.get_chat_summaries(profile_id)
        return jsonify({'ok': True, 'data': summaries})
    except Exception as e:
        print('Admin get summaries error: {}'.format(e))
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@app.route('/api/v1/admin/summaries', methods=['POST'])
@verify_jwt_token
def admin_save_summary():
    """儲存聊天摘要"""
    try:
        summary_data = request.get_json()
        success = db.save_chat_summary(summary_data)
        if success:
            return jsonify({'ok': True, 'message': 'Summary saved successfully'})
        else:
            return jsonify({'ok': False, 'error': 'Failed to save summary'}), 500
    except Exception as e:
        print('Admin save summary error: {}'.format(e))
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@app.route('/api/v1/admin/role-summary', methods=['GET'])
@verify_jwt_token
def admin_get_role_summary():
    """獲取用戶角色摘要"""
    try:
        summary = db.get_user_role_summary()
        return jsonify({'ok': True, 'data': summary})
    except Exception as e:
        print('Admin get role summary error: {}'.format(e))
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@app.route('/', methods=['GET'])
def root():
    return jsonify({
        'message': 'AI 留學顧問後端服務運行中',
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route('/admin.html', methods=['GET'])
def admin_page():
    """提供後台管理頁面"""
    try:
        import os
        admin_path = os.path.join(os.path.dirname(__file__), 'admin.html')
        with open(admin_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return content, 200, {'Content-Type': 'text/html; charset=utf-8'}
    except FileNotFoundError:
        return jsonify({'error': 'Admin page not found', 'path': admin_path}), 404
    except Exception as e:
        return jsonify({'error': 'Failed to load admin page', 'details': str(e)}), 500

@app.route('/api/v1/admin/backup', methods=['GET'])
def backup_database():
    """資料庫備份 API"""
    try:
        # 檢查管理員權限
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Unauthorized'}), 401
        
        # 獲取所有資料
        users = db.get_all_users()
        profiles = db.get_user_profiles()
        messages = db.get_chat_messages(limit=1000)
        usage_stats = db.get_usage_stats(limit=1000)
        
        backup_data = {
            'timestamp': datetime.now().isoformat(),
            'users': users,
            'profiles': profiles,
            'messages': messages,
            'usage_stats': usage_stats
        }
        
        return jsonify({
            'ok': True,
            'backup': backup_data,
            'counts': {
                'users': len(users),
                'profiles': len(profiles),
                'messages': len(messages),
                'usage_stats': len(usage_stats)
            }
        })
        
    except Exception as e:
        logger.error('Backup error: {}'.format(e))
        return jsonify({'error': 'Backup failed', 'details': str(e)}), 500

@app.route('/api/v1/admin/export', methods=['GET'])
def export_data():
    """匯出所有資料"""
    try:
        export_data = db.export_all_data()
        if export_data:
            return jsonify({
                'ok': True,
                'data': export_data
            })
        else:
            return jsonify({'error': 'Export failed'}), 500
    except Exception as e:
        logger.error('Export data error: {}'.format(e))
        return jsonify({'error': 'Export failed', 'details': str(e)}), 500

@app.route('/api/v1/admin/import', methods=['POST'])
def import_data():
    """匯入資料"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        if db.import_data(data):
            return jsonify({'ok': True, 'message': 'Data imported successfully'})
        else:
            return jsonify({'error': 'Import failed'}), 500
    except Exception as e:
        logger.error('Import data error: {}'.format(e))
        return jsonify({'error': 'Import failed', 'details': str(e)}), 500

@app.route('/api/v1/admin/backup/status', methods=['GET'])
def backup_status():
    """獲取備份狀態"""
    try:
        import os
        import glob
        
        backup_dirs = ['/data/backups', '/tmp/backups']
        backup_files = []
        
        for backup_dir in backup_dirs:
            if os.path.exists(backup_dir):
                files = glob.glob(os.path.join(backup_dir, 'auto_backup_*.json'))
                for file_path in files:
                    stat = os.stat(file_path)
                    backup_files.append({
                        'filename': os.path.basename(file_path),
                        'path': file_path,
                        'size': stat.st_size,
                        'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })
        
        # 按修改時間排序
        backup_files.sort(key=lambda x: x['modified'], reverse=True)
        
        return jsonify({
            'ok': True,
            'backups': backup_files,
            'total_backups': len(backup_files),
            'backup_dirs': backup_dirs
        })
        
    except Exception as e:
        logger.error('Backup status error: {}'.format(e))
        return jsonify({'error': 'Failed to get backup status', 'details': str(e)}), 500

@app.route('/api/v1/admin/backup/manual', methods=['POST'])
def manual_backup():
    """手動觸發備份"""
    try:
        if auto_backup():
            return jsonify({'ok': True, 'message': 'Manual backup completed successfully'})
        else:
            return jsonify({'error': 'Manual backup failed'}), 500
    except Exception as e:
        logger.error('Manual backup error: {}'.format(e))
        return jsonify({'error': 'Manual backup failed', 'details': str(e)}), 500

@app.route('/api/v1/monitor/status', methods=['GET'])
def monitor_status():
    """系統監控狀態 API"""
    try:
        import psutil
        import os
        
        # 系統資源監控
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # 資料庫狀態
        try:
            users = db.get_all_users()
            profiles = db.get_user_profiles()
            messages = db.get_chat_messages(limit=10)
            db_status = 'healthy'
        except Exception as e:
            db_status = 'error'
            logger.error('Database health check failed: {}'.format(e))
        
        # API 健康檢查
        api_status = 'healthy'
        
        # 環境變數檢查
        env_status = {
            'GEMINI_API_KEY': bool(GEMINI_API_KEY),
            'SESSION_SECRET': bool(SESSION_SECRET),
            'GOOGLE_CLIENT_ID': bool(GOOGLE_CLIENT_ID),
            'LINE_CHANNEL_ID': bool(LINE_CHANNEL_ID)
        }
        
        return jsonify({
            'ok': True,
            'timestamp': datetime.now().isoformat(),
            'system': {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_available': memory.available,
                'disk_percent': disk.percent,
                'disk_free': disk.free
            },
            'services': {
                'database': db_status,
                'api': api_status
            },
            'environment': env_status,
            'uptime': time.time() - psutil.boot_time()
        })
        
    except ImportError:
        # 如果 psutil 不可用，返回基本狀態
        return jsonify({
            'ok': True,
            'timestamp': datetime.now().isoformat(),
            'system': {
                'status': 'basic_monitoring'
            },
            'services': {
                'database': 'unknown',
                'api': 'healthy'
            },
            'environment': {
                'GEMINI_API_KEY': bool(GEMINI_API_KEY),
                'SESSION_SECRET': bool(SESSION_SECRET),
                'GOOGLE_CLIENT_ID': bool(GOOGLE_CLIENT_ID),
                'LINE_CHANNEL_ID': bool(LINE_CHANNEL_ID)
            }
        })
    except Exception as e:
        logger.error('Monitor status error: {}'.format(e))
        return jsonify({
            'ok': False,
            'error': 'Monitor check failed',
            'details': str(e)
        }), 500

@app.route('/api/v1/monitor/ssl', methods=['GET'])
def monitor_ssl():
    """SSL 證書監控 API"""
    try:
        import ssl
        import socket
        from datetime import datetime
        
        def check_ssl_cert(hostname, port=443):
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return cert
        
        # 檢查前端 SSL
        frontend_cert = check_ssl_cert('aistudent.zeabur.app')
        backend_cert = check_ssl_cert('aistudentbackend.zeabur.app')
        
        def parse_cert_dates(cert):
            from datetime import datetime
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_remaining = (not_after - datetime.now()).days
            return {
                'not_before': not_before.isoformat(),
                'not_after': not_after.isoformat(),
                'days_remaining': days_remaining,
                'status': 'expiring_soon' if days_remaining < 30 else 'healthy'
            }
        
        return jsonify({
            'ok': True,
            'timestamp': datetime.now().isoformat(),
            'certificates': {
                'frontend': parse_cert_dates(frontend_cert),
                'backend': parse_cert_dates(backend_cert)
            }
        })
        
    except Exception as e:
        logger.error('SSL monitor error: {}'.format(e))
        return jsonify({
            'ok': False,
            'error': 'SSL check failed',
            'details': str(e)
        }), 500

# LINE Login 相關 API
@app.route('/api/v1/auth/line/login', methods=['GET'])
def line_login():
    """生成 LINE Login URL"""
    if not LINE_CHANNEL_ID:
        return jsonify({'ok': False, 'error': 'LINE Login not configured'}), 400
    
    # 生成 state 參數防止 CSRF 攻擊
    import secrets
    state = secrets.token_urlsafe(32)
    
    # 儲存 state 到 session
    session['line_state'] = state
    
    # 構建 LINE Login URL
    line_login_url = 'https://access.line.me/oauth2/v2.1/authorize'
    params = {
        'response_type': 'code',
        'client_id': LINE_CHANNEL_ID,
        'redirect_uri': 'https://aistudentbackend.zeabur.app/auth/line/callback',
        'state': state,
        'scope': 'profile openid',
        'nonce': secrets.token_urlsafe(16)
    }
    
    login_url = line_login_url + '?' + urllib.parse.urlencode(params)
    
    return jsonify({
        'ok': True,
        'login_url': login_url
    })

@app.route('/auth/line/callback', methods=['GET'])
def line_callback():
    """處理 LINE Login 回調"""
    try:
        code = request.args.get('code')
        state = request.args.get('state')
        error = request.args.get('error')
        
        if error:
            return redirect('https://aistudent.zeabur.app?error=' + error)
        
        if not code or not state:
            return redirect('https://aistudent.zeabur.app?error=missing_parameters')
        
        # 驗證 state 參數
        if state != session.get('line_state'):
            return redirect('https://aistudent.zeabur.app?error=invalid_state')
        
        # 交換 access token
        token_url = 'https://api.line.me/oauth2/v2.1/token'
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'https://aistudentbackend.zeabur.app/auth/line/callback',
            'client_id': LINE_CHANNEL_ID,
            'client_secret': LINE_CHANNEL_SECRET
        }
        
        token_response = requests.post(token_url, data=token_data)
        token_result = token_response.json()
        
        if 'access_token' not in token_result:
            return redirect('https://aistudent.zeabur.app?error=token_exchange_failed')
        
        access_token = token_result['access_token']
        
        # 獲取用戶資料
        profile_url = 'https://api.line.me/v2/profile'
        headers = {'Authorization': 'Bearer ' + access_token}
        profile_response = requests.get(profile_url, headers=headers)
        profile_data = profile_response.json()
        
        if 'userId' not in profile_data:
            return redirect('https://aistudent.zeabur.app?error=profile_fetch_failed')
        
        # 儲存用戶資料
        user_data = {
            'user_id': profile_data['userId'],
            'email': profile_data.get('email', ''),
            'name': profile_data.get('displayName', ''),
            'picture': profile_data.get('pictureUrl', ''),
            'provider': 'line',
            'created_at': datetime.now().isoformat()
        }
        
        # 檢查用戶是否已存在
        existing_user = db.get_user_by_provider_id('line', profile_data['userId'])
        if not existing_user:
            db.save_user(user_data)
        else:
            # 更新現有用戶資料
            db.update_user(existing_user['user_id'], user_data)
        
        # 生成 JWT token
        token_payload = {
            'user_id': user_data['user_id'],
            'email': user_data['email'],
            'name': user_data['name'],
            'provider': 'line',
            'exp': datetime.utcnow() + timedelta(days=7)
        }
        
        jwt_token = jwt.encode(token_payload, SESSION_SECRET, algorithm='HS256')
        
        # 重定向到前端並帶上 token
        return redirect('https://aistudent.zeabur.app?token=' + jwt_token)
        
    except Exception as e:
        print('LINE Login error: {}'.format(e))
        return redirect('https://aistudent.zeabur.app?error=login_failed')

# 管理員認證 API
@app.route('/api/v1/admin/login', methods=['POST'])
def admin_login():
    """管理員登入"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': '請提供用戶名和密碼'}), 400
        
        # 獲取管理員資訊
        admin = db.get_admin_by_username(username)
        if not admin:
            return jsonify({'error': '用戶名或密碼錯誤'}), 401
        
        # 驗證密碼
        if not verify_password(password, admin['password_hash']):
            return jsonify({'error': '用戶名或密碼錯誤'}), 401
        
        # 生成會話
        session_id = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=8)
        
        # 儲存會話
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        user_agent = request.headers.get('User-Agent', '')
        
        if db.create_admin_session(session_id, admin['admin_id'], expires_at, client_ip, user_agent):
            # 更新最後登入時間
            db.update_admin_login(admin['admin_id'], client_ip)
            
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
        else:
            return jsonify({'error': '登入失敗'}), 500
            
    except Exception as e:
        logger.error('Admin login error: {}'.format(e))
        return jsonify({'error': '登入失敗'}), 500

@app.route('/api/v1/admin/logout', methods=['POST'])
def admin_logout():
    """管理員登出"""
    try:
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            session_id = auth_header.split(' ')[1]
            db.delete_admin_session(session_id)
        
        return jsonify({'ok': True, 'message': '已登出'})
        
    except Exception as e:
        logger.error('Admin logout error: {}'.format(e))
        return jsonify({'error': '登出失敗'}), 500

@app.route('/api/v1/admin/profile', methods=['GET'])
@require_admin_auth
def admin_profile():
    """獲取管理員資料"""
    return jsonify({
        'ok': True,
        'admin': {
            'admin_id': request.admin['admin_id'],
            'username': request.admin['username'],
            'email': request.admin['email'],
            'role': request.admin['role'],
            'permissions': request.admin['permissions']
        }
    })

@app.route('/api/v1/admin/admins', methods=['GET'])
@require_admin_auth
def get_admins():
    """獲取所有管理員列表"""
    try:
        admins = db.get_all_admins()
        return jsonify({'ok': True, 'admins': admins})
    except Exception as e:
        logger.error('Get admins error: {}'.format(e))
        return jsonify({'error': '獲取管理員列表失敗'}), 500

@app.route('/api/v1/admin/admins', methods=['POST'])
@require_super_admin
def create_admin():
    """建立新管理員"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        email = data.get('email', '').strip()
        role = data.get('role', 'advisor')
        permissions = data.get('permissions', 'read_only')
        
        # 驗證輸入
        if not username or not password or not email:
            return jsonify({'error': '請提供完整的用戶資訊'}), 400
        
        if not validate_email(email):
            return jsonify({'error': '電子郵件格式不正確'}), 400
        
        if len(password) < 6:
            return jsonify({'error': '密碼長度至少6位'}), 400
        
        # 檢查用戶名是否已存在
        existing_admin = db.get_admin_by_username(username)
        if existing_admin:
            return jsonify({'error': '用戶名已存在'}), 400
        
        # 建立管理員
        password_hash = hash_password(password)
        created_by = request.admin['username']
        
        if db.create_admin(username, password_hash, email, role, permissions, created_by):
            return jsonify({'ok': True, 'message': '管理員建立成功'})
        else:
            return jsonify({'error': '建立管理員失敗'}), 500
            
    except Exception as e:
        logger.error('Create admin error: {}'.format(e))
        return jsonify({'error': '建立管理員失敗'}), 500

@app.route('/api/v1/admin/admins/<int:admin_id>/permissions', methods=['PUT'])
@require_super_admin
def update_admin_permissions(admin_id):
    """更新管理員權限"""
    try:
        data = request.get_json()
        permissions = data.get('permissions', 'read_only')
        
        if db.update_admin_permissions(admin_id, permissions):
            return jsonify({'ok': True, 'message': '權限更新成功'})
        else:
            return jsonify({'error': '權限更新失敗'}), 500
            
    except Exception as e:
        logger.error('Update admin permissions error: {}'.format(e))
        return jsonify({'error': '權限更新失敗'}), 500

# 初始化超級管理員
def init_super_admin():
    """初始化超級管理員帳號"""
    try:
        # 檢查是否已有超級管理員
        admins = db.get_all_admins()
        super_admins = [admin for admin in admins if admin['role'] == 'super_admin']
        
        if not super_admins:
            # 建立預設超級管理員
            username = 'admin'
            password = 'admin123456'  # 請在首次登入後立即修改
            email = 'admin@aistudent.com'
            
            password_hash = hash_password(password)
            if db.create_admin(username, password_hash, email, 'super_admin', 'full_access', 'system'):
                logger.info('Super admin created: username=admin, password=admin123456')
                logger.warning('請立即修改預設密碼！')
            else:
                logger.error('Failed to create super admin')
    except Exception as e:
        logger.error('Init super admin error: {}'.format(e))

# 自動備份功能
def auto_backup():
    """自動備份資料庫"""
    try:
        logger.info('Starting automatic backup...')
        
        # 匯出資料
        export_data = db.export_all_data()
        if not export_data:
            logger.error('Failed to export data for backup')
            return False
        
        # 儲存備份到檔案
        import os
        backup_dir = '/data/backups' if os.path.exists('/data') else '/tmp/backups'
        os.makedirs(backup_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(backup_dir, f'auto_backup_{timestamp}.json')
        
        with open(backup_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)
        
        logger.info(f'Automatic backup completed: {backup_file}')
        
        # 清理舊備份（保留最近7天）
        cleanup_old_backups(backup_dir)
        
        return True
        
    except Exception as e:
        logger.error(f'Automatic backup failed: {e}')
        return False

def cleanup_old_backups(backup_dir, days_to_keep=7):
    """清理舊備份檔案"""
    try:
        import os
        import glob
        from datetime import datetime, timedelta
        
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        
        backup_files = glob.glob(os.path.join(backup_dir, 'auto_backup_*.json'))
        
        for backup_file in backup_files:
            file_time = datetime.fromtimestamp(os.path.getmtime(backup_file))
            if file_time < cutoff_date:
                os.remove(backup_file)
                logger.info(f'Removed old backup: {backup_file}')
                
    except Exception as e:
        logger.error(f'Failed to cleanup old backups: {e}')

def start_backup_scheduler():
    """啟動備份排程器"""
    try:
        # 設定每日備份（凌晨2點）
        schedule.every().day.at("02:00").do(auto_backup)
        
        # 設定每小時備份（作為備用）
        schedule.every().hour.do(auto_backup)
        
        def run_scheduler():
            while True:
                schedule.run_pending()
                time.sleep(60)  # 每分鐘檢查一次
        
        # 在背景執行排程器
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
        
        logger.info('Backup scheduler started')
        
    except Exception as e:
        logger.error(f'Failed to start backup scheduler: {e}')

# 資料恢復功能
def auto_restore():
    """自動恢復資料（如果資料庫為空）"""
    try:
        # 檢查是否有現有資料
        users = db.get_all_users()
        if len(users) > 0:
            logger.info('Database has existing data, skipping restore')
            return True
        
        # 尋找最新的備份檔案
        import os
        import glob
        
        backup_dirs = ['/data/backups', '/tmp/backups']
        latest_backup = None
        latest_time = 0
        
        for backup_dir in backup_dirs:
            if os.path.exists(backup_dir):
                backup_files = glob.glob(os.path.join(backup_dir, 'auto_backup_*.json'))
                for backup_file in backup_files:
                    file_time = os.path.getmtime(backup_file)
                    if file_time > latest_time:
                        latest_time = file_time
                        latest_backup = backup_file
        
        if latest_backup:
            logger.info(f'Found backup file: {latest_backup}')
            
            # 讀取備份檔案
            with open(latest_backup, 'r', encoding='utf-8') as f:
                backup_data = json.load(f)
            
            # 恢復資料
            if db.import_data(backup_data):
                logger.info('Data restored successfully from backup')
                return True
            else:
                logger.error('Failed to restore data from backup')
                return False
        else:
            logger.info('No backup files found, starting with empty database')
            return True
            
    except Exception as e:
        logger.error(f'Auto restore failed: {e}')
        return False

# 在應用啟動時初始化超級管理員
init_super_admin()

# 嘗試自動恢復資料
auto_restore()

# 啟動自動備份
start_backup_scheduler()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
