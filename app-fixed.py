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
@app.route('/api/v1/health', methods=['GET'])
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

# Google OAuth 登入
@app.route('/api/v1/auth/google/login', methods=['POST'])
def google_login():
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return jsonify({'ok': False, 'error': 'Token required'}), 400
        
        # 驗證 Google token
        try:
            idinfo = id_token.verify_oauth2_token(token, requests.Request(), GOOGLE_CLIENT_ID)
            user_id = idinfo['sub']
            email = idinfo.get('email', '')
            name = idinfo.get('name', '')
            picture = idinfo.get('picture', '')
        except ValueError as e:
            return jsonify({'ok': False, 'error': 'Invalid token'}), 400
        
        # 檢查用戶是否存在
        user = db.get_user_by_google_id(user_id)
        if not user:
            # 創建新用戶
            user_id_db = db.create_user({
                'google_id': user_id,
                'email': email,
                'name': name,
                'picture': picture,
                'login_type': 'google'
            })
        else:
            user_id_db = user['user_id']
            # 更新最後登入時間
            db.update_user_login_time(user_id_db)
        
        # 生成 JWT token
        payload = {
            'user_id': user_id_db,
            'google_id': user_id,
            'email': email,
            'name': name,
            'exp': datetime.utcnow() + timedelta(days=7)
        }
        jwt_token = jwt.encode(payload, SESSION_SECRET, algorithm='HS256')
        
        return jsonify({
            'ok': True,
            'token': jwt_token,
            'user': {
                'user_id': user_id_db,
                'email': email,
                'name': name,
                'picture': picture
            }
        })
        
    except Exception as e:
        logger.error(f"Google login error: {e}")
        return jsonify({'ok': False, 'error': 'Login failed'}), 500

# 用戶登出
@app.route('/api/v1/auth/logout', methods=['POST'])
def logout():
    try:
        # 前端會清除 localStorage 中的 token
        return jsonify({'ok': True, 'message': 'Logged out successfully'})
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'ok': False, 'error': 'Logout failed'}), 500

# 聊天 API
@app.route('/api/v1/chat', methods=['POST'])
def chat():
    try:
        data = request.get_json()
        message = data.get('message', '').strip()
        user_id = data.get('user_id')
        
        if not message:
            return jsonify({'ok': False, 'error': 'Message required'}), 400
        
        if not user_id:
            return jsonify({'ok': False, 'error': 'User ID required'}), 400
        
        # 儲存用戶訊息
        db.save_message(user_id, 'user', message)
        
        # 生成 AI 回應
        ai_response = gemini_generate_text(f"""
你是一位專業的留學顧問，請回答以下問題：

用戶問題：{message}

請提供專業、詳細的留學建議，並使用適當的 emoji 讓回答更生動。
""")
        
        if not ai_response:
            ai_response = "抱歉，我暫時無法回答您的問題。請稍後再試。"
        
        # 儲存 AI 回應
        db.save_message(user_id, 'assistant', ai_response)
        
        return jsonify({
            'ok': True,
            'response': ai_response
        })
        
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return jsonify({'ok': False, 'error': 'Chat failed'}), 500

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

if __name__ == '__main__':
    # 初始化超級管理員
    init_super_admin()
    
    # 啟動應用
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
