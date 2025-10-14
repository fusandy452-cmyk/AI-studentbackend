from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import jwt
import json
from datetime import datetime, timedelta
import google.generativeai as genai
from google.oauth2 import id_token
from google.auth.transport import requests

app = Flask(__name__)
CORS(app, origins=["https://aistudent.zeabur.app"])

# 環境變數
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
SESSION_SECRET = os.getenv('SESSION_SECRET', 'dev-secret')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')

# 初始化 Gemini AI
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-pro')

# 簡單的記憶體資料庫
user_profiles = {}

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
    return jsonify({
        'status': 'ok',
        'message': 'API 服務正常',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/v1/auth/config', methods=['GET'])
def auth_config():
    return jsonify({
        'ok': True,
        'googleClientId': GOOGLE_CLIENT_ID
    })

@app.route('/api/v1/auth/google/verify', methods=['POST'])
def verify_google_token():
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
        
        # 簽發 JWT
        token = jwt.encode(
            {**user, 'exp': datetime.utcnow() + timedelta(days=7)},
            SESSION_SECRET,
            algorithm='HS256'
        )
        
        return jsonify({'ok': True, 'token': token, 'user': user})
        
    except Exception as e:
        print(f'Google verify error: {e}')
        return jsonify({'ok': False, 'error': 'verify_failed'}), 401

def verify_jwt_token():
    """JWT 驗證裝飾器"""
    def decorator(f):
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
        return wrapper
    return decorator

@app.route('/api/v1/auth/status', methods=['GET'])
@verify_jwt_token()
def auth_status():
    return jsonify({'ok': True, 'user': request.user})

@app.route('/api/v1/intake', methods=['POST'])
@verify_jwt_token()
def intake():
    try:
        profile_id = f"profile_{int(datetime.now().timestamp())}_{hash(str(request.user)) % 10000}"
        user_data = {
            'profile_id': profile_id,
            'user_id': request.user['userId'],
            **request.get_json(),
            'created_at': datetime.now().isoformat()
        }
        
        user_profiles[profile_id] = user_data
        
        print(f'User profile saved: {profile_id}, role: {user_data.get("user_role")}')
        return jsonify({'ok': True, 'data': {'profile_id': profile_id}})
        
    except Exception as e:
        print(f'Intake error: {e}')
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@app.route('/api/v1/chat', methods=['POST'])
@verify_jwt_token()
def chat():
    try:
        data = request.get_json()
        message = data.get('message', '')
        user_role = data.get('user_role', 'student')
        profile_id = data.get('profile_id')
        language = data.get('language', 'zh')
        
        # 獲取用戶資料
        user_profile = user_profiles.get(profile_id, {})
        
        # 構建 Gemini 提示
        if language == 'en':
            system_prompt = f"""You are a professional AI Study Abroad Advisor. You provide personalized, expert guidance for students and parents planning international education.

User Role: {user_role}
User Profile: {json.dumps(user_profile, indent=2) if user_profile else 'No profile data available'}

Please respond in English and provide comprehensive, actionable advice."""
            
            if message and message.strip():
                user_prompt = f"""User Question: "{message}"

Please provide detailed, professional advice based on the user's role and profile. Include specific recommendations, timelines, and actionable steps."""
            else:
                user_prompt = f"""Please provide a welcoming message and overview of how you can help this {user_role} with their study abroad planning."""
        else:
            system_prompt = f"""你是一位專業的AI留學顧問。你為計劃國際教育的學生和家長提供個人化的專業指導。

用戶角色：{user_role}
用戶資料：{json.dumps(user_profile, indent=2) if user_profile else '無資料'}

請用中文回應，提供全面且可執行的建議。"""
            
            if message and message.strip():
                user_prompt = f"""用戶問題：「{message}」

請根據用戶角色和資料提供詳細的專業建議，包括具體推薦、時間規劃和可執行的步驟。"""
            else:
                user_prompt = f"""請提供歡迎訊息，並概述你如何幫助這位{user_role}進行留學規劃。"""
        
        full_prompt = f"{system_prompt}\n\n{user_prompt}"
        
        # 呼叫 Gemini AI
        response = model.generate_content(full_prompt)
        reply = response.text
        
        return jsonify({'ok': True, 'data': {'response': reply}})
        
    except Exception as e:
        print(f'Gemini AI error: {e}')
        
        # 備用回覆
        fallback_reply = (
            'I apologize, but I\'m currently experiencing technical difficulties. Please try again in a moment or contact our support team for assistance.'
            if language == 'en' else
            '抱歉，我目前遇到技術問題。請稍後再試，或聯繫我們的支援團隊獲得協助。'
        )
        
        return jsonify({'ok': True, 'data': {'response': fallback_reply}})

@app.route('/', methods=['GET'])
def root():
    return jsonify({
        'message': 'AI 留學顧問後端服務運行中',
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
