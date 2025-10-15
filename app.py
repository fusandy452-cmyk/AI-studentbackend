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

app = Flask(__name__)
CORS(app, origins=["https://aistudent.zeabur.app"])

# 環境變數
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY') or os.getenv('GOOGLE_API_KEY')
GEMINI_MODEL = os.getenv('GEMINI_MODEL', 'gemini-2.5-flash')
SESSION_SECRET = os.getenv('SESSION_SECRET', 'dev-secret')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')

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
        print('Google verify error: {}'.format(e))
        return jsonify({'ok': False, 'error': 'verify_failed'}), 401

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
            'usage_stats': stats
        }
        
        return jsonify({'ok': True, 'data': dashboard_data})
    except Exception as e:
        print('Admin dashboard error: {}'.format(e))
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

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
