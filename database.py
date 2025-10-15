# -*- coding: utf-8 -*-
import sqlite3
import os
from datetime import datetime
import json

class DatabaseManager:
    def __init__(self, db_path=None):
        # 使用環境變數或預設路徑
        if db_path is None:
            import os
            # 優先使用 Zeabur 持久化目錄
            persistent_dir = os.getenv('ZEABUR_PERSISTENT_DIR', '/data')
            # 如果沒有持久化目錄，使用 /tmp 但會定期備份
            if not os.path.exists(persistent_dir):
                persistent_dir = '/tmp'
                print('Warning: Using /tmp directory, data may be lost on restart')
            # 確保目錄存在
            os.makedirs(persistent_dir, exist_ok=True)
            self.db_path = os.path.join(persistent_dir, 'ai_study_advisor.db')
        else:
            self.db_path = db_path
        self.init_database()
    
    def get_connection(self):
        """獲取資料庫連接"""
        return sqlite3.connect(self.db_path)
    
    def init_database(self):
        """初始化資料庫和表格"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # 用戶資料表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT UNIQUE NOT NULL,
                email TEXT,
                name TEXT,
                avatar TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 用戶設定資料表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT UNIQUE NOT NULL,
                user_id TEXT NOT NULL,
                user_role TEXT NOT NULL,
                student_name TEXT,
                student_email TEXT,
                parent_name TEXT,
                parent_email TEXT,
                relationship TEXT,
                child_name TEXT,
                child_email TEXT,
                citizenship TEXT,
                gpa REAL,
                degree TEXT,
                countries TEXT,
                budget INTEGER,
                target_intake TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        # 聊天記錄表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                message_type TEXT NOT NULL,
                message_content TEXT NOT NULL,
                language TEXT DEFAULT 'zh',
                user_role TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (profile_id) REFERENCES user_profiles (profile_id),
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        # 使用統計表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usage_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                profile_id TEXT,
                action_type TEXT NOT NULL,
                action_details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (user_id),
                FOREIGN KEY (profile_id) REFERENCES user_profiles (profile_id)
            )
        ''')
        
        # 留學進度追蹤表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS study_progress (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                progress_category TEXT NOT NULL,
                progress_item TEXT NOT NULL,
                status TEXT NOT NULL,
                completion_percentage INTEGER DEFAULT 0,
                notes TEXT,
                target_date DATE,
                completed_date DATE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (profile_id) REFERENCES user_profiles (profile_id),
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        # 聊天摘要表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chat_summaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                summary_period TEXT NOT NULL,
                summary_content TEXT NOT NULL,
                key_topics TEXT,
                action_items TEXT,
                advisor_notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (profile_id) REFERENCES user_profiles (profile_id),
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        # 建立管理員表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL DEFAULT 'advisor',
                permissions TEXT NOT NULL DEFAULT 'read_only',
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                created_by TEXT
            )
        ''')
        
        # 建立管理員會話表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_sessions (
                session_id TEXT PRIMARY KEY,
                admin_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (admin_id) REFERENCES admins (admin_id)
            )
        ''')
        
        conn.commit()
        conn.close()
        print('Database initialized successfully at: {}'.format(self.db_path))
    
    def save_user(self, user_data):
        """儲存用戶資料"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO users (user_id, email, name, avatar, updated_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                user_data['userId'],
                user_data.get('email'),
                user_data.get('name'),
                user_data.get('avatar'),
                datetime.now().isoformat()
            ))
            conn.commit()
            return True
        except Exception as e:
            print('Error saving user: {}'.format(e))
            return False
        finally:
            conn.close()
    
    def save_user_profile(self, profile_data):
        """儲存用戶設定資料"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            # 將 countries 列表轉換為 JSON 字串
            countries_json = json.dumps(profile_data.get('countries', []))
            
            cursor.execute('''
                INSERT OR REPLACE INTO user_profiles (
                    profile_id, user_id, user_role, student_name, student_email,
                    parent_name, parent_email, relationship, child_name, child_email,
                    citizenship, gpa, degree, countries, budget, target_intake, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                profile_data['profile_id'],
                profile_data['user_id'],
                profile_data.get('user_role'),
                profile_data.get('student_name'),
                profile_data.get('student_email'),
                profile_data.get('parent_name'),
                profile_data.get('parent_email'),
                profile_data.get('relationship'),
                profile_data.get('child_name'),
                profile_data.get('child_email'),
                profile_data.get('citizenship'),
                profile_data.get('gpa'),
                profile_data.get('degree'),
                countries_json,
                profile_data.get('budget'),
                profile_data.get('target_intake'),
                datetime.now().isoformat()
            ))
            conn.commit()
            return True
        except Exception as e:
            print('Error saving user profile: {}'.format(e))
            return False
        finally:
            conn.close()
    
    def save_chat_message(self, message_data):
        """儲存聊天記錄"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO chat_messages (
                    profile_id, user_id, message_type, message_content, language, user_role
                ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                message_data.get('profile_id'),
                message_data.get('user_id'),
                message_data.get('message_type'),  # 'user' or 'ai'
                message_data.get('message_content'),
                message_data.get('language', 'zh'),
                message_data.get('user_role')
            ))
            conn.commit()
            return True
        except Exception as e:
            print('Error saving chat message: {}'.format(e))
            return False
        finally:
            conn.close()
    
    def save_usage_stat(self, stat_data):
        """儲存使用統計"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            action_details = json.dumps(stat_data.get('action_details', {}))
            cursor.execute('''
                INSERT INTO usage_stats (user_id, profile_id, action_type, action_details)
                VALUES (?, ?, ?, ?)
            ''', (
                stat_data.get('user_id'),
                stat_data.get('profile_id'),
                stat_data.get('action_type'),
                action_details
            ))
            conn.commit()
            return True
        except Exception as e:
            print('Error saving usage stat: {}'.format(e))
            return False
        finally:
            conn.close()
    
    def get_all_users(self):
        """獲取所有用戶資料"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT u.*, COUNT(up.id) as profile_count, COUNT(cm.id) as message_count
            FROM users u
            LEFT JOIN user_profiles up ON u.user_id = up.user_id
            LEFT JOIN chat_messages cm ON u.user_id = cm.user_id
            GROUP BY u.id
            ORDER BY u.created_at DESC
        ''')
        
        users = []
        for row in cursor.fetchall():
            users.append({
                'id': row[0],
                'user_id': row[1],
                'email': row[2],
                'name': row[3],
                'avatar': row[4],
                'created_at': row[5],
                'updated_at': row[6],
                'profile_count': row[7],
                'message_count': row[8]
            })
        
        conn.close()
        return users
    
    def get_user_profiles(self, user_id=None):
        """獲取用戶設定資料"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if user_id:
            cursor.execute('''
                SELECT * FROM user_profiles WHERE user_id = ?
                ORDER BY created_at DESC
            ''', (user_id,))
        else:
            cursor.execute('''
                SELECT * FROM user_profiles ORDER BY created_at DESC
            ''')
        
        profiles = []
        for row in cursor.fetchall():
            countries = json.loads(row[13]) if row[13] else []
            profiles.append({
                'id': row[0],
                'profile_id': row[1],
                'user_id': row[2],
                'user_role': row[3],
                'student_name': row[4],
                'student_email': row[5],
                'parent_name': row[6],
                'parent_email': row[7],
                'relationship': row[8],
                'child_name': row[9],
                'child_email': row[10],
                'citizenship': row[11],
                'gpa': row[12],
                'degree': row[13],
                'countries': countries,
                'budget': row[15],
                'target_intake': row[16],
                'created_at': row[17],
                'updated_at': row[18]
            })
        
        conn.close()
        return profiles
    
    def get_chat_messages(self, profile_id=None, limit=100):
        """獲取聊天記錄"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if profile_id:
            cursor.execute('''
                SELECT * FROM chat_messages WHERE profile_id = ?
                ORDER BY created_at DESC LIMIT ?
            ''', (profile_id, limit))
        else:
            cursor.execute('''
                SELECT * FROM chat_messages ORDER BY created_at DESC LIMIT ?
            ''', (limit,))
        
        messages = []
        for row in cursor.fetchall():
            messages.append({
                'id': row[0],
                'profile_id': row[1],
                'user_id': row[2],
                'message_type': row[3],
                'message_content': row[4],
                'language': row[5],
                'user_role': row[6],
                'created_at': row[7]
            })
        
        conn.close()
        return messages
    
    def get_usage_stats(self, days=30):
        """獲取使用統計"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                DATE(created_at) as date,
                action_type,
                COUNT(*) as count
            FROM usage_stats 
            WHERE created_at >= datetime('now', '-{} days')
            GROUP BY DATE(created_at), action_type
            ORDER BY date DESC
        '''.format(days))
        
        stats = []
        for row in cursor.fetchall():
            stats.append({
                'date': row[0],
                'action_type': row[1],
                'count': row[2]
            })
        
        conn.close()
        return stats
    
    def save_study_progress(self, progress_data):
        """儲存留學進度"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO study_progress (
                    profile_id, user_id, progress_category, progress_item,
                    status, completion_percentage, notes, target_date, completed_date, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                progress_data.get('profile_id'),
                progress_data.get('user_id'),
                progress_data.get('progress_category'),
                progress_data.get('progress_item'),
                progress_data.get('status'),
                progress_data.get('completion_percentage', 0),
                progress_data.get('notes'),
                progress_data.get('target_date'),
                progress_data.get('completed_date'),
                datetime.now().isoformat()
            ))
            conn.commit()
            return True
        except Exception as e:
            print('Error saving study progress: {}'.format(e))
            return False
        finally:
            conn.close()
    
    def get_study_progress(self, profile_id=None):
        """獲取留學進度"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if profile_id:
            cursor.execute('''
                SELECT * FROM study_progress WHERE profile_id = ?
                ORDER BY created_at DESC
            ''', (profile_id,))
        else:
            cursor.execute('''
                SELECT * FROM study_progress ORDER BY created_at DESC
            ''')
        
        progress = []
        for row in cursor.fetchall():
            progress.append({
                'id': row[0],
                'profile_id': row[1],
                'user_id': row[2],
                'progress_category': row[3],
                'progress_item': row[4],
                'status': row[5],
                'completion_percentage': row[6],
                'notes': row[7],
                'target_date': row[8],
                'completed_date': row[9],
                'created_at': row[10],
                'updated_at': row[11]
            })
        
        conn.close()
        return progress
    
    def save_chat_summary(self, summary_data):
        """儲存聊天摘要"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO chat_summaries (
                    profile_id, user_id, summary_period, summary_content,
                    key_topics, action_items, advisor_notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                summary_data.get('profile_id'),
                summary_data.get('user_id'),
                summary_data.get('summary_period'),
                summary_data.get('summary_content'),
                summary_data.get('key_topics'),
                summary_data.get('action_items'),
                summary_data.get('advisor_notes')
            ))
            conn.commit()
            return True
        except Exception as e:
            print('Error saving chat summary: {}'.format(e))
            return False
        finally:
            conn.close()
    
    def get_chat_summaries(self, profile_id=None):
        """獲取聊天摘要"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if profile_id:
            cursor.execute('''
                SELECT * FROM chat_summaries WHERE profile_id = ?
                ORDER BY created_at DESC
            ''', (profile_id,))
        else:
            cursor.execute('''
                SELECT * FROM chat_summaries ORDER BY created_at DESC
            ''')
        
        summaries = []
        for row in cursor.fetchall():
            summaries.append({
                'id': row[0],
                'profile_id': row[1],
                'user_id': row[2],
                'summary_period': row[3],
                'summary_content': row[4],
                'key_topics': row[5],
                'action_items': row[6],
                'advisor_notes': row[7],
                'created_at': row[8]
            })
        
        conn.close()
        return summaries
    
    def get_user_role_summary(self):
        """獲取用戶角色摘要"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                up.user_role,
                COUNT(*) as count,
                AVG(up.budget) as avg_budget,
                GROUP_CONCAT(DISTINCT up.citizenship) as countries,
                MAX(up.created_at) as latest_activity
            FROM user_profiles up
            GROUP BY up.user_role
        ''')
        
        summary = []
        for row in cursor.fetchall():
            summary.append({
                'role': row[0],
                'count': row[1],
                'avg_budget': row[2],
                'countries': row[3].split(',') if row[3] else [],
                'latest_activity': row[4]
            })
        
        conn.close()
        return summary
    
    def get_users_count(self):
        """獲取用戶總數"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM users')
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def get_profiles_count(self):
        """獲取用戶設定總數"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM user_profiles')
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def get_messages_count(self):
        """獲取聊天訊息總數"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM chat_messages')
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def export_user_data(self, user_id=None):
        """匯出用戶資料"""
        data = {
            'users': self.get_all_users() if not user_id else [u for u in self.get_all_users() if u['user_id'] == user_id],
            'profiles': self.get_user_profiles(user_id),
            'messages': self.get_chat_messages(limit=1000),
            'stats': self.get_usage_stats(days=90),
            'study_progress': self.get_study_progress(),
            'chat_summaries': self.get_chat_summaries(),
            'role_summary': self.get_user_role_summary(),
            'export_time': datetime.now().isoformat()
        }
        return data
    
    # 管理員相關方法
    def create_admin(self, username, password_hash, email, role='advisor', permissions='read_only', created_by=None):
        """建立管理員帳號"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO admins (username, password_hash, email, role, permissions, created_by)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, password_hash, email, role, permissions, created_by))
            
            conn.commit()
            return True
        except Exception as e:
            print('Create admin error: {}'.format(e))
            return False
        finally:
            conn.close()
    
    def get_admin_by_username(self, username):
        """根據用戶名獲取管理員"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM admins WHERE username = ? AND is_active = 1', (username,))
        result = cursor.fetchone()
        
        conn.close()
        
        if result:
            return {
                'admin_id': result[0],
                'username': result[1],
                'password_hash': result[2],
                'email': result[3],
                'role': result[4],
                'permissions': result[5],
                'is_active': result[6],
                'created_at': result[7],
                'last_login': result[8],
                'created_by': result[9]
            }
        return None
    
    def get_admin_by_id(self, admin_id):
        """根據ID獲取管理員"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM admins WHERE admin_id = ? AND is_active = 1', (admin_id,))
        result = cursor.fetchone()
        
        conn.close()
        
        if result:
            return {
                'admin_id': result[0],
                'username': result[1],
                'password_hash': result[2],
                'email': result[3],
                'role': result[4],
                'permissions': result[5],
                'is_active': result[6],
                'created_at': result[7],
                'last_login': result[8],
                'created_by': result[9]
            }
        return None
    
    def get_all_admins(self):
        """獲取所有管理員"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM admins WHERE is_active = 1 ORDER BY created_at DESC')
        results = cursor.fetchall()
        
        conn.close()
        
        admins = []
        for result in results:
            admins.append({
                'admin_id': result[0],
                'username': result[1],
                'email': result[3],
                'role': result[4],
                'permissions': result[5],
                'is_active': result[6],
                'created_at': result[7],
                'last_login': result[8],
                'created_by': result[9]
            })
        
        return admins
    
    def update_admin_login(self, admin_id, ip_address=None):
        """更新管理員最後登入時間"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE admins SET last_login = CURRENT_TIMESTAMP 
            WHERE admin_id = ?
        ''', (admin_id,))
        
        conn.commit()
        conn.close()
        return True
    
    def create_admin_session(self, session_id, admin_id, expires_at, ip_address=None, user_agent=None):
        """建立管理員會話"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO admin_sessions (session_id, admin_id, expires_at, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?)
            ''', (session_id, admin_id, expires_at, ip_address, user_agent))
            
            conn.commit()
            return True
        except Exception as e:
            print('Create admin session error: {}'.format(e))
            return False
        finally:
            conn.close()
    
    def get_admin_session(self, session_id):
        """獲取管理員會話"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT s.*, a.username, a.role, a.permissions 
            FROM admin_sessions s
            JOIN admins a ON s.admin_id = a.admin_id
            WHERE s.session_id = ? AND s.expires_at > CURRENT_TIMESTAMP AND a.is_active = 1
        ''', (session_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'session_id': result[0],
                'admin_id': result[1],
                'created_at': result[2],
                'expires_at': result[3],
                'ip_address': result[4],
                'user_agent': result[5],
                'username': result[6],
                'role': result[7],
                'permissions': result[8]
            }
        return None
    
    def delete_admin_session(self, session_id):
        """刪除管理員會話"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM admin_sessions WHERE session_id = ?', (session_id,))
        conn.commit()
        conn.close()
        return True
    
    def update_admin_permissions(self, admin_id, permissions):
        """更新管理員權限"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE admins SET permissions = ? WHERE admin_id = ?
        ''', (permissions, admin_id))
        
        conn.commit()
        conn.close()
        return True
    
    def export_all_data(self):
        """匯出所有資料"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # 獲取所有資料
            users = self.get_all_users()
            profiles = self.get_user_profiles()
            messages = self.get_chat_messages(limit=10000)
            usage_stats = self.get_usage_stats(limit=10000)
            admins = self.get_all_admins()
            
            # 獲取資料庫結構
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            export_data = {
                'export_time': datetime.now().isoformat(),
                'database_version': '1.0',
                'tables': tables,
                'data': {
                    'users': users,
                    'profiles': profiles,
                    'messages': messages,
                    'usage_stats': usage_stats,
                    'admins': admins
                },
                'counts': {
                    'users': len(users),
                    'profiles': len(profiles),
                    'messages': len(messages),
                    'usage_stats': len(usage_stats),
                    'admins': len(admins)
                }
            }
            
            conn.close()
            return export_data
            
        except Exception as e:
            print('Export data error: {}'.format(e))
            return None
    
    def import_data(self, import_data):
        """匯入資料"""
        try:
            if not import_data or 'data' not in import_data:
                return False
            
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # 匯入用戶資料
            if 'users' in import_data['data']:
                for user in import_data['data']['users']:
                    try:
                        cursor.execute('''
                            INSERT OR REPLACE INTO users 
                            (user_id, email, name, picture, provider, created_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            user.get('user_id'),
                            user.get('email'),
                            user.get('name'),
                            user.get('picture'),
                            user.get('provider'),
                            user.get('created_at')
                        ))
                    except Exception as e:
                        print('Import user error: {}'.format(e))
            
            # 匯入用戶檔案
            if 'profiles' in import_data['data']:
                for profile in import_data['data']['profiles']:
                    try:
                        cursor.execute('''
                            INSERT OR REPLACE INTO user_profiles 
                            (profile_id, user_id, user_role, target_country, target_major, 
                             current_education_level, target_degree, budget, citizenship, 
                             target_intake_time, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            profile.get('profile_id'),
                            profile.get('user_id'),
                            profile.get('user_role'),
                            profile.get('target_country'),
                            profile.get('target_major'),
                            profile.get('current_education_level'),
                            profile.get('target_degree'),
                            profile.get('budget'),
                            profile.get('citizenship'),
                            profile.get('target_intake_time'),
                            profile.get('created_at')
                        ))
                    except Exception as e:
                        print('Import profile error: {}'.format(e))
            
            # 匯入聊天記錄
            if 'messages' in import_data['data']:
                for message in import_data['data']['messages']:
                    try:
                        cursor.execute('''
                            INSERT OR REPLACE INTO chat_messages 
                            (message_id, user_id, message_text, message_type, created_at)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (
                            message.get('message_id'),
                            message.get('user_id'),
                            message.get('message_text'),
                            message.get('message_type'),
                            message.get('created_at')
                        ))
                    except Exception as e:
                        print('Import message error: {}'.format(e))
            
            # 匯入管理員資料
            if 'admins' in import_data['data']:
                for admin in import_data['data']['admins']:
                    try:
                        cursor.execute('''
                            INSERT OR REPLACE INTO admins 
                            (admin_id, username, password_hash, email, role, permissions, 
                             is_active, created_at, last_login, created_by)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            admin.get('admin_id'),
                            admin.get('username'),
                            admin.get('password_hash'),
                            admin.get('email'),
                            admin.get('role'),
                            admin.get('permissions'),
                            admin.get('is_active'),
                            admin.get('created_at'),
                            admin.get('last_login'),
                            admin.get('created_by')
                        ))
                    except Exception as e:
                        print('Import admin error: {}'.format(e))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print('Import data error: {}'.format(e))
            return False
