# -*- coding: utf-8 -*-
import sqlite3
import os
from datetime import datetime
import json

class DatabaseManager:
    def __init__(self, db_path='ai_study_advisor.db'):
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
        
        conn.commit()
        conn.close()
        print('Database initialized successfully')
    
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
    
    def export_user_data(self, user_id=None):
        """匯出用戶資料"""
        data = {
            'users': self.get_all_users() if not user_id else [u for u in self.get_all_users() if u['user_id'] == user_id],
            'profiles': self.get_user_profiles(user_id),
            'messages': self.get_chat_messages(limit=1000),
            'stats': self.get_usage_stats(days=90),
            'export_time': datetime.now().isoformat()
        }
        return data
