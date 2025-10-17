# -*- coding: utf-8 -*-
import requests
import json
import logging
import os

logger = logging.getLogger(__name__)

class DatabaseClient:
    """資料庫服務客戶端"""
    
    def __init__(self, base_url=None):
        # 預設使用 Zeabur 部署的資料庫服務 URL
        self.base_url = base_url or os.getenv('DATABASE_SERVICE_URL', 'https://ai-study-advisor-database.zeabur.app')
        self.session = requests.Session()
        
    def _make_request(self, method, endpoint, data=None, params=None):
        """發送 HTTP 請求到資料庫服務"""
        try:
            url = f"{self.base_url}{endpoint}"
            headers = {'Content-Type': 'application/json'}
            
            if method == 'GET':
                response = self.session.get(url, params=params, headers=headers)
            elif method == 'POST':
                response = self.session.post(url, json=data, headers=headers)
            elif method == 'PUT':
                response = self.session.put(url, json=data, headers=headers)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Database service request failed: {e}")
            return {'ok': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Unexpected error in database request: {e}")
            return {'ok': False, 'error': str(e)}
    
    def health_check(self):
        """檢查資料庫服務健康狀態"""
        return self._make_request('GET', '/health')
    
    def save_user(self, user_data):
        """儲存用戶資料"""
        return self._make_request('POST', '/api/users', data=user_data)
    
    def get_all_users(self):
        """獲取所有用戶資料"""
        return self._make_request('GET', '/api/users')
    
    def get_user(self, user_id):
        """獲取用戶資料"""
        return self._make_request('GET', f'/api/users/{user_id}')
    
    def get_user_profiles(self, user_id):
        """獲取用戶的設定資料"""
        return self._make_request('GET', f'/api/users/{user_id}/profiles')
    
    def save_user_profile(self, profile_data):
        """儲存用戶設定資料"""
        return self._make_request('POST', '/api/profiles', data=profile_data)
    
    def get_user_profile(self, profile_id):
        """獲取設定資料"""
        return self._make_request('GET', f'/api/profiles/{profile_id}')
    
    def update_user_profile(self, profile_id, data):
        """更新設定資料"""
        return self._make_request('PUT', f'/api/profiles/{profile_id}', data=data)
    
    def save_chat_message(self, message_data):
        """儲存聊天記錄"""
        return self._make_request('POST', '/api/messages', data=message_data)
    
    def get_chat_messages(self, profile_id, limit=100):
        """獲取聊天記錄"""
        return self._make_request('GET', f'/api/messages/{profile_id}', params={'limit': limit})
    
    def save_usage_stat(self, stat_data):
        """儲存使用統計"""
        return self._make_request('POST', '/api/stats', data=stat_data)
    
    def get_usage_stats(self, days=30):
        """獲取使用統計"""
        return self._make_request('GET', '/api/stats', params={'days': days})
    
    def create_backup(self):
        """創建資料庫備份"""
        return self._make_request('POST', '/api/backup')
    
    # 向後相容的方法
    def get_user_by_provider_id(self, provider, provider_id):
        """根據提供者和提供者ID獲取用戶"""
        return self.get_user(provider_id)
    
    def update_user(self, user_id, user_data):
        """更新用戶資料"""
        # 資料庫服務目前沒有直接的更新用戶 API，這裡可以擴展
        logger.warning("Update user method not implemented in database service")
        return {'ok': False, 'error': 'Method not implemented'}
    
    def get_user_by_id(self, user_id):
        """根據用戶ID獲取用戶"""
        return self.get_user(user_id)
