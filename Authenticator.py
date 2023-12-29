import base64
import time
import uuid


def generate_session_id():
    return str(uuid.uuid4())


class Authenticator:
    """
    负责会话管理和用户认证，会话管理使用字典存储会话ID和用户名的映射关系，用户认证检查用户名和密码是否正确。
    """

    def __init__(self, user_credentials, sessions, session_expiry):
        self.user_credentials = user_credentials
        self.sessions = sessions
        self.session_expiry = session_expiry

    def handle_session(self, headers):
        """会话管理，先检查会话ID是否存在，如果不存在则检查认证信息。"""
        response = {'session_id': None, 'status': None, 'headers': {}}

        cookie = headers.get('Cookie')
        if cookie:
            session_id = cookie.split('=')[1]
            if session_id in self.sessions and self.session_expiry[session_id] > time.time():
                # 更新会话过期时间，不需要返回session_id
                self.session_expiry[session_id] = time.time() + 3600
            else:
                response['status'] = '401 Unauthorized'
                if session_id not in self.sessions:
                    # 无效的会话ID
                    response['body'] = 'Invalid session ID'
                else:
                    # 会话过期
                    del self.sessions[session_id]
                    del self.session_expiry[session_id]
                    response['body'] = 'Session expired'
        elif 'Authorization' in headers:
            session_id, message = self.authenticate_user(headers)
            response['session_id'] = session_id
            if not session_id:
                response['status'] = '401 Unauthorized'
                response['body'] = message
        else:
            # 没有提供认证信息
            response['status'] = '401 Unauthorized'
            response['body'] = 'Authentication required'
            response['headers'] = {'WWW-Authenticate': 'Basic realm="Authorization Required"'}

        return response

    def authenticate_user(self, headers):
        """用户认证，检查用户名和密码是否正确。"""
        auth_header = headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            return None, 'Invalid authentication header'

        encoded_credentials = auth_header.split(' ')[1]
        decoded_credentials = base64.b64decode(encoded_credentials).decode()
        username, password = decoded_credentials.split(':')
        print(username, password)

        if username in self.user_credentials and self.user_credentials[username] == password:
            # 认证成功，生成会话ID
            session_id = generate_session_id()
            self.sessions[session_id] = username
            self.session_expiry[session_id] = time.time() + 3600  # 假设会话有效期为1小时
            return session_id, None
        else:
            return None, 'Invalid username or password'
