import socket
import json
import base64
import uuid

def load_user_credentials():
    """加载用户凭证"""
    with open('users.json', 'r') as file:
        return json.load(file)


class HttpServer:
    def __init__(self, host, port, user_credentials):
        self.host = host
        self.port = port
        self.user_credentials = user_credentials
        self.active_sessions = {}# 保存会话ID与用户名的映射关系

    def parse_request(self, request):
        """解析HTTP请求"""
        headers, body = request.split('\r\n\r\n', 1)
        request_line, headers = headers.split('\r\n', 1)
        method, path, _ = request_line.split(' ')
        headers = dict(line.split(': ') for line in headers.split('\r\n'))
        return method, path, headers, body

    def send_response(self, client_socket, status_code, body='', headers=None):
        """发送HTTP响应"""
        if headers is None:
            headers = {}
        headers.setdefault('Content-Type', 'text/plain')
        headers_lines = [f'{key}: {value}' for key, value in headers.items()]
        headers_section = '\r\n'.join(headers_lines)
        response = f'HTTP/1.1 {status_code}\r\n{headers_section}\r\n\r\n{body}'
        client_socket.send(response.encode())
    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        print(f'Listening at {self.host}:{self.port}')
        try:
            while True:
                client_socket, addr = server.accept()
                print(f'Accepted connection from {addr}')
                # 用户认证
                try:
                    while True:
                        # 首先解析请求
                        request = client_socket.recv(1024).decode()
                        print("wait parse request",request)
                        method, path, headers, body = self.parse_request(request)
                        print("receive the first request",method,":",path,":",headers,":",body)
                        # 检查授权状态
                        if not self.check_authorization(headers):
                            print("Enter:no cokkies")
                            # 如果未授权，则尝试进行用户认证
                            self.send_response(client_socket, '401 Unauthorized',
                                               headers={"WWW-Authenticate": 'Basic realm="Authorization Required"'})
                            # 再次解析请求
                            print("wait the second request")
                            request = client_socket.recv(1024).decode()
                            print("wait parse request", request)
                            method, path, headers, body = self.parse_request(request)
                            print("receive the second request",headers,":",body)
                            if not self.authenticate_user(client_socket, headers, path):
                                print("Enter 授权失败")
                                continue  # 继续监听下一个请求
                        # else:
                            # 授权成功，处理客户端请求
                            # self.handle_client_connection(client_socket, request)
                finally:
                    client_socket.close()
                    print(f'{addr} Connection closed')
        finally:
            server.close()

    def check_authorization(self,headers):
        # 检查是否存在Cookie头
        cookie = headers.get('Cookie')
        if cookie and "session_id" in cookie:
            session_id = cookie.split('session_id=')[1]
            if session_id in self.active_sessions:
                return True
        return False

    def authenticate_user(self, client_socket, headers, path):
        """用户认证"""
        if path != '/authenticate':
            self.send_response(client_socket, '401 Unauthorized', 'Invalid authentication path')
            return False

        auth_header = headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            self.send_response(client_socket, '401 Unauthorized', 'Invalid authentication header')
            return False

        encoded_credentials = auth_header.split(' ')[1]
        decoded_credentials = base64.b64decode(encoded_credentials).decode()
        username, password = decoded_credentials.split(':')

        if username in self.user_credentials and self.user_credentials[username] == password:
            session_id =uuid.uuid4()# 生成会话ID
            self.active_sessions[session_id] = username# 将会话ID与用户名关联
            self.send_response(client_socket, '200 OK',headers={'Set-Cookie': f'session_id={session_id}'})
            return True
        else:
            self.send_response(client_socket, '401 Unauthorized', 'Invalid username or password')
            return False

    def handle_client_connection(self,client_socket):
        """处理客户端连接"""
        try:
            while True:
                request = client_socket.recv(1024).decode()
                if not request:
                    break
                method, path, headers, body = self.parse_request(request)

                if method == 'POST' and path.startswith('/upload/'):
                    filename = path.split('/')[-1]
                    with open(filename, 'wb') as file:
                        file.write(body.encode())  # 保存文件内容
                    self.send_response(client_socket, '200 OK', 'File uploaded successfully')
                    continue

                if method == 'GET':
                    response_body = 'This is a response to a GET request.'
                    self.send_response(client_socket, '200 OK', response_body)
                    continue

        finally:
            client_socket.close()

# 服务器监听地址和端口
HOST, PORT = 'localhost', 8000
user_credentials = load_user_credentials()
server = HttpServer(HOST, PORT, user_credentials)
server.start()
