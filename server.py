import socket
import json
import base64
import uuid


def load_user_credentials():
    """加载用户凭证"""
    with open('users.json', 'r') as file:
        return json.load(file)


def send_response(client_socket, status_code, body='', headers=None):
    """发送HTTP响应"""
    if headers is None:
        headers = {}
    headers.setdefault('Content-Type', 'text/plain')
    headers_lines = [f'{key}: {value}' for key, value in headers.items()]
    headers_section = '\r\n'.join(headers_lines)
    response = f'HTTP/1.1 {status_code}\r\n{headers_section}\r\n\r\n{body}'
    client_socket.send(response.encode())


def parse_request(request):
    """解析HTTP请求"""
    headers, body = request.split('\r\n\r\n', 1)
    request_line, headers = headers.split('\r\n', 1)
    method, path, _ = request_line.split(' ')
    headers = dict(line.split(': ') for line in headers.split('\r\n'))
    return method, path, headers, body


# def handle_client_connection(client_socket, method, path, headers, body):
#     """处理客户端连接"""
#     try:
#         while True:
#             if not request:
#                 break
#             method, path, headers, body = parse_request(request)
#
#             if method == 'POST' and path.startswith('/upload/'):
#                 filename = path.split('/')[-1]
#                 with open(filename, 'wb') as file:
#                     file.write(body.encode())  # 保存文件内容
#                 send_response(client_socket, '200 OK', 'File uploaded successfully')
#                 continue
#
#             if method == 'GET':
#                 response_body = 'This is a response to a GET request.'
#                 send_response(client_socket, '200 OK', response_body)
#                 continue
#
#     finally:
#         client_socket.close()


class HttpServer:
    def __init__(self, host, port, user_credentials):
        self.host = host
        self.port = port
        self.user_credentials = user_credentials
        self.active_sessions = {}  # 保存会话ID与用户名的映射关系

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
                try:
                    while True:
                        request = client_socket.recv(1024).decode()
                        method, path, headers, body = parse_request(request)

                        # 判断是否有Authorization头
                        if not self.authenticate_user(client_socket, headers, path):
                            print("Enter 授权失败")
                            continue  # 继续监听下一个请求
                        else:
                            print("Enter 授权成功")
                            # handle_client_connection(client_socket,method, path, headers, body)
                finally:
                    client_socket.close()
                    print(f'{addr} Connection closed')
        finally:
            server.close()

    def authenticate_user(self, client_socket, headers, path):
        """用户认证"""
        if path != '/authenticate':
            send_response(client_socket, '401 Unauthorized',
                          headers={"WWW-Authenticate": 'Basic realm="Authorization Required"'},
                          body='Invalid authentication path')
            return False

        auth_header = headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            send_response(client_socket, '401 Unauthorized',
                          headers={"WWW-Authenticate": 'Basic realm="Authorization Required"'},
                          body='Invalid authentication header')
            return False

        encoded_credentials = auth_header.split(' ')[1]
        decoded_credentials = base64.b64decode(encoded_credentials).decode()
        username, password = decoded_credentials.split(':')

        if username in self.user_credentials and self.user_credentials[username] == password:
            send_response(client_socket, '200 OK', body='Authentication successful')
            return True
        else:
            send_response(client_socket, '401 Unauthorized',
                          headers={"WWW-Authenticate": 'Basic realm="Authorization Required"'},
                          body='Invalid username or password')
            return False


# 服务器监听地址和端口
HOST, PORT = 'localhost', 8000
user_credentials = load_user_credentials()
server = HttpServer(HOST, PORT, user_credentials)
server.start()
