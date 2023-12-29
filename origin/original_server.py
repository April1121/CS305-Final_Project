import mimetypes
import os
import socket
import json
import base64
import threading
import time
import uuid


def generate_session_id():
    """使用uuid生成唯一的会话ID"""
    return str(uuid.uuid4())


def load_user_credentials():
    """加载用户凭证"""
    with open('../users.json', 'r') as file:
        return json.load(file)


def parse_request(request):
    """解析HTTP请求"""
    headers, body = request.split('\r\n\r\n', 1)
    request_line, headers = headers.split('\r\n', 1)
    method, path, _ = request_line.split(' ')
    headers = dict(line.split(': ') for line in headers.split('\r\n'))
    return method, path, headers, body


def parse_multipart_form_data(body, boundary):
    """解析multipart/form-data格式的数据。

    Args:
        body (str): 请求体的内容。
        boundary (str): 分隔符。

    Returns:
        tuple: 包含文件名和文件数据的元组。
    """
    # 分割请求体为不同部分
    parts = body.split('--' + boundary)

    # 初始化文件名和文件数据
    file_name = None
    file_data = None

    # 遍历每个部分
    for part in parts:
        # 检查是否有Content-Disposition头部
        if 'Content-Disposition: form-data;' in part:
            # 提取文件名
            file_name = part.split('filename="')[1].split('"')[0]

            # 提取文件数据
            # 文件数据通常位于两个CRLF之后
            file_data = part.split('\r\n\r\n')[1].rstrip('\r\n--')

            # 一旦找到文件，就跳出循环
            break

    return file_name, file_data.encode()  # 编码文件数据为字节


def parse_range_header(range_header):
    """解析Range头部，返回范围列表"""
    try:
        # Range头部的格式是"start-end"，多个范围以逗号分隔（如果没有range后面的参数呢？）
        ranges = []
        parts = range_header.strip().split(',')
        for part in parts:
            start, end = part.strip().split('-')
            start = int(start) if start else None
            end = int(end) if end else None
            ranges.append((start, end))
        return ranges
    except Exception as e:
        print(f"Error parsing Range header: {e}")
        return None


def send_directory_html(client_socket, session_id, dir_path):
    """发送一个列出目录内容的HTML页面。"""
    try:
        entries = os.listdir(dir_path)
        # 添加HTML头部和标题
        html_content = '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">\n'
        html_content += '<html>\n<head>\n'
        html_content += '<meta http-equiv="Content-Type" content="text/html; charset=utf-8">\n'
        html_content += '<title>Directory listing for {}</title>\n'.format(dir_path)
        html_content += '</head>\n<body>\n'
        html_content += '<h1>Directory listing for {}</h1>\n<hr>\n<ul>\n'.format(dir_path)

        for entry in entries:
            # 判断是否是目录，如果是，添加斜杠（/）
            if os.path.isdir(os.path.join(dir_path, entry)):
                entry += '/'
                html_content += '<li><a href="{}">{}</a></li>\n'.format(entry + '?SUSTech-HTTP=0', entry)
            else:
                html_content += '<li><a href="{}">{}</a></li>\n'.format(entry, entry)

        html_content += '</ul>\n<hr>\n</body>\n</html>'

        send_response(client_socket, session_id, '200 OK', html_content, {'Content-Type': 'text/html'})
    except IOError:
        send_response(client_socket, session_id, '404 Not Found', 'Directory not found.')


def send_directory_metadata(client_socket, session_id, dir_path):
    """发送目录的元数据。"""
    try:
        entries = os.listdir(dir_path)
        send_response(client_socket, session_id, '200 OK', json.dumps(entries), {'Content-Type': 'application/json'})
    except IOError:
        send_response(client_socket, session_id, '404 Not Found', 'Directory not found.')


def send_file_content(client_socket, session_id, file_path):
    """发送文件的内容。"""
    print('send_file_content')
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            content_type = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
            headers = {
                'Content-Type': content_type,
                'Content-Disposition': 'attachment; filename="{}"'.format(os.path.basename(file_path))
            }
            send_response(client_socket, session_id, '200 OK', content, headers)
    except IOError:
        send_response(client_socket, session_id, '404 Not Found', 'File not found.')


def send_file_content_chunked(client_socket, session_id, file_path):
    """以分块传输编码发送文件内容"""
    try:
        with open(file_path, 'rb') as f:
            # 设置分块传输头部
            headers = {
                'Content-Type': mimetypes.guess_type(file_path)[0] or 'application/octet-stream',
                'Transfer-Encoding': 'chunked'
            }
            send_response(client_socket, session_id, '200 OK', b'', headers)

            # 发送文件内容的每个块
            while True:
                chunk = f.read(4096)  # 读取固定大小的块
                if not chunk:
                    break
                size_str = f"{len(chunk):X}\r\n"
                client_socket.send(size_str.encode() + chunk + b'\r\n')

            # 发送结束块
            client_socket.send(b'0\r\n\r\n')
    except IOError:
        send_response(client_socket, session_id, '404 Not Found', 'File not found.')


def send_file_content_range(client_socket, session_id, file_path, range_header):
    file_size = os.path.getsize(file_path)
    ranges = parse_range_header(range_header)
    if len(ranges) == 1:
        # 单范围请求
        start, end = ranges[0]
        send_single_range(client_socket, session_id, file_path, start, end, file_size)
    else:
        # 多范围请求
        send_multiple_ranges(client_socket, session_id, file_path, ranges, file_size)


def send_single_range(client_socket, session_id, file_path, start, end, file_size):
    if start is None:
        start = file_size - end
        end = file_size - 1
    elif end is None:
        end = file_size - 1
    if 0 <= start <= end < file_size:
        # 有效范围
        with open(file_path, 'rb') as f:
            f.seek(start)
            content = f.read(end - start + 1)
            headers = {
                'Content-Type': mimetypes.guess_type(file_path)[0] or 'application/octet-stream',
                'Content-Range': f'bytes {start}-{end}/{file_size}',
            }
            send_response(client_socket, session_id, '206 Partial Content', content, headers)
    else:
        # 无效范围
        send_response(client_socket, session_id, '416 Range Not Satisfiable', 'Invalid byte range')


def send_multiple_ranges(client_socket, session_id, file_path, ranges, file_size):
    """发送多范围请求的响应"""
    headers = {
        'Content-Type': 'multipart/byteranges; boundary=THIS_STRING_SEPARATES',
        # 'Transfer-Encoding': 'chunked',
        'Content-Range': f'bytes */{file_size}',
        'MIME-Version': '1.0'
    }
    content = b''

    # 发送每个范围的响应
    for start, end in ranges:
        if start is None:
            start = file_size - end
            end = file_size - 1
        elif end is None:
            end = file_size - 1
        if 0 <= start <= end < file_size:
            # 有效范围
            with open(file_path, 'rb') as f:
                f.seek(start)
                content += f'--THIS_STRING_SEPARATES\r\n'.encode()
                content += f'Content-Type: {mimetypes.guess_type(file_path)[0] or "application/octet-stream"}\r\n'.encode()
                content += f'Content-Range: bytes {start}-{end}/{file_size}\r\n\r\n'.encode()
                content += f.read(end - start + 1) + b'\r\n'
        else:
            # 无效范围
            send_response(client_socket, session_id, '416 Range Not Satisfiable', 'Invalid byte range')
            return

    content += b'--THIS_STRING_SEPARATES--\r\n'  # 结束块（是否要加上\r\n？）
    send_response(client_socket, session_id, '206 Partial Content', content, headers)


def send_response(client_socket, session_id, status_code, body, headers=None):
    """发送HTTP响应"""
    if headers is None:
        headers = {}
    headers.setdefault('Content-Type', 'text/plain')
    # 如果是分块传输，不设置Content-Length头部，不发送body
    if 'Transfer-Encoding' not in headers or headers['Transfer-Encoding'] != 'chunked':
        # 如果body不是字节类型，将其编码为字节流
        if not isinstance(body, bytes):
            body = body.encode()
        # 设置Content-Length和Set-Cookie头部
        headers['Content-Length'] = str(len(body))
        if session_id:  # 如果有会话ID，设置Set-Cookie头部
            headers['Set-Cookie'] = f'SessionID={session_id}'

    # 构建并发送响应头部
    headers_lines = [f'{key}: {value}' for key, value in headers.items()]
    headers_section = '\r\n'.join(headers_lines)
    response = f'HTTP/1.1 {status_code}\r\n{headers_section}\r\n\r\n'
    client_socket.send(response.encode())

    # 如果是分块传输，发送响应时不包含body
    if 'Transfer-Encoding' not in headers or headers['Transfer-Encoding'] != 'chunked':
        client_socket.send(body)


class HttpServer:
    def __init__(self, host, port, user_credentials):
        self.host = host
        self.port = port
        self.user_credentials = user_credentials
        self.sessions = {}  # 存储会话ID和用户名的映射
        self.session_expiry = {}  # 存储会话ID的过期时间

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
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, addr))
                client_thread.start()
        finally:
            server.close()

    def handle_client(self, client_socket, addr):
        """处理客户端连接，包括检查Cookie、用户认证和结束会话"""
        try:
            while True:
                try:
                    request = client_socket.recv(1024).decode()
                except ConnectionResetError:
                    print(f"Connection reset by peer {addr}")
                    break

                if not request:  # 检查请求是否为空
                    print("请求为空")
                    break

                try:
                    method, path, headers, body = parse_request(request)
                except ValueError:
                    print("请求解析失败")
                    break  # 退出循环，关闭连接

                # 检查请求中的Cookie
                cookie = headers.get('Cookie')
                if cookie:
                    session_id = cookie.split('=')[1]
                    if session_id in self.sessions:
                        if self.session_expiry[session_id] > time.time():
                            # 更新会话过期时间
                            self.session_expiry[session_id] = time.time() + 3600
                        else:
                            # 会话过期
                            del self.sessions[session_id]
                            del self.session_expiry[session_id]
                            send_response(client_socket, None, '401 Unauthorized', 'Session expired')
                            continue
                    else:
                        # 无效的会话ID
                        send_response(client_socket, None, '401 Unauthorized', 'Invalid session ID')
                        continue
                # 如果没有Cookie，判断是否有Authorization头
                else:
                    auth_success, session_id, error_message = self.authenticate_user(headers)
                    if not auth_success:
                        send_response(client_socket, None, '401 Unauthorized',
                                      headers={"WWW-Authenticate": 'Basic realm="Authorization Required"'}, # 这里逻辑有点问题，只有没有提供Authorization头部时才需要发送WWW-Authenticate头部
                                      body=error_message)
                        continue  # 继续监听下一个请求

                # 认证成功，传递Cookie
                self.handle_request(client_socket, session_id, method, path, headers, body)

                # 如果headers中有Connection: close，则关闭连接
                if headers.get('Connection') == 'close':
                    client_socket.close()
                    break
        finally:
            client_socket.close()
            print(f'{addr} Connection closed')

    def handle_request(self, client_socket, session_id, method, path, headers, body):
        """处理客户端连接"""

        # 如果是POST请求
        if method == 'POST':
            if '/upload' in path:
                upload_path = self.parse_and_validate_path(client_socket, session_id, path, 'upload')
                if not upload_path:
                    return

                # 解析multipart/form-data
                content_type = headers.get('Content-Type', '')
                if 'multipart/form-data' in content_type:
                    boundary = content_type.split('boundary=')[1]
                    file_name, file_data = parse_multipart_form_data(body, boundary)

                    full_path = os.path.join('../data', upload_path, file_name)
                    directory = os.path.dirname(full_path)
                    if not os.path.exists(directory):
                        send_response(client_socket, session_id, '404 Not Found', 'Directory not found')
                        return

                    try:
                        with open(full_path, 'wb') as file:
                            file.write(file_data)
                        send_response(client_socket, session_id, '200 OK', 'File uploaded successfully')
                    except IOError:
                        send_response(client_socket, session_id, '500 Internal Server Error', 'Failed to write file')

            elif '/delete' in path:
                delete_path = self.parse_and_validate_path(client_socket, session_id, path, 'delete')
                if not delete_path:
                    return

                full_path = os.path.join('../data', delete_path)
                if not os.path.exists(full_path):
                    send_response(client_socket, session_id, '404 Not Found', 'File not found')
                    return

                try:
                    os.remove(full_path)
                    send_response(client_socket, session_id, '200 OK', 'File deleted successfully')
                except IOError:
                    send_response(client_socket, session_id, '500 Internal Server Error', 'Failed to delete file')
            else:
                send_response(client_socket, session_id, '405 Method Not Allowed', 'Method not allowed.')

        # 如果是GET或HEAD请求
        elif method == 'GET' or method == 'HEAD':
            # 解析URL
            print(path)
            path_parts = path.split('?')
            file_path = path_parts[0]
            query_params = {}
            if len(path_parts) > 1:
                query_params = dict(param.split('=') for param in path_parts[1].split('&') if '=' in param)

            sustech_http = query_params.get('SUSTech-HTTP')

            # Remove the leading '/' and prepend the data directory
            file_system_path = './data' + file_path

            if not os.path.exists(file_system_path):
                send_response(client_socket, session_id, '404 Not Found',
                              'The requested URL was not found on this server.')
                return

            if os.path.isdir(file_system_path):
                if sustech_http == '0' or path == '/':  # 如果是请求根目录，发送目录列表
                    send_directory_html(client_socket, session_id, file_system_path)
                elif sustech_http == '1':
                    send_directory_metadata(client_socket, session_id, file_system_path)
                else:
                    send_response(client_socket, session_id, '400 Bad Request',
                                  'Bad request syntax or unsupported method.')
            elif os.path.isfile(file_system_path):
                # 发送文件
                range_header = headers.get('Range')
                print(range_header)
                if query_params.get('chunked') == '1':  # 分块传输
                    send_file_content_chunked(client_socket, session_id, file_system_path)
                elif range_header:  # 断点传输
                    send_file_content_range(client_socket, session_id, file_system_path, range_header)
                else:
                    send_file_content(client_socket, session_id, file_system_path)
            else:
                send_response(client_socket, session_id, '404 Not Found',
                              'The requested URL was not found on this server.')

    def authenticate_user(self, headers):
        """用户认证，返回认证状态和会话ID（如果认证成功）。"""
        auth_header = headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            return False, None, 'Invalid authentication header'

        encoded_credentials = auth_header.split(' ')[1]
        decoded_credentials = base64.b64decode(encoded_credentials).decode()
        username, password = decoded_credentials.split(':')
        print(username, password)

        if username in self.user_credentials and self.user_credentials[username] == password:
            # 认证成功，生成会话ID
            session_id = generate_session_id()
            self.sessions[session_id] = username
            self.session_expiry[session_id] = time.time() + 3600  # 假设会话有效期为1小时
            return True, session_id, None
        else:
            return False, None, 'Invalid username or password'

    def parse_and_validate_path(self, client_socket, session_id, path, operation):
        # Extract the username from the session
        username = self.sessions.get(session_id)

        # Check if the request is authorized
        if not username:
            send_response(client_socket, session_id, '401 Unauthorized', 'Unauthorized')
            return None

        # Parse the path query parameter
        try:
            query = path.split('?')[1]
            query_params = query.split('=')

            if not query_params[0] == 'path' or len(query_params) != 2:
                send_response(client_socket, session_id, '400 Bad Request', 'Missing or invalid path parameter')
                return None

            # Normalize the path
            normalized_path = query_params[1]
            if normalized_path.startswith('/'):
                normalized_path = normalized_path[1:]
            if normalized_path.endswith('/'):
                normalized_path = normalized_path[:-1]

            # Check if the path is valid for the user
            if not normalized_path.startswith(f'{username}'):
                send_response(client_socket, session_id, '403 Forbidden', 'Forbidden')
                return None

            return normalized_path
        except IndexError:
            send_response(client_socket, session_id, '400 Bad Request', f'Missing {operation} path parameter')
            return None


# 服务器监听地址和端口
HOST, PORT = 'localhost', 8080
user_credentials = load_user_credentials()
server = HttpServer(HOST, PORT, user_credentials)
server.start()
