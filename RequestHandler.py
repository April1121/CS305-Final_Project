from FileHandler import FileHandler
from ResponseSender import ResponseSender


def parse_request(request):
    """解析HTTP请求"""
    headers, body = request.split('\r\n\r\n', 1)
    request_line, headers = headers.split('\r\n', 1)
    method, path, _ = request_line.split(' ')
    headers = dict(line.split(': ') for line in headers.split('\r\n'))
    return method, path, headers, body


class RequestHandler:
    """
    解析请求，委托给Authenticator处理会话管理和用户认证， 委托给FileHandler处理文件上传和下载
    """

    def __init__(self, client_socket, authenticator):
        self.client_socket = client_socket
        self.authenticator = authenticator
        self.response_sender = ResponseSender(client_socket, None, False)
        self.file_handler = FileHandler(self.response_sender, self.authenticator)

    def handle_request(self):
        try:
            request = self.client_socket.recv(1024).decode()
            if not request:
                return False  # 没有请求或连接应该关闭

            method, path, headers, body = parse_request(request)
            auth_response = self.authenticator.handle_session(headers)

            # 更新ResponseSender设置
            self.response_sender.set_is_head_request(method == 'HEAD')
            self.response_sender.set_session_id(auth_response['session_id'])  # 如果认证失败，session_id为None

            if auth_response['status']:  # 认证失败，返回认证响应
                self.response_sender.send(auth_response)
                return True  # 继续监听下一个请求

            # 处理请求逻辑
            self.process_method(method, path, headers, body)

            # 检查是否需要关闭连接
            if headers.get('Connection') == 'close':
                return False  # 返回 False 表示连接应该关闭

            return True  # 继续监听下一个请求
        except ConnectionResetError:
            return False  # 连接被重置，关闭连接
        except ValueError:
            return False  # 请求解析失败，关闭连接

    def process_method(self, method, path, headers, body):
        """处理客户端连接"""
        if method == 'POST':
            self.handle_post_request(path, headers, body)
        elif method in ['GET', 'HEAD']:
            self.handle_get_head_request(method, path, headers)
        else:
            self.response_sender.send(
                {'status': '405 Method Not Allowed', 'body': 'Method not allowed.'})

    def handle_post_request(self, path, headers, body):
        if '/upload' in path:
            self.file_handler.handle_file_upload(path, headers, body)
        elif '/delete' in path:
            self.file_handler.handle_file_deletion(path)
        else:
            self.response_sender.send(
                {'status': '405 Method Not Allowed', 'body': 'Method not allowed.'})

    def handle_get_head_request(self, method, path, headers):
        self.file_handler.handle_file_download(path, headers)
