class ResponseSender:
    """发送HTTP响应"""

    def __init__(self, client_socket, session_id, is_head_request):
        self.client_socket = client_socket
        self.session_id = session_id
        self.is_head_request = is_head_request

    def set_session_id(self, session_id):
        self.session_id = session_id

    def set_is_head_request(self, is_head_request):
        self.is_head_request = is_head_request

    def get_client_socket(self):
        return self.client_socket

    def get_session_id(self):
        return self.session_id

    def send(self, response):
        status = response.get('status', '200 OK')
        body = response.get('body', '')
        headers = response.get('headers', {})
        headers.setdefault('Content-Type', 'text/plain')

        # 检查是否是分块传输
        is_chunked = 'Transfer-Encoding' in headers and headers['Transfer-Encoding'] == 'chunked'

        if not is_chunked:
            # 如果body不是字节类型，将其编码为字节流
            if not isinstance(body, bytes):
                body = body.encode()
            # 设置Content-Length头部
            headers['Content-Length'] = str(len(body))
            if self.session_id:  # 如果有会话ID，设置Set-Cookie头部
                headers['Set-Cookie'] = f'SessionID={self.session_id}'

        # 构建响应头部
        headers_lines = [f'{key}: {value}' for key, value in headers.items()]
        headers_section = '\r\n'.join(headers_lines)
        response_header = f'HTTP/1.1 {status}\r\n{headers_section}\r\n\r\n'
        self.client_socket.send(response_header.encode())  # 不用发body吗？

        # 分块传输 和 HEAD 请求不发送响应体
        if not is_chunked and not self.is_head_request:
            self.client_socket.send(body)
