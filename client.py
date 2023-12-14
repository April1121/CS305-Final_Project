import socket
import base64
import os


class HttpClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.connection = None

    def connect(self):
        if self.connection is None:
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connection.connect((self.host, self.port))

    def send_request(self, request, cookies=None):
        if cookies:
            request += f"\r\nCookie: {cookies}"
        request += "\r\n"
        self.connection.send(request.encode())
        response = self.connection.recv(4096)  # 表示从服务器接收最多4096字节的数据
        return response

    def close(self):
        if self.connection:
            self.connection.close()
            self.connection = None

    def build_request(self, method, url, headers=None, body=None):  # 这里的none表示默认，当header没有值时
        # method: HTTP请求方法（如GET, POST, PUT, DELETE等）
        # url: 请求的资源路径（如 / index.html或 / api / data）。
        request_line = f"{method} {url} HTTP/1.1"
        headers_lines = [f"Host: {self.host}"]
        if headers:
            headers_lines += [f"{key}: {value}" for key, value in headers.items()]
        request_headers = "\r\n".join(headers_lines)  # 为headers_lines中的每个元素之间添加\r\n
        request_body = body if body else ""
        return f"{request_line}\r\n{request_headers}\r\n\r\n{request_body}"

    def parse_response(self, response):
        """解析HTTP响应"""
        headers, body = response.split('\r\n\r\n', 1)
        status_line, headers = headers.split('\r\n', 1)
        status_code = status_line.split(' ')[1]
        headers = dict(line.split(': ') for line in headers.split('\r\n'))
        return status_code, headers, body


def authenticate_user(client, username, password):
    auth_headers = {
        "Authorization": f"Basic {base64.b64encode(f'{username}:{password}'.encode()).decode()}",
        "Connection": "keep-alive"
    }
    auth_request = client.build_request("GET", "/authenticate", auth_headers)
    auth_response = client.send_request(auth_request)
    status_code, headers, body = client.parse_response(auth_response.decode())
    if status_code == "200":
        print(status_code, "Authentication successfully")
        return True
    else:
        print(status_code, body)
        return False


def send_file(client, username, password, filepath):
    directory, filename = os.path.split(filepath)
    with open(filepath, 'rb') as file:
        file_content = file.read()

    upload_headers = {
        "Content-Length": str(len(file_content)),
        "Connection": "keep-alive"
    }
    upload_request = client.build_request("POST", f"/upload/{filename}", upload_headers, file_content)
    upload_response = client.send_request(upload_request)
    print(upload_response.decode())


def get_credentials():
    username = input("Enter username: ")
    password = input("Enter password: ")
    return username, password


def initial_request(client):
    """发送初始请求，不带认证信息"""
    request = client.build_request("GET", "/")
    response = client.send_request(request)
    status_code, headers, body = client.parse_response(response.decode())
    if status_code == "401":
        print(status_code, "Unauthorized, please authenticate")
        return headers.get("WWW-Authenticate")
    else:
        print(status_code, body)
        return None


def choose_server(choice, client):
    if choice == 1:
        www_authenticate = initial_request(client)
        if www_authenticate:
            username, password = get_credentials()
            authenticated = authenticate_user(client, username, password)
            while not authenticated:
                print("Authentication failed, please try again")
                username, password = get_credentials()
                authenticated = authenticate_user(client, username, password)
    elif choice == 2:
        print("hello")
    elif choice == 3:
        print("hello")
    elif choice == 4:
        print("Bye")
        exit(0)


# 服务器地址和端口
HOST, PORT = 'localhost', 8000
client = HttpClient(HOST, PORT)
try:
    client.connect()
    while True:
        print("Input the number of server you need:")
        print("1. send empty request")
        print("2. send request with credentials")
        print("3. upload file")
        print("4. exit")
        choice = int(input())
        choose_server(choice, client)

finally:
    client.close()
