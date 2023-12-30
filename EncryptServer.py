import argparse
import json
import socket
import threading

from Authenticator import Authenticator
from EncryptRequestHandler import EncryptRequestHandler

def load_user_credentials():
    """加载用户凭证"""
    with open('users.json', 'r') as file:
        return json.load(file)


class HttpServer:
    """
    HTTP服务器类，负责监听端口，接收客户端连接，委托请求处理给 RequestHandler
    """

    def __init__(self, host, port, user_credentials):
        self.host = host
        self.port = port
        self.user_credentials = user_credentials
        self.authenticator = Authenticator(user_credentials, {}, {})

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(128)
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
        """处理客户端连接，委托请求处理给 RequestHandler"""
        try:
            request_handler = EncryptRequestHandler(client_socket, self.authenticator)
            while True:
                try:
                    result = request_handler.handle_request()
                    if result is None or result is False:
                        break  # 如果返回 None 或 False，则关闭连接
                except Exception as e:
                    print(f"Exception occurred while handling request from {addr}: {e}")
                    break  # 出现异常时退出循环
        except Exception as e:
            print(f"Exception occurred with connection from {addr}: {e}")
        finally:
            client_socket.close()
            print(f'{addr} Connection closed')


if __name__ == '__main__':
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='HTTP Server')
    parser.add_argument('-i', '--host', type=str, default='localhost', help='Host address')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port number')

    args = parser.parse_args()

    # 服务器监听地址和端口
    HOST, PORT = args.host, args.port
    user_credentials = load_user_credentials()
    server = HttpServer(HOST, PORT, user_credentials)
    server.start()
