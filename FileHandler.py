import base64
import json
import mimetypes
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

def parse_multipart_form_data(body, boundary):
    """解析multipart/form-data格式的数据以支持多文件上传。

    Args:
        body (str): 请求体的内容。
        boundary (str): 分隔符。

    Returns:
        list of tuples: 包含文件名和文件数据的元组的列表。
    """
    # 分割请求体为不同部分
    parts = body.split('--' + boundary)

    # 初始化用于存储所有文件的列表
    files = []

    # 遍历每个部分
    for part in parts:
        # 检查是否有Content-Disposition头部
        if 'Content-Disposition: form-data;' in part:
            # 提取文件名
            file_name = part.split('filename="')[1].split('"')[0]

            # 提取文件数据
            # 文件数据通常位于两个CRLF之后
            file_data = part.split('\r\n\r\n')[1].rstrip('\r\n--')

            # 将文件名和文件数据添加到列表中
            files.append((file_name, file_data.encode()))

    return files  # 返回包含所有文件的列表


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
            if start is None and end is None:  # 当part为'-'时
                return []
            ranges.append((start, end))
        return ranges
    except Exception as e:  # 当range_header为None时，或没有'-'时，或start和end不是整数时
        print(f"Error parsing Range header: {e}")
        return []


class FileHandler:
    """
    负责文件处理
    基础处理：文件上传、文件下载、文件删除
    高级处理：分块传输、断点传输
    """

    def __init__(self, response_sender, authenticator):
        self.response_sender = response_sender
        self.authenticator = authenticator

    def handle_file_upload(self, path, headers, body):
        # 在这里处理文件上传逻辑
        path_validation = self.parse_and_validate_path(path, 'upload')
        if 'response' in path_validation:
            self.response_sender.send(path_validation['response'])
            return

        upload_path = path_validation['upload_path']

        # 解析multipart/form-data
        content_type = headers.get('Content-Type', '')
        if 'multipart/form-data' in content_type:
            boundary = content_type.split('boundary=')[1]
            files = parse_multipart_form_data(body, boundary)  # 获取所有文件

            # 如果没有文件上传，则发送相应的响应
            if not files:
                self.response_sender.send(
                    {'status': '400 Bad Request', 'body': 'No files uploaded'})
                return
            # 首先找到密钥文件并解密对称密钥
            cipher_suite = None
            for file_name, file_data in files:
                if file_name == "key.txt":
                    # 加载私钥
                    with open("key/Server_private_key.pem", "rb") as key_file:
                        private_key = serialization.load_pem_private_key(
                            key_file.read(),
                            password=None
                        )
                    # 解码Base64编码的密钥
                    decoded_key = base64.b64decode(file_data)
                    # 使用私钥解密对称密钥
                    decrypted_key = private_key.decrypt(
                        decoded_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )

                    # 创建一个Cipher对象
                    cipher_suite = Fernet(decrypted_key)
                    break
            # 然后遍历所有的文件，使用解密后的对称密钥来解密文件数据
            for file_name, file_data in files:
                if file_name == "key.txt":
                    continue
                # 解密文件数据
                if cipher_suite:
                    file_data = cipher_suite.decrypt(file_data)

                full_path = os.path.join('./data', upload_path, file_name)
                directory = os.path.dirname(full_path)
                if not os.path.exists(directory):
                    self.response_sender.send(
                        {'status': '404 Not Found', 'body': 'Directory not found'})
                    return

                try:
                    with open(full_path, 'wb') as file:
                        file.write(file_data)
                    # 发送成功上传的消息
                    self.response_sender.send(
                        {'status': '200 OK', 'body': f'File {file_name} uploaded successfully'})
                except IOError:
                    self.response_sender.send(
                        {'status': '500 Internal Server Error', 'body': 'Failed to write file'})
                    return

    def handle_file_deletion(self, path):
        # 在这里处理文件删除逻辑
        path_validation = self.parse_and_validate_path(path, 'delete')
        if 'response' in path_validation:
            self.response_sender.send(path_validation['response'])
            return

        delete_path = path_validation['delete_path']

        full_path = os.path.join('./data', delete_path)
        if not os.path.exists(full_path):
            self.response_sender.send(
                {'status': '404 Not Found', 'body': 'File not found'})
            return

        try:
            os.remove(full_path)
            self.response_sender.send(
                {'status': '200 OK', 'body': 'File deleted successfully'})
            return
        except IOError:
            self.response_sender.send(
                {'status': '500 Internal Server Error', 'body': 'Failed to delete file'})
            return

    def handle_file_download(self, path, headers):
        # 在这里处理文件下载逻辑，包括处理目录和文件请求
        print(path)
        # 解析请求路径和查询参数
        path_parts = path.split('?')
        file_path = path_parts[0]
        query_params = {}
        if len(path_parts) > 1:
            try:
                query_params = dict(param.split('=') for param in path_parts[1].split('&') if '=' in param)
            except ValueError:
                # 如果查询参数格式无效，返回400 Bad Request
                self.response_sender.send(
                    {'status': '400 Bad Request', 'body': 'Bad request syntax.'})
                return

        sustech_http = query_params.get('SUSTech-HTTP')

        file_system_path = './data' + file_path

        if not os.path.exists(file_system_path):
            print(f'File not found: {file_system_path}')
            self.response_sender.send(
                {'status': '404 Not Found', 'body': 'The requested URL was not found on this server.'})
            return

        # 发送逻辑
        if os.path.isdir(file_system_path):
            # 发送目录
            if sustech_http is None or sustech_http == '0':  # 如果没有指定SUSTech-HTTP或者指定为0，则发送HTML
                self.send_directory_html(file_system_path)
            elif sustech_http == '1':
                self.send_directory_metadata(file_system_path)
            else:
                self.response_sender.send(
                    {'status': '400 Bad Request', 'body': 'Bad request syntax or unsupported method.'})
        elif os.path.isfile(file_system_path):
            # 发送文件
            range_header = headers.get('Range')
            if query_params.get('chunked') == '1':  # 分块传输
                self.send_file_content_chunked(file_system_path)
            elif range_header:  # 断点传输
                self.send_file_content_range(file_system_path, range_header)
            else:
                self.send_file_content(file_system_path)

    def parse_and_validate_path(self, path, operation):
        username = self.authenticator.sessions.get(self.response_sender.get_session_id())
        if not username:
            return {'response': {'status': '401 Unauthorized', 'body': 'Unauthorized'}}

        try:
            query = path.split('?')[1]
            query_params = query.split('=')

            if not query_params[0] == 'path' or len(query_params) != 2:
                return {'response': {'status': '400 Bad Request', 'body': 'Missing or invalid path parameter'}}

            # Normalize the path
            normalized_path = query_params[1]
            if normalized_path.startswith('/'):
                normalized_path = normalized_path[1:]
            if normalized_path.endswith('/'):
                normalized_path = normalized_path[:-1]

            # Check if the path is valid for the user
            if not normalized_path.startswith(f'{username}'):
                return {'response': {'status': '403 Forbidden', 'body': 'Forbidden'}}

            # 成功时返回有效的路径
            if operation == 'upload':
                return {'upload_path': normalized_path}
            elif operation == 'delete':
                return {'delete_path': normalized_path}
        except IndexError:
            return {'response': {'status': '400 Bad Request', 'body': f'Missing {operation} path parameter'}}

    # def send_directory_html(self, dir_system_path):
    #     """发送一个列出目录内容的HTML页面。"""
    #     try:
    #         entries = os.listdir(dir_system_path)
    #         # 添加HTML头部和标题
    #         html_content = '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">\n'
    #         html_content += '<html>\n<head>\n'
    #         html_content += '<meta http-equiv="Content-Type" content="text/html; charset=utf-8">\n'
    #         html_content += '<title>Directory listing for {}</title>\n'.format(dir_system_path)
    #         html_content += '</head>\n<body>\n'
    #         html_content += '<h1>Directory listing for {}</h1>\n<hr>\n<ul>\n'.format(dir_system_path)
    #
    #         for entry in entries:
    #             # 判断是否是目录，如果是，添加斜杠（/）
    #             if os.path.isdir(os.path.join(dir_system_path, entry)):
    #                 entry += '/'
    #                 html_content += '<li><a href="{}">{}</a></li>\n'.format(entry + '?SUSTech-HTTP=0', entry)
    #             else:
    #                 html_content += '<li><a href="{}">{}</a></li>\n'.format(entry, entry)
    #
    #         html_content += '</ul>\n<hr>\n</body>\n</html>'
    #
    #         self.response_sender.send(
    #             {'status': '200 OK', 'body': html_content, 'headers': {'Content-Type': 'text/html'}})
    #     except IOError:
    #         self.response_sender.send(
    #             {'status': '404 Not Found', 'body': 'Directory not found.'})

    def send_directory_html(self, dir_system_path):
        try:
            entries = os.listdir(dir_system_path)
            entry_list_items = ""
            for entry in entries:
                # 判断是否是目录，如果是，添加斜杠（/）
                if os.path.isdir(os.path.join(dir_system_path, entry)):
                    entry += '/'
                    entry_list_items += '<li><a href="{}">{}</a></li>\n'.format(entry + '?SUSTech-HTTP=0', entry)
                else:
                    entry_list_items += '<li><a href="{}">{}</a></li>\n'.format(entry, entry)

            root_directory = './data'  # 根目录设置为`data`目录
            parent_path = os.path.dirname(dir_system_path.rstrip('/'))  # This calculates the parent directory path
            print('parent_path: ' + parent_path)

            if parent_path and os.path.normpath(parent_path) != os.path.normpath(root_directory):
                # 由于parent_path将包含'data'，我们需要移除它，只留下相对于'data'的路径
                parent_path = os.path.relpath(parent_path, root_directory)
                parent_path += '/'  # 确保URL将其视为目录
                parent_path = '/' + parent_path  # 这里添加了斜杠，使其成为绝对路径
            else:
                # 如果上级目录是根目录，那么我们设置链接为根目录
                parent_path = '/'

            print('parent_path111111: ' + parent_path)

            # Add HTML links for root and parent directory
            root_directory_link = '<li><a href="/?SUSTech-HTTP=0">Root Directory</a></li>\n'
            parent_directory_link = '<li><a href="{}?SUSTech-HTTP=0">Parent Directory</a></li>\n'.format(parent_path)

            # Prepend the root and parent directory links to the directory entries
            entry_list_items = root_directory_link + parent_directory_link + entry_list_items

            with open('directory_listing_template.html', 'r') as file:
                html_template = file.read()

            html_content = html_template.format(path=dir_system_path, directory_entries=entry_list_items)
            self.response_sender.send(
                {'status': '200 OK', 'body': html_content, 'headers': {'Content-Type': 'text/html'}})
        except IOError:
            self.response_sender.send(
                {'status': '404 Not Found', 'body': 'Directory not found.'})

    def send_directory_metadata(self, dir_system_path):
        """发送目录的元数据。"""
        try:
            entries = os.listdir(dir_system_path)
            entries = sorted(entries)  # 按字典序排序
            updated_entries = [entry + '/' if os.path.isdir(os.path.join(dir_system_path, entry)) else entry for entry
                               in entries]
            self.response_sender.send(
                {'status': '200 OK', 'body': json.dumps(updated_entries),
                 'headers': {'Content-Type': 'application/json'}})
        except IOError:
            self.response_sender.send(
                {'status': '404 Not Found', 'body': 'Directory not found.'})

    def send_file_content_chunked(self, file_system_path):
        """以分块传输编码发送文件内容"""
        try:
            with open(file_system_path, 'rb') as f:
                # 设置分块传输头部
                headers = {
                    'Content-Type': mimetypes.guess_type(file_system_path)[0] or 'application/octet-stream',
                    'Transfer-Encoding': 'chunked'
                }
                self.response_sender.send({'status': '200 OK', 'headers': headers})

                client_socket = self.response_sender.get_client_socket()
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
            self.response_sender.send(
                {'status': '404 Not Found', 'body': 'File not found.'})

    def send_file_content_range(self, file_system_path, range_header):
        file_size = os.path.getsize(file_system_path)
        ranges = parse_range_header(range_header)
        if not ranges:  # 没有提供范围或解析失败
            self.response_sender.send(
                {'status': '400 Bad Request', 'body': 'Invalid Range header'})
            return

        if len(ranges) == 1:
            # 单范围请求
            start, end = ranges[0]
            self.send_single_range(file_system_path, start, end, file_size)
        else:
            # 多范围请求
            self.send_multiple_ranges(file_system_path, ranges, file_size)

    def send_single_range(self, file_path, start, end, file_size):
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
                self.response_sender.send(
                    {'status': '206 Partial Content', 'body': content, 'headers': headers})
        else:
            # 无效范围
            self.response_sender.send(
                {'status': '416 Range Not Satisfiable', 'body': 'Invalid byte range'})

    def send_multiple_ranges(self, file_path, ranges, file_size):
        """发送多范围请求的响应"""
        headers = {
            'Content-Type': 'multipart/byteranges; boundary=THISISMYSELFDIFINEDBOUNDARY',
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
                    content += f'--THISISMYSELFDIFINEDBOUNDARY\r\n'.encode()
                    content += f'Content-Type: {mimetypes.guess_type(file_path)[0] or "application/octet-stream"}\r\n'.encode()
                    content += f'Content-Range: bytes {start}-{end}/{file_size}\r\n\r\n'.encode()
                    content += f.read(end - start + 1) + b'\r\n'
            else:
                # 无效范围
                self.response_sender.send(
                    {'status': '416 Range Not Satisfiable', 'body': 'Invalid byte range'})
                return

        content += b'--THISISMYSELFDIFINEDBOUNDARY--\r\n'  # 结束块
        self.response_sender.send(
            {'status': '206 Partial Content', 'body': content, 'headers': headers})

    def send_file_content(self, file_system_path):
        """发送文件的内容。"""
        try:
            with open(file_system_path, 'rb') as f:
                content = f.read()
                headers = {
                    'Content-Type': mimetypes.guess_type(file_system_path)[0] or 'application/octet-stream',
                    'Content-Disposition': 'attachment; filename="{}"'.format(os.path.basename(file_system_path))
                }
                self.response_sender.send(
                    {'status': '200 OK', 'body': content, 'headers': headers})
        except IOError:
            self.response_sender.send(
                {'status': '404 Not Found', 'body': 'File not found.'})
