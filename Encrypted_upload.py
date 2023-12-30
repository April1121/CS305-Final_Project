import base64
import io
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

# 生成对称密钥
symmetric_key = Fernet.generate_key()

# 创建一个Cipher对象
cipher_suite = Fernet(symmetric_key)

# 加载服务器的公钥
with open("key/Server_public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read()
    )

# 使用公钥加密对称密钥
encrypted_key = public_key.encrypt(
    symmetric_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# 将加密后的对称密钥转换为Base64编码的字符串
base64_encoded_key = base64.b64encode(encrypted_key).decode()

# 将Base64编码的字符串保存为.txt文件
with open("key/Server_encrypted_key.txt", "w") as f:
    f.write(base64_encoded_key)

# 读取并加密文件内容
with open("tmp/a.txt", "rb") as file:
    encrypted_file_data = cipher_suite.encrypt(file.read())

# 将加密后的文件数据写入一个新的文件
with open("tmp/encrypted_a.txt", "wb") as file:
    file.write(encrypted_file_data)

files = {"firstFile": ("a.txt", open('tmp/encrypted_a.txt', "rb")),
         "key.txt": ("key.txt", open("key/Server_encrypted_key.txt", "rb"))}
data = {}
headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
r = requests.post(url='http://127.0.0.1:8080/upload?path=client1/', data=data, headers=headers, files=files)
print(r)