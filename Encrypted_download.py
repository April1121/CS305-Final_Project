import base64

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
headers = {"Authorization": "Basic Y2xpZW50MToxMjM="}
r = requests.get(url='http://127.0.0.1:8080/a.txt', headers=headers)
print(r.content.decode())
print(r.headers)
# 提取密钥
encrypted_key_base64 = r.headers['encrypted_key']
encrypted_key = base64.b64decode(encrypted_key_base64)

# 用私钥解密密钥
with open("key/Client_private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )

decrypted_key = private_key.decrypt(
    encrypted_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# 使用解密后的密钥解密文件内容
cipher_suite = Fernet(decrypted_key)
decrypted_content = cipher_suite.decrypt(r.content)

print(decrypted_content.decode())

