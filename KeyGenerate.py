from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# 生成私钥
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,  # 密钥长度，通常为2048或4096
)

# 生成公钥
public_key = private_key.public_key()

# 将私钥保存为PEM格式文件
with open("key/Client_private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

# 将公钥保存为PEM格式文件
with open("key/Client_public_key.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )