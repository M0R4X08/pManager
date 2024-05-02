import bcrypt
import secrets
import string
import random
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

class EncryptionUtils:
    
    @classmethod
    def generate_key(cls):
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()

            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            return private_pem, public_pem
    
    @classmethod
    def derive_key_from_password(cls,password, salt=None, iterations=100000):
            if salt is None:
                salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations
            )
            derived_key = kdf.derive(password.encode())
            return derived_key, salt
        
    @classmethod
    def encrypt_keys(cls, message, key, salt):
            iv = secrets.token_bytes(16)  # Generar un IV aleatorio
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(message) + encryptor.finalize()
            return iv + ciphertext  # Retornar solo el IV seguido del texto cifrado
        
    @classmethod
    def decrypt_keys(cls, ciphertext, key, salt):
        iv = ciphertext[:16]  # Obtener el IV del ciphertext
        ciphertext = ciphertext[16:]  # Eliminar el IV del ciphertext
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        message = decryptor.update(ciphertext) + decryptor.finalize()
        return message
    
    @classmethod
    def encrypt(cls,message, public_pem):
        public_key = serialization.load_pem_public_key(public_pem)
        message = public_key.encrypt( 
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return message
    
    @classmethod
    def decrypt(cls,message_encrypted, private_pem):
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        message = private_key.decrypt(
            message_encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return message.decode()
    @classmethod
    def random_password(cls):
        length = 20
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for i in range(length))
        return password
    
    @classmethod
    def hash_password(cls,password):
        # Generar un salt aleatorio
        salt = bcrypt.gensalt()
        # Hashear la contraseÃ±a con el salt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password
    
    @classmethod
    def verify_password(cls,hashed_password, password):
        if isinstance(hashed_password, str):
            hashed_password = hashed_password.encode('utf-8')
        if isinstance(password, str):
            password = password.encode('utf-8')
        return bcrypt.checkpw(password, hashed_password)