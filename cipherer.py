from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import b64encode, b64decode
from defaults import kdf_iters, block_size


class Cipherer:
    def __init__(self, iterations=kdf_iters):
        self.salt_size = block_size
        self.iv_size = block_size
        self.iterations = iterations
        self.block_size = block_size

    def derive_key(self, userpass, key_salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=key_salt,
            iterations=self.iterations,
        )
        return kdf.derive(userpass.encode())

    def encrypt(self, plaintext, userpass):
        if not plaintext:
            raise ValueError("Cannot encrypt empty plaintext.")
        if not userpass:
            raise ValueError("Password is required for encryption.")

        key_salt = urandom(self.salt_size)
        iv = urandom(self.iv_size)
        key = self.derive_key(userpass, key_salt)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(
            plaintext.encode()) + encryptor.finalize()

        return key_salt + iv + ciphertext

    def decrypt(self, enc_blob, userpass):
        if len(enc_blob) < self.salt_size + self.iv_size:
            raise ValueError("Invalid encrypted data format.")
        if not userpass:
            raise ValueError("Password is required for decryption.")

        key_salt = enc_blob[:self.salt_size]
        iv = enc_blob[self.salt_size:self.salt_size + self.iv_size]
        enc_data = enc_blob[self.salt_size + self.iv_size:]

        key = self.derive_key(userpass, key_salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()

        plaintext = decryptor.update(enc_data) + decryptor.finalize()
        return plaintext.decode()

    @staticmethod
    def armorize(data):
        return b64encode(data).decode()

    @staticmethod
    def dearmorize(data):
        return b64decode(data)
