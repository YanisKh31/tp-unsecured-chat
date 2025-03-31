import logging
import base64
import os
from typing import Tuple

import msgpack
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from pywebio.output import put_text
from names_generator import generate_name

from simple_client import SimpleClient

ITERATIONS = 100  # Number of iterations for key derivation

class AEClient(SimpleClient):
    def __init__(self, host: str, send_port: int, broadcast_port: int, nick: str, password: str):
        super().__init__(host, send_port, broadcast_port, nick)
        self._password = password
        # Override serialization functions to use msgpack
        self._serial_function = msgpack.dumps
        self._deserial_function = msgpack.loads

    def derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Derive a cryptographic key from password using PBKDF2HMAC"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_message(self, password: str, message: str) -> Tuple[bytes, bytes]:
        """Encrypt a message using Fernet"""
        salt = os.urandom(16)  # Generate random salt
        key = self.derive_key_from_password(password, salt)
        fernet = Fernet(key)
        encrypted_message = fernet.encrypt(message.encode())
        return encrypted_message, salt

    def decrypt_message(self, password: str, encrypted_message: bytes, salt: bytes, nick: str) -> str:
        """Decrypt a message using Fernet"""
        key = self.derive_key_from_password(password, salt)
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_message).decode()

    def send(self, frame: dict) -> dict:
        """Override send to handle encryption for message frames"""
        if frame["type"] == "message":
            encrypted_msg, salt = self.encrypt_message(self._password, frame["message"])
            frame["message"] = base64.b64encode(encrypted_msg).decode()
            frame["salt"] = base64.b64encode(salt).decode()
        
        packet = self._serial_function(frame)
        response_packet = self._client.send(packet)
        if response_packet:
            return self._deserial_function(response_packet)

    def on_recv(self, packet: bytes):
        """Handle received broadcast messages"""
        frame = self._deserial_function(packet)
        if frame["type"] == "message":
            try:
                encrypted_msg = base64.b64decode(frame["message"])
                salt = base64.b64decode(frame["salt"])
                decrypted_msg = self.decrypt_message(self._password, encrypted_msg, salt, frame["nick"])
                put_text(f"{frame['nick']} : {decrypted_msg}", scope='scrollable')
            except Exception as e:
                self._log.error(f"Failed to decrypt message: {e}")
        else:
            self._log.error(f"Unknown frame type: {frame['type']}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    client = AEClient("localhost", 6666, 6667, generate_name(), "Best_Secr3t_ever_1")
    client.run()