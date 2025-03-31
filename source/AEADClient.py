import logging
import base64
import os
import random
import threading
import time
import zmq
from typing import Tuple, Optional

import msgpack
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

from pywebio.output import *
from pywebio.input import *
from pywebio.session import *
from pywebio.pin import *

from simple_client import SimpleClient

# Configuration silencieuse du logging
logging.basicConfig(level=logging.CRITICAL)
logger = logging.getLogger("AEADClient")
logger.setLevel(logging.ERROR)  # On ne montre que les erreurs importantes

ITERATIONS = 100000

class AEADClient(SimpleClient):
    def __init__(self, host: str, send_port: int, broadcast_port: int, nick: str, password: str):
        super().__init__(host, send_port, broadcast_port, nick)
        self._password = password
        self._serial_function = msgpack.dumps
        self._deserial_function = msgpack.loads
        self._connected = False
        self._running = False
        self._lock = threading.Lock()
        self._zmq_context = zmq.Context.instance()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def cleanup(self):
        """Nettoyage propre des ressources"""
        self._running = False
        if hasattr(self, '_client'):
            self._client.close()
        if hasattr(self, '_broadcast_socket'):
            self._broadcast_socket.close()
        self._zmq_context.term()

    def derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_message(self, password: str, message: str) -> Tuple[bytes, bytes]:
        salt = os.urandom(16)
        key = self.derive_key_from_password(password, salt)
        fernet = Fernet(key)
        encrypted_message = fernet.encrypt(message.encode())
        return encrypted_message, salt

    def decrypt_message(self, password: str, encrypted_message: bytes, salt: bytes, nick: str) -> str:
        key = self.derive_key_from_password(password, salt)
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_message).decode()

    def join(self) -> bool:
        frame = {"type": "join", "nick": self._nick}
        try:
            response = self.send(frame)
            return response and response.get("response") == "ok"
        except Exception:
            return False

    def send(self, frame: dict) -> Optional[dict]:
        if not self._running:
            return None

        try:
            if frame["type"] == "message":
                encrypted_msg, salt = self.encrypt_message(self._password, frame["message"])
                frame["message"] = base64.b64encode(encrypted_msg).decode()
                frame["salt"] = base64.b64encode(salt).decode()
            
            packet = self._serial_function(frame)
            response_packet = self._client.send(packet)
            return self._deserial_function(response_packet) if response_packet else None
        except zmq.ZMQError:
            self._running = False
            return None
        except Exception as e:
            logger.debug(f"Send error: {e}")
            return None

    def on_recv(self, packet: bytes):
        try:
            frame = self._deserial_function(packet)
            if frame["type"] == "message":
                encrypted_msg = base64.b64decode(frame["message"])
                salt = base64.b64decode(frame["salt"])
                decrypted_msg = self.decrypt_message(self._password, encrypted_msg, salt, frame["nick"])
                with self._lock:
                    put_text(f"{frame['nick']}: {decrypted_msg}", scope='chat')
                    scroll_to('chat', 'bottom')
        except Exception:
            pass  # Ignore les messages qui ne peuvent pas être déchiffrés

    def _setup_ui(self):
        put_scrollable(put_scope('chat'), height=400, keep_bottom=True)
        put_row([
            None,
            put_input('msg', placeholder='Your message'),
            put_button("Send", onclick=self._on_send),
            None
        ], size='1fr auto 1fr')

    def _on_send(self):
        msg = pin.msg
        if msg and self._running:
            try:
                self.message(msg)
                pin_update('msg', value='')
            except Exception:
                pass

    def start_ui(self):
        t = threading.Thread(target=self._setup_ui)
        register_thread(t)
        defer_call(self.cleanup)
        t.start()

    def run(self):
        self._running = True
        
        if not self.join():
            logger.error("Failed to join server")
            self.cleanup()
            return

        self.start_ui()
        
        try:
            while self._running:
                try:
                    self.update()
                    time.sleep(0.1)
                except zmq.ZMQError:
                    break
                except Exception:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            self.cleanup()

if __name__ == "__main__":
    nick = f"user_{random.randint(1000, 9999)}"
    try:
        with AEADClient("localhost", 6666, 6667, nick, "Best_Secr3t_ever_1") as client:
            client.run()
    except Exception:
        pass  # Toutes les erreurs sont déjà gérées en interne