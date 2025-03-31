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
from pywebio.session import *
from simple_client import SimpleClient

# On utilise beaucoup d'itérations pour rendre le chiffrement plus robuste
ITERATIONS = 100000

class AEADClient(SimpleClient):
    def __init__(self, host: str, send_port: int, broadcast_port: int, nick: str, password: str):
        # Initialise un client de chat avec chiffrement
        super().__init__(host, send_port, broadcast_port, nick)
        self._password = password  # On stocke le mot de passe pour déchiffrer
        # On utilise msgpack pour formater les données (comme JSON mais plus efficace)
        self._serial_function = msgpack.dumps
        self._deserial_function = msgpack.loads
        self._running = False

    def derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        # Transforme un mot de passe en clé de chiffrement sécurisée
        # Le "sel" permet d'éviter que deux mots de passe identiques donnent la même clé
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),  # Utilise SHA-256 comme fonction de hachage
            length=32,  # Longueur de la clé (32 octets = 256 bits)
            salt=salt,  # Valeur aléatoire pour renforcer la sécurité
            iterations=ITERATIONS,  # Plus c'est grand, plus c'est sécurisé (mais lent)
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_message(self, password: str, message: str) -> Tuple[bytes, bytes]:
        # Chiffre un message avec le mot de passe
        salt = os.urandom(16)  # Génère un sel aléatoire
        key = self.derive_key_from_password(password, salt)
        fernet = Fernet(key)  # Prépare le système de chiffrement
        encrypted_message = fernet.encrypt(message.encode())  # Chiffre le message
        return encrypted_message, salt  # Renvoie le message chiffré + le sel

    def decrypt_message(self, password: str, encrypted_message: bytes, salt: bytes, nick: str) -> str:
        # Déchiffre un message avec le mot de passe et le sel
        key = self.derive_key_from_password(password, salt)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_message).decode()  # Déchiffre
        # Ici on pourrait vérifier que le message vient bien de "nick"
        return decrypted

    def send(self, frame: dict) -> Optional[dict]:
        # Envoie un message en le chiffrant d'abord
        if frame["type"] == "message":
            encrypted_msg, salt = self.encrypt_message(self._password, frame["message"])
            # Convertit en base64 pour pouvoir l'envoyer comme texte
            frame["message"] = base64.b64encode(encrypted_msg).decode()
            frame["salt"] = base64.b64encode(salt).decode()
        packet = self._serial_function(frame)  # Formate les données
        response_packet = self._client.send(packet)  # Envoie
        return self._deserial_function(response_packet) if response_packet else None

    def on_recv(self, packet: bytes):
        # Reçoit un message et le déchiffre
        try:
            frame = self._deserial_function(packet)  # Déformate les données
            if frame["type"] == "message":
                # Convertit depuis le base64
                encrypted_msg = base64.b64decode(frame["message"])
                salt = base64.b64decode(frame["salt"])
                # Déchiffre le message
                decrypted_msg = self.decrypt_message(self._password, encrypted_msg, salt, frame["nick"])
                # Affiche le message dans le chat
                put_text(f"{frame['nick']}: {decrypted_msg}", scope='chat')
        except Exception:
            pass  # Si erreur, on ignore (pas très propre mais simple)