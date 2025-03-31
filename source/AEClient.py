# Importe les bibliothèques nécessaires
import logging  # Pour gérer les messages de log
import base64   # Pour encoder/décoder en base64
import os       # Pour les fonctions système (comme générer des nombres aléatoires)
from typing import Tuple  # Pour indiquer les types de retour des fonctions

# Importe des outils pour le chiffrement/déchiffrement
import msgpack  # Pour sérialiser les données (les convertir en format binaire)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Pour dériver une clé à partir d'un mot de passe
from cryptography.hazmat.primitives import hashes  # Pour les fonctions de hachage
from cryptography.fernet import Fernet  # Pour chiffrer/déchiffrer simplement

# Quelques outils d'interface et pour générer des noms aléatoires
from pywebio.output import put_text
from names_generator import generate_name

from simple_client import SimpleClient  # Le client de base qu'on va améliorer

ITERATIONS = 100  # Nombre de répétitions pour sécuriser la génération de clé

class AEClient(SimpleClient):
    def __init__(self, host: str, send_port: int, broadcast_port: int, nick: str, password: str):
        super().__init__(host, send_port, broadcast_port, nick)
        self._password = password  # Stocke le mot de passe pour le chiffrement
        # Utilise msgpack pour sérialiser/désérialiser au lieu du format par défaut
        self._serial_function = msgpack.dumps
        self._deserial_function = msgpack.loads

    def derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Crée une clé de chiffrement à partir d'un mot de passe et d'un 'sel' (une valeur aléatoire)"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),  # Utilise l'algorithme SHA256
            length=32,                 # Longueur de la clé (32 octets)
            salt=salt,                # Le "sel" ajoute de l'aléatoire pour sécuriser
            iterations=ITERATIONS,    # Nombre de répétitions pour ralentir les attaques
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_message(self, password: str, message: str) -> Tuple[bytes, bytes]:
        """Chiffre un message avec le mot de passe"""
        salt = os.urandom(16)  # Génère un sel aléatoire (16 octets)
        key = self.derive_key_from_password(password, salt)
        fernet = Fernet(key)  # Prépare l'outil de chiffrement
        encrypted_message = fernet.encrypt(message.encode())  # Chiffre le message
        return encrypted_message, salt  # Retourne le message chiffré + le sel

    def decrypt_message(self, password: str, encrypted_message: bytes, salt: bytes, nick: str) -> str:
        """Déchiffre un message avec le mot de passe et le sel"""
        key = self.derive_key_from_password(password, salt)
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_message).decode()  # Déchiffre et convertit en texte

    def send(self, frame: dict) -> dict:
        """Envoie un message après l'avoir chiffré si c'est un message texte"""
        if frame["type"] == "message":
            # Chiffre le message et récupère le sel
            encrypted_msg, salt = self.encrypt_message(self._password, frame["message"])
            # Encode en base64 pour l'envoi (format texte sûr)
            frame["message"] = base64.b64encode(encrypted_msg).decode()
            frame["salt"] = base64.b64encode(salt).decode()
        
        # Convertit le dictionnaire en binaire et l'envoie
        packet = self._serial_function(frame)
        response_packet = self._client.send(packet)
        if response_packet:
            return self._deserial_function(response_packet)

    def on_recv(self, packet: bytes):
        """Reçoit un message et le déchiffre si c'est un message texte"""
        frame = self._deserial_function(packet)  # Convertit le binaire en dictionnaire
        if frame["type"] == "message":
            try:
                # Décode le message et le sel depuis le base64
                encrypted_msg = base64.b64decode(frame["message"])
                salt = base64.b64decode(frame["salt"])
                # Déchiffre le message
                decrypted_msg = self.decrypt_message(self._password, encrypted_msg, salt, frame["nick"])
                # Affiche le message déchiffré
                put_text(f"{frame['nick']} : {decrypted_msg}", scope='scrollable')
            except Exception as e:
                self._log.error(f"Échec du déchiffrement: {e}")
        else:
            self._log.error(f"Type de message inconnu: {frame['type']}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)  # Active les logs détaillés
    # Crée un client avec un nom aléatoire et un mot de passe
    client = AEClient("localhost", 6666, 6667, generate_name(), "Best_Secr3t_ever_1")
    client.run()  # Lance le client