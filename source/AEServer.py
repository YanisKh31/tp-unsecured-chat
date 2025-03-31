# Importe les modules nécessaires
import logging  # Pour enregistrer des messages (debug, info, etc.)
from typing import Tuple  # Pour indiquer qu'une fonction retourne un tuple
import msgpack  # Format de sérialisation binaire (comme JSON mais plus compact)

# Importe les classes parentes depuis d'autres fichiers
from base_server import BaseServer
from simple_server import SimpleServer

class AEServer(SimpleServer):
    """Serveur qui gère les connexions clients et le routage des messages."""
    
    def __init__(self, recv_port: int, broadcast_port: int) -> None:
        """Initialise le serveur avec les ports d'écoute et de diffusion."""
        super().__init__(recv_port, broadcast_port)  # Appelle le constructeur parent
        
        # Configure comment les données sont transformées pour le réseau
        self._serial_function = msgpack.dumps  # Convertit un objet Python en bytes
        self._deserial_function = msgpack.loads  # Convertit bytes en objet Python
        
        self._log = logging.getLogger(self.__class__.__name__)  # Crée un logger
        self._clients = set()  # Stocke les pseudos des clients connectés (set évite les doublons)

    def on_join(self, packet: bytes, frame: dict) -> Tuple[bytes, bytes]:
        """Appelé quand un nouveau client veut se connecter."""
        if frame["nick"] in self._clients:  # Si le pseudo est déjà pris
            return None, self._serial_function({"response": "ko"})  # Refuse la connexion
        self._clients.add(frame["nick"])  # Ajoute le client
        return None, self._serial_function({"response": "ok"})  # Accepte la connexion

    def on_message(self, packet: bytes, frame: dict) -> Tuple[bytes, bytes]:
        """Appelé quand un client envoie un message."""
        if frame["nick"] not in self._clients:  # Vérifie que l'expéditeur est connecté
            return None, self._serial_function({"response": "ko"})
        return packet, self._serial_function({"response": "ok"})  # Renvoie le message à tous

    def on_leave(self, packet: bytes, frame: dict) -> Tuple[bytes, bytes]:
        """Appelé quand un client se déconnecte."""
        if frame["nick"] not in self._clients:  # Vérifie que le client était connecté
            return None, self._serial_function({"response": "ko"})
        self._clients.remove(frame["nick"])  # Supprime le client
        return None, self._serial_function({"response": "ok"})

    def on_list(self, packet: bytes, frame: dict) -> Tuple[bytes, bytes]:
        """Appelé pour obtenir la liste des clients connectés."""
        return None, self._serial_function({"response": list(self._clients)})  # Renvoie la liste

if __name__ == "__main__":
    """Point d'entrée principal quand on exécute ce fichier directement."""
    logging.basicConfig(level=logging.INFO)  # Configure le niveau de logging
    
    # Crée le serveur qui écoute sur le port 6666 et diffuse sur 6667
    server = AEServer(6666, 6667)
    
    try:
        while True:  # Boucle principale infinie
            server.update()  # Traite les messages entrants
    except KeyboardInterrupt:  # Si l'utilisateur fait Ctrl+C
        server.close()  # Ferme proprement les connexions