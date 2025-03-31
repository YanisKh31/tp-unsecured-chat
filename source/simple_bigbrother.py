import logging
import pickle

from base_client import BaseClient

class SimpleBigBrother:
    def __init__(self, host: str, broadcast_port: int):
        self._client = BaseClient(host, 0, broadcast_port) 
        self._log = logging.getLogger(self.__class__.__name__)
        self._clients = set()
        self._serial_function = pickle.dumps
        self._deserial_function = pickle.loads

    def on_recv(self, packet: bytes):
        frame = pickle.loads(packet)
        if frame["type"] == "message":
            self._log.info(f"{frame['nick']} : {frame['message']}")

    def run(self):
        while True:
                self._client.update(self.on_recv)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    big_brother = SimpleBigBrother("localhost", 6667)
    big_brother.run()