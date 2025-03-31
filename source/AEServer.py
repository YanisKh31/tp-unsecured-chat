import logging
from typing import Tuple
import msgpack

from base_server import BaseServer
from simple_server import SimpleServer

class AEServer(SimpleServer):
    def __init__(self, recv_port: int, broadcast_port: int) -> None:
        super().__init__(recv_port, broadcast_port)
        self._serial_function = msgpack.dumps
        self._deserial_function = msgpack.loads
        self._log = logging.getLogger(self.__class__.__name__)
        self._clients = set()

    def on_join(self, packet: bytes, frame: dict) -> Tuple[bytes, bytes]:
        if frame["nick"] in self._clients:
            return None, self._serial_function({"response": "ko"})
        self._clients.add(frame["nick"])
        return None, self._serial_function({"response": "ok"})

    def on_message(self, packet: bytes, frame: dict) -> Tuple[bytes, bytes]:
        if frame["nick"] not in self._clients:
            return None, self._serial_function({"response": "ko"})
        return packet, self._serial_function({"response": "ok"})

    def on_leave(self, packet: bytes, frame: dict) -> Tuple[bytes, bytes]:
        if frame["nick"] not in self._clients:
            return None, self._serial_function({"response": "ko"})
        self._clients.remove(frame["nick"])
        return None, self._serial_function({"response": "ok"})

    def on_list(self, packet: bytes, frame: dict) -> Tuple[bytes, bytes]:
        return None, self._serial_function({"response": list(self._clients)})

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    server = AEServer(6666, 6667)
    try:
        while True:
            server.update()
    except KeyboardInterrupt:
        server.close()