import pickle
from typing import Tuple
import logging

from base_server import BaseServer

class SimpleServer:
    def __init__(self, recv_port: int, broadcast_port: int) -> None:
        self._server = BaseServer(recv_port, broadcast_port)
        self._log = logging.getLogger(self.__class__.__name__)
        self._clients = set()
        # can be overrided
        # serial : expect a direct, return bytes
        self._serial_function = pickle.dumps
        # deserial : expect bytes, return dict
        self._deserial_function = pickle.loads

    def update(self):
        self._server.update(self.on_recv)

    def on_recv(self, packet: bytes) -> Tuple[bytes, bytes]:
        callbacks = {
            "join" : self.on_join,
            "leave" : self.on_leave,
            "message" : self.on_message,
            "list": self.on_list
        }
        frame = self._deserial_function(packet)
        return callbacks[frame["type"]](packet, frame)
        
    def on_join(self, packet:bytes, frame: dict) -> Tuple[bytes, bytes]:
        if frame["nick"] in self._clients:
            self._log.error(f"Client '{frame['nick']}' is already joined")
            return None, self._serial_function({"response": "ko"})
        else:
            self._clients.add(frame["nick"])
            self._log.info(f"Client '{frame['nick']}' join")
            return None, self._serial_function({"response": "ok"})

    def on_leave(self, packet:bytes, frame: dict) -> Tuple[bytes, bytes]:
        if frame["nick"] not in self._clients:
            self._log.error(f"Client '{frame['nick']}' doesn't joined")
            return None, self._serial_function({"response": "ko"})
        else:
            self._clients.remove(frame["nick"])
            self._log.info(f"Client '{frame['nick']}' left")
            return None, self._serial_function({"response": "ok"})

    def on_message(self, packet:bytes, frame: dict) -> Tuple[bytes, bytes]:
        if frame["nick"] not in self._clients:
            self._log.error(f"Client '{frame['nick']}' didn't join, can't send message")
            return None, self._serial_function({"response": "ko"})
        else:
            self._log.info(f"Client '{frame['nick']}' sent message '{frame['message']}'")
            return packet, self._serial_function({"response": "ok"})
        
    def on_list(self, packet: bytes, frame: dict) -> Tuple[bytes, bytes]:
        self._log.info(f"List requested")
        return None, self._serial_function({"response": list(self._clients)})

    def close(self):
        self._server.close()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    server = SimpleServer(6666, 6667)

    try:
        while True:
            server.update()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()