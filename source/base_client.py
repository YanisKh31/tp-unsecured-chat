import logging
from typing import Callable

import zmq

class BaseClient:
    def __init__(self, host:str, send_port:int, broadcast_port:int) -> None:
        self._context = zmq.Context()
        self._send_socket = self._context.socket(zmq.REQ)
        self._send_socket.connect(f"tcp://{host}:{send_port}")
        self._broadcast_socket = self._context.socket(zmq.SUB)
        self._broadcast_socket.connect(f"tcp://{host}:{broadcast_port}")
        self._broadcast_socket.setsockopt(zmq.SUBSCRIBE, b"")
        self._log = logging.getLogger("BaseClient")

    def send(self, message:bytes)->bytes:
        self._send_socket.send(message)
        response = self._send_socket.recv()
        self._log.debug(f"Send '{message}', recv '{response}'")
        return response
    
    def update(self, on_recv:Callable):
        try:
            while True:
                broadcast_message = self._broadcast_socket.recv(flags=zmq.NOBLOCK)
                self._log.debug(f"Recv from broadcast '{broadcast_message}'")
                try:
                    on_recv(broadcast_message)
                except Exception as e:
                     self._log.error(f"Exception raised on message '{broadcast_message}' ({e})")
        except zmq.Again as e:
            pass # no message

    def close(self):
        self._log.info("closing socket")
        self._send_socket.close()
        self._broadcast_socket.close()
