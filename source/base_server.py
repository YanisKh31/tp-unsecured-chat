import logging
from typing import Tuple, Callable

import zmq

class BaseServer:
    def __init__(self, recv_port:int, broadcast_port:int) -> None:
        self._context = zmq.Context()
        self._incoming_socket = self._context.socket(zmq.REP)
        self._incoming_socket.bind(f"tcp://*:{recv_port}")
        self._broadcast_socket = self._context.socket(zmq.PUB)
        self._broadcast_socket.bind(f"tcp://*:{broadcast_port}")
        self._log = logging.getLogger("BaseServer")

    def update(self, on_recv:Callable[[bytes], Tuple[bytes, bytes]]):
        try:
            while True:
                message = self._incoming_socket.recv(flags=zmq.NOBLOCK)
                try:
                    broadcast, return_value = on_recv(message)
                except Exception as e:
                    self._log.error(f"Exception raised on message '{message}' ({e})")
                    broadcast, return_value = None, b""
                
                self._log.debug(f"Recv '{message}', send '{return_value}', broadcast '{broadcast}'")
                self._incoming_socket.send(return_value)
                if broadcast:
                    self._broadcast_socket.send(broadcast)
        except zmq.Again as e:
            pass # no message

    def close(self):
        self._log.info("closing socket")
        self._incoming_socket.close()
        self._broadcast_socket.close()
