from contextlib import contextmanager, ExitStack
from dataclasses import dataclass, field
from getpass import getuser
from os import environ, urandom
from socket import socket, create_connection
from time import sleep
from typing import Callable, Dict
from zlib import decompressobj

import pytest
import numpy as np

from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES, TripleDES
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives.serialization import load_der_public_key

from keysymdef import keysymdef  # type: ignore


# Keyboard keys
key_codes: Dict[str, int] = {}
key_codes.update((name, code) for name, code, char in keysymdef)
key_codes.update((chr(char), code) for name, code, char in keysymdef if char)
key_codes['Del'] = key_codes['Delete']
key_codes['Esc'] = key_codes['Escape']
key_codes['Cmd'] = key_codes['Super_L']
key_codes['Alt'] = key_codes['Alt_L']
key_codes['Ctrl'] = key_codes['Control_L']
key_codes['Super'] = key_codes['Super_L']
key_codes['Shift'] = key_codes['Shift_L']
key_codes['Backspace'] = key_codes['BackSpace']


# Colour channel orders
video_modes: Dict[bytes, str] = {
     b'\x20\x18\x00\x01\x00\xff\x00\xff\x00\xff\x10\x08\x00': 'bgra',
     b'\x20\x18\x00\x01\x00\xff\x00\xff\x00\xff\x00\x08\x10': 'rgba',
     b'\x20\x18\x01\x01\x00\xff\x00\xff\x00\xff\x10\x08\x00': 'argb',
     b'\x20\x18\x01\x01\x00\xff\x00\xff\x00\xff\x00\x08\x10': 'abgr',
}


def read(sock: socket, length: int) -> bytes:
    """
    Read *length* bytes from the given socket.
    """

    data = b''
    while len(data) < length:
        data += sock.recv(length - len(data))
    return data


def read_int(sock: socket, length: int) -> int:
    """
    Read *length* bytes from the given socket and decode as a big-endian integer.
    """

    return int.from_bytes(read(sock, length), 'big')


def pack_ard(data):
    """
    Packs the given credential for use in Apple Remote Desktop authentication.
    """

    data = data.encode('utf-8') + b'\x00'
    if len(data) < 64:
        data += urandom(64 - len(data))
    else:
        data = data[:64]
    return data


def pytest_addoption(parser):
    """
    Adds VNC-related configuration options to the pytest argument parser.
    """

    parser.addini('vnc_host', 'vnc host (default: localhost)')
    parser.addini('vnc_port', 'vnc port (default: 5900)')
    parser.addini('vnc_speed', 'vnc interactions per second (default: 20)')
    parser.addini('vnc_timeout', 'vnc connection timeout in seconds (default: 5)')
    parser.addini('vnc_user', 'vnc username (default: env: PYTEST_VNC_USER or current user)')
    parser.addini('vnc_passwd', 'vnc password (default: env: PYTEST_VNC_PASSWD)')


@pytest.fixture(scope='session')
def vnc(pytestconfig):
    """
    Pytest fixture that evaluates to a :class:`VNCClient` object.
    """

    # Load client config
    host = pytestconfig.getini('vnc_host') or 'localhost'
    port = int(pytestconfig.getini('vnc_port') or '5900')
    speed = float(pytestconfig.getini('vnc_speed') or '20.0')
    timeout = float(pytestconfig.getini('vnc_timeout') or '5.0')
    user = pytestconfig.getini('vnc_user') or environ.get('PYTEST_VNC_USER') or getuser()
    passwd = pytestconfig.getini('vnc_passwd') or environ.get('PYTEST_VNC_PASSWD')

    # Connect and handshake
    sock = create_connection((host, port), timeout)
    intro = read(sock, 12)
    if intro[:4] != b'RFB ':
        raise ValueError('not a VNC server')
    sock.sendall(b'RFB 003.008\n')

    # Negotiate an authentication type
    auth_types = set(read(sock, read_int(sock, 1)))
    for auth_type in (33, 0, 1):
        if auth_type in auth_types:
            sock.sendall(auth_type.to_bytes(1, 'big'))
            break
    else:
        raise ValueError(f'unsupported VNC auth types: {auth_types}')

    # Apple authentication
    if auth_type == 33:
        if not passwd:
            raise ValueError('VNC server requires password')
        sock.sendall(b'\x00\x00\x00\x0a\x01\x00RSA1\x00\x00\x00\x00')
        read(sock, 6)  # padding
        host_key = load_der_public_key(read(sock, read_int(sock, 4)))
        read(sock, 1)  # padding
        aes_key = urandom(16)
        encryptor = Cipher(AES(aes_key), ECB()).encryptor()
        sock.sendall(
            b'\x00\x00\x01\x8a\x01\x00RSA1' +
            b'\x00\x01' + encryptor.update(pack_ard(user) + pack_ard(passwd)) +
            b'\x00\x01' + host_key.encrypt(aes_key, padding=PKCS1v15()))
        read(sock, 4)  # padding

    # VNC authentication
    if auth_type == 1:
        if not passwd:
            raise ValueError('VNC server requires password')
        des_key = passwd.encode('ascii')[:8].ljust(8, b'\x00')
        encryptor = Cipher(TripleDES(des_key * 3), ECB()).encryptor()
        sock.sendall(encryptor.update(read(sock, 16)) + encryptor.finalize())

    # Check auth result
    auth_result = read_int(sock, 4)
    if auth_result == 0:
        pass
    elif auth_result == 1:
        raise PermissionError('VNC auth failed')
    elif auth_result == 2:
        raise PermissionError('VNC auth failed (too many attempts)')
    else:
        reason = read(sock, auth_result)
        raise PermissionError(reason.decode('utf-8'))

    # Read video settings
    sock.sendall(b'\x01')
    width = read_int(sock, 2)
    height = read_int(sock, 2)
    mode = video_modes[read(sock, 13)]
    read(sock, 3)  # padding
    read(sock, read_int(sock, 4))
    decompress = decompressobj().decompress

    # Set encodings
    sock.sendall(b'\x02\x00\x00\x01\x00\x00\x00\x06')
    return VNC(sock, decompress, mode, width, height, speed)


@dataclass
class VNC:
    """
    A VNC client.
    """

    sock: socket = field(repr=False)
    decompress: Callable[[bytes], bytes] = field(repr=False)
    mode: str
    width: int
    height: int
    speed: float
    mouse_x: int = 0
    mouse_y: int = 0
    mouse_buttons: int = 0

    @contextmanager
    def _write_key(self, key: str):
        data = key_codes[key].to_bytes(4, 'big')
        self.sock.sendall(b'\x04\x01\x00\x00' + data)
        sleep(1.0 / self.speed)
        try:
            yield
        finally:
            self.sock.sendall(b'\x04\x00\x00\x00' + data)
            sleep(1.0 / self.speed)

    def _write_mouse(self):
        self.sock.sendall(
            b'\x05' +
            self.mouse_buttons.to_bytes(1, 'big') +
            self.mouse_x.to_bytes(2, 'big') +
            self.mouse_y.to_bytes(2, 'big'))
        sleep(1.0 / self.speed)

    def capture(self, x: int = 0, y: int = 0, width: int = 0, height: int = 0) -> np.ndarray:
        """
        Takes a screenshot and returns its pixels as an RGBA numpy array.
        """

        width = width or (self.width - x)
        height = height or (self.height - y)
        self.sock.sendall(
            b'\x03\x00' +
            x.to_bytes(2, 'big') +
            y.to_bytes(2, 'big') +
            width.to_bytes(2, 'big') +
            height.to_bytes(2, 'big'))
        pixels = np.zeros((self.height, self.width, 4), 'B')
        while True:
            update_type = read_int(self.sock, 1)
            if update_type == 2:  # clipboard
                read(self.sock, read_int(self.sock, 4))
            elif update_type == 0:  # video
                read(self.sock, 1)  # padding
                for _ in range(read_int(self.sock, 2)):
                    area_x = read_int(self.sock, 2)
                    area_y = read_int(self.sock, 2)
                    area_width = read_int(self.sock, 2)
                    area_height = read_int(self.sock, 2)
                    area_encoding = read_int(self.sock, 4)
                    if area_encoding == 0:  # Raw
                        area = read(self.sock, area_height * area_width * 4)
                    elif area_encoding == 6:  # ZLib
                        area = read(self.sock, read_int(self.sock, 4))
                        area = self.decompress(area)
                    else:
                        raise ValueError(f'unsupported VNC encoding: {area_encoding}')
                    area = np.ndarray((area_height, area_width, 4), 'B', area)
                    pixels[area_y:area_y + area_height, area_x:area_x + area_width] = area
                    pixels[area_y:area_y + area_height, area_x:area_x + area_width, self.mode.index('a')] = 255
                area = pixels[y:y+height, x:x+width]
                if area[:, :, self.mode.index('a')].all():
                    if self.mode == 'rgba':
                        return area
                    if self.mode == 'abgr':
                        return area[:, :, ::-1]
                    return np.dstack((
                        area[:, :, self.mode.index('r')],
                        area[:, :, self.mode.index('g')],
                        area[:, :, self.mode.index('b')],
                        area[:, :, self.mode.index('a')]))

    @contextmanager
    def hold(self, *keys: str):
        """
        Context manager that pushes the given keys on enter, and releases them (in reverse order) on exit.
        """

        with ExitStack() as stack:
            for key in keys:
                stack.enter_context(self._write_key(key))
            yield

    def press(self, *keys: str):
        """
        Pushes all the given keys, and then releases them in reverse order.
        """

        with self.hold(*keys):
            pass

    def write(self, text: str):
        """
        Pushes and releases each of the given keys, one after the other.
        """

        for key in text:
            with self.hold(key):
                pass

    @contextmanager
    def drag(self, button: int = 0):
        """
        Context manager that presses a mouse button on enter, and releases it on exit.
        """

        mask = 1 << button
        self.mouse_buttons |= mask
        self._write_mouse()
        try:
            yield
        finally:
            self.mouse_buttons &= ~mask
            self._write_mouse()

    @contextmanager
    def middle_drag(self):
        """
        Context manager that presses the middle mouse button on enter, and releases it on exit.
        """

        with self.drag(1):
            yield

    @contextmanager
    def right_drag(self):
        """
        Context manager that presses the right mouse button on enter, and releases it on exit.
        """

        with self.drag(2):
            yield

    def click(self, button: int = 0):
        """
        Presses and releases a mouse button.
        """

        with self.drag(button):
            pass

    def double_click(self, button: int = 0):
        """
        Presses and releases a mouse button twice.
        """

        self.click(button)
        self.click(button)

    def middle_click(self):
        """
        Presses and releases the middle mouse button.
        """

        self.click(1)

    def right_click(self):
        """
        Presses and releases the right mouse button.
        """

        self.click(2)

    def scroll_up(self, repeat: int = 1):
        """
        Scrolls the mouse wheel upwards.
        """

        for _ in range(repeat):
            self.click(3)

    def scroll_down(self, repeat: int = 1):
        """
        Scrolls the mouse wheel downwards.
        """

        for _ in range(repeat):
            self.click(4)

    def move(self, x: int, y: int):
        """
        Moves the mouse cursor to the given co-ordinates.
        """

        self.mouse_x = x
        self.mouse_y = y
        self._write_mouse()
