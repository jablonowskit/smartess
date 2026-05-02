#!/usr/bin/env python3
# Copyright (C) 2025 Tomasz Jablonowski - distributed under the GNU GPL v3 (see LICENSE).
"""
smartess_protocol.py - niskopoziomowe funkcje protokołu SmartESS/Anenji.
Zawiera: CRC16, budowa ramek, parsowanie, UDP notify, TCP accept.
"""

import socket
import struct
import sys
import time
from typing import Optional, List, Tuple, Any


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def resolve_local_ip(localip: Optional[str] = None) -> str:
    """Zwroc podany localip lub wykryj lokalny adres IP."""
    if localip:
        return localip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def crc16_modbus(data: bytes) -> int:
    """Oblicza CRC16/MODBUS."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def send_udp_notify(dev_ip: str, local_ip: str, udp_port: int, tcp_port: int, debug: bool = False) -> None:
    """Wysyła UDP notyfikację do dataloggera (protokół Anenji)."""
    cmd = f"set>server={local_ip}:{tcp_port};"
    if debug:
        print(f"{now_iso()} DEBUG: Sending UDP notification to {dev_ip}:{udp_port}")
        print(f"{now_iso()} DEBUG: Command: {cmd}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(cmd.encode("utf-8"), (dev_ip, udp_port))
        try:
            data, addr = sock.recvfrom(1024)
            if debug:
                print(f"{now_iso()} DEBUG: UDP resp from {addr}: {data!r}")
        except socket.timeout:
            if debug:
                print(f"{now_iso()} DEBUG: UDP: brak odpowiedzi (dozwolone)")
    finally:
        sock.close()


def wait_for_datalogger_connection(listen_host: str, tcp_port: int, timeout: int, debug: bool = False) -> Optional[socket.socket]:
    """Uruchamia TCP serwer i czeka na połączenie od dataloggera."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(timeout)
    try:
        srv.bind((listen_host, tcp_port))
        srv.listen(1)
        if debug:
            print(f"{now_iso()} DEBUG: TCP server listening on {listen_host}:{tcp_port} (Anenji protocol)")
            print(f"{now_iso()} DEBUG: Waiting for datalogger to connect (timeout: {timeout}s)...")
        conn, addr = srv.accept()
        if debug:
            print(f"{now_iso()} DEBUG: Datalogger connected from {addr}")
        return conn
    except socket.timeout:
        print("Blad: timeout oczekiwania na polaczenie TCP od dataloggera.", file=sys.stderr)
        return None
    finally:
        try:
            srv.close()
        except Exception:
            pass


def iter_frames(b: bytearray) -> bytes:
    """Generator pełnych ramek Modbus-TCP z bufora."""
    while True:
        if len(b) < 6:
            return
        length = struct.unpack(">H", b[4:6])[0]
        total = 6 + length
        if len(b) < total:
            return
        frame = bytes(b[:total])
        del b[:total]
        yield frame


def build_tunneled_request(tid: int, base_addr: int, qty: int, debug: bool = False) -> bytes:
    """Buduje tunelowaną ramkę Modbus-TCP (fn=0x03 Read Input Registers)."""
    fn_addr_qty = bytes([0x03]) + struct.pack(">HH", base_addr, qty)
    crc = crc16_modbus(b"\x01" + fn_addr_qty)
    pdu = b"\x04\x01" + fn_addr_qty + struct.pack("<H", crc)
    mbap = struct.pack(">HHHB", tid, 0x0001, len(pdu) + 1, 0xFF)
    frame = mbap + pdu
    if debug:
        print(f"{now_iso()} DEBUG: build_block_frame: TID=0x{tid:04x}, base_addr={base_addr}, qty={qty}")
        print(f"{now_iso()} DEBUG: build_block_frame: fn_addr_qty={fn_addr_qty.hex()}")
        print(f"{now_iso()} DEBUG: build_block_frame: final frame={frame.hex()}")
    return frame


def build_tunneled_write(tid: int, base_addr: int, values: List[int], debug: bool = False) -> bytes:
    """Buduje tunelowaną ramkę Modbus-TCP (fn=0x10 Write Multiple Registers)."""
    qty = len(values)
    byte_count = qty * 2
    data_bytes = b"".join(struct.pack(">H", v & 0xFFFF) for v in values)
    fn_and_rest = bytes([0x10]) + struct.pack(">HHB", base_addr, qty, byte_count) + data_bytes
    crc = crc16_modbus(b"\x01" + fn_and_rest)
    pdu = b"\x04\x01" + fn_and_rest + struct.pack("<H", crc)
    mbap = struct.pack(">HHHB", tid, 0x0001, len(pdu) + 1, 0xFF)
    frame = mbap + pdu
    if debug:
        print(f"{now_iso()} DEBUG: build_tunneled_write: TID=0x{tid:04x}, base_addr={base_addr}, qty={qty}, data={data_bytes.hex()}")
        print(f"{now_iso()} DEBUG: build_tunneled_write: final frame={frame.hex()}")
    return frame


def read_one_modbus_tcp_frame(sock: socket.socket, timeout: float, expect_tid: Optional[int] = None, debug: bool = False) -> Optional[bytes]:
    """Odbiera jedną ramkę Modbus-TCP z socketa."""
    sock.settimeout(0.1)
    deadline = time.time() + timeout
    buf = bytearray()
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                time.sleep(0.05)
                continue
            if debug:
                print(f"{now_iso()} DEBUG: Received {len(chunk)} bytes from logger: {chunk.hex()}")
            buf.extend(chunk)
            for frame in iter_frames(buf):
                tid = struct.unpack(">H", frame[0:2])[0]
                if debug:
                    print(f"{now_iso()} DEBUG: RX frame TID=0x{tid:04X} : {' '.join(f'{x:02X}' for x in frame)}")
                if expect_tid is None or tid == (expect_tid & 0xFFFF):
                    return frame
        except socket.timeout:
            continue
        except Exception as e:
            print(f"Blad odbioru: {e}", file=sys.stderr)
            return None
    return None


def parse_tunneled_response(frame: bytes, debug: bool = False) -> Optional[Tuple[int, Any]]:
    """Parsuje tunelowaną odpowiedź Modbus (fn=0x03 lub fn=0x10)."""
    if len(frame) < 7:
        return None
    tid, pid, length, uid = struct.unpack(">HHHB", frame[:7])
    pdu = frame[7:]
    if not (len(pdu) >= 3 and pdu[0] == 0x04 and pdu[1] == 0x01):
        return None
    fn = pdu[2]

    if fn == 0x03:
        if len(pdu) < 4:
            return None
        byte_count = pdu[3]
        if len(pdu) < 4 + byte_count + 2:
            return None
        data = pdu[4:4 + byte_count]
        regs = []
        for i in range(0, len(data), 2):
            val = (data[i] << 8) | data[i + 1]
            if val >= 32768:
                val -= 65536
            regs.append(val)
        return tid, regs

    if fn == 0x10:
        if len(pdu) < 3 + 4 + 2:
            return None
        addr = struct.unpack(">H", pdu[3:5])[0]
        qty = struct.unpack(">H", pdu[5:7])[0]
        return tid, ("write", addr, qty)

    return None
