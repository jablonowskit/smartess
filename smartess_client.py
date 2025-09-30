#!/usr/bin/env python3
# Copyright (C) 2025 Tomasz Jabłonowski — distributed under the GNU GPL v3 (see LICENSE).
"""
smartess_client.py — minimalny klient do odczytu rejestrów z dataloggera SmartESS.
Użycie:
  python smartess_client.py <IP_DATALOGGERA> <REGISTER> [--count N] [--localip X.X.X.X] [--tcp-port 502] [--debug]
"""
 
import argparse
import socket
import struct
import sys
import time
import json
from typing import Optional, Union, List
 
__version__ = "1.0.0"
 
# ───── konfiguracja TID (jak w data_logger_v2) ─────
NEXT_TID = 0x8000
def next_tid():
    global NEXT_TID
    tid = NEXT_TID
    NEXT_TID = (NEXT_TID + 1) & 0xFFFF
    if NEXT_TID == 0:
        NEXT_TID = 1
    return tid
 
def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S")
 
# ───── CRC16/MODBUS ─────
def crc16_modbus(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if (crc & 1):
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF
 
# ───── UDP notify (Anenji) ─────
def send_udp_notify(dev_ip: str, local_ip: str, udp_port: int, tcp_port: int, debug: bool = False) -> None:
    cmd = f"set>server={local_ip}:{tcp_port};"
    if debug:
        print(f"{now_iso()} DEBUG: Sending UDP notification to {dev_ip}:{udp_port}")
        print(f"{now_iso()} DEBUG: Command: {cmd}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(cmd.encode('utf-8'), (dev_ip, udp_port))
        try:
            data, addr = sock.recvfrom(1024)
            if debug:
                print(f"{now_iso()} DEBUG: UDP resp from {addr}: {data!r}")
        except socket.timeout:
            if debug:
                print(f"{now_iso()} DEBUG: UDP: brak odpowiedzi (dozwolone)")
    finally:
        sock.close()
 
# ───── TCP accept z timeoutem ─────
def wait_for_datalogger_connection(listen_host: str, tcp_port: int, timeout: int, debug: bool = False):
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
        print("Błąd: timeout oczekiwania na połączenie TCP od dataloggera.", file=sys.stderr)
        return None
    finally:
        try:
            srv.close()
        except Exception:
            pass
 
# ───── generator pełnych ramek (jak w data_logger_v2) ─────
def iter_frames(b: bytearray):
    while True:
        if len(b) < 6:
            return
        length = struct.unpack(">H", b[4:6])[0]
        total  = 6 + length
        if len(b) < total:
            return
        frame = bytes(b[:total])
        del b[:total]
        yield frame
 
# ───── budowa tunelowanej ramki (PID=1, UID=0xFF, fn=3) ─────
def build_tunneled_request(tid: int, base_addr: int, qty: int, debug: bool = False) -> bytes:
    fn_addr_qty = bytes([0x03]) + struct.pack(">HH", base_addr, qty)
    crc = crc16_modbus(b"\x01" + fn_addr_qty)           # CRC po unit(0x01)+fn+addr+qty
    pdu = b"\x04\x01" + fn_addr_qty + struct.pack("<H", crc)
    mbap = struct.pack(">HHHB", tid, 0x0001, len(pdu) + 1, 0xFF)
    frame = mbap + pdu
    if debug:
        print(f"{now_iso()} DEBUG: build_block_frame: TID=0x{tid:04x}, base_addr={base_addr}, qty={qty}")
        print(f"{now_iso()} DEBUG: build_block_frame: fn_addr_qty={fn_addr_qty.hex()}")
        print(f"{now_iso()} DEBUG: build_block_frame: final frame={frame.hex()}")
    return frame
 
# ───── budowa tunelowanej ramki WRITE MULTIPLE REGISTERS (fn=0x10) ─────
def build_tunneled_write(tid: int, base_addr: int, values: List[int], debug: bool = False) -> bytes:
    qty = len(values)
    byte_count = qty * 2
    data_bytes = b"".join(struct.pack(">H", v & 0xFFFF) for v in values)
    fn_and_rest = bytes([0x10]) + struct.pack(">HHB", base_addr, qty, byte_count) + data_bytes
    crc = crc16_modbus(b"\x01" + fn_and_rest)  # CRC over unit(0x01)+fn+addr+qty+bytecount+data
    pdu = b"\x04\x01" + fn_and_rest + struct.pack("<H", crc)
    mbap = struct.pack(">HHHB", tid, 0x0001, len(pdu) + 1, 0xFF)
    frame = mbap + pdu
    if debug:
        print(f"{now_iso()} DEBUG: build_tunneled_write: TID=0x{tid:04x}, base_addr={base_addr}, qty={qty}, data={data_bytes.hex()}")
        print(f"{now_iso()} DEBUG: build_tunneled_write: final frame={frame.hex()}")
    return frame
 
# ───── odbiór jednej ramki (jak w data_logger_v2) ─────
def read_one_modbus_tcp_frame(sock: socket.socket, timeout: float, expect_tid: Optional[int] = None, debug: bool = False):
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
                    # hexdump w stylu data_logger_v2
                    print(f"{now_iso()} DEBUG: RX frame TID=0x{tid:04X} : {' '.join(f'{x:02X}' for x in frame)}")
                if expect_tid is None or tid == (expect_tid & 0xFFFF):
                    return frame
        except socket.timeout:
            continue
        except Exception as e:
            print(f"Błąd odbioru: {e}", file=sys.stderr)
            return None
    return None
 
# ───── minimalny parse tunelu 04 01, fn=3 oraz fn=0x10 (write) ─────
def parse_tunneled_response(frame: bytes, debug: bool = False):
    if len(frame) < 7:
        return None
    tid, pid, length, uid = struct.unpack(">HHHB", frame[:7])
    pdu = frame[7:]
    if not (len(pdu) >= 3 and pdu[0] == 0x04 and pdu[1] == 0x01):
        return None
    fn = pdu[2]
    # Read response (fn=3) -> bytecount + data + CRC
    if fn == 0x03:
        if len(pdu) < 4:
            return None
        byte_count = pdu[3]
        if len(pdu) < 4 + byte_count + 2:  # wymagamy pełnej długości z CRC
            return None
        data = pdu[4:4 + byte_count]
        regs = []
        for i in range(0, len(data), 2):
            val = (data[i] << 8) | data[i + 1]
            if val >= 32768:
                val -= 65536
            regs.append(val)
        return tid, regs
    # Write Multiple Registers response (fn=0x10) -> addr(2) + qty(2) + CRC(2)
    elif fn == 0x10:
        if len(pdu) < 3 + 4 + 2:
            return None
        addr = struct.unpack(">H", pdu[3:5])[0]
        qty = struct.unpack(">H", pdu[5:7])[0]
        return tid, ("write", addr, qty)
    else:
        return None
 
def smartess_read(ip, register, count=1, localip=None, tcp_port=502, udp_port=58899, debug=False, tid=None):
    # ustal lokalny IP jeśli nie podano
    if not localip:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            localip = s.getsockname()[0]
        except Exception:
            localip = '127.0.0.1'
        finally:
            s.close()
 
    # 1) UDP notify
    send_udp_notify(ip, localip, udp_port=udp_port, tcp_port=tcp_port, debug=debug)
 
    # 2) TCP accept
    conn = wait_for_datalogger_connection("0.0.0.0", tcp_port=tcp_port, timeout=30, debug=debug)
    if not conn:
        raise RuntimeError("Timeout oczekiwania na połączenie TCP od dataloggera")
 
    try:
        time.sleep(0.2)  # krótka pauza jak w v2
        tid_used = tid if tid is not None else next_tid()
 
        # 3) zbuduj i wyślij ramkę (tunel 04 01, fn=3)
        frame = build_tunneled_request(tid_used, register, count, debug=debug)
        if debug:
            print(f"{now_iso()} DEBUG: Sending frame: TID=0x{tid_used:04x}, base={register}, qty={count}")
            pdu = frame[7:]
            print(f"{now_iso()} DEBUG: PDU={pdu.hex()}, len={len(pdu)}, pdu[0]=0x{pdu[0]:02x}, pdu[1]=0x{pdu[1]:02x}")
            if len(pdu) >= 3 and pdu[0] == 0x04 and pdu[1] == 0x01:
                print(f"{now_iso()} DEBUG: Matched tunneled RTU")
                print(f"{now_iso()} DEBUG: Tunneled RTU fn=0x{pdu[2]:02x}")
        conn.sendall(frame)
 
        # 4) odbierz (limit 3 s – jak w v2)
        rx = read_one_modbus_tcp_frame(conn, timeout=3.0, expect_tid=tid_used, debug=debug)
        if not rx:
            raise RuntimeError("Brak odpowiedzi od dataloggera")
 
        # 5) parse
        parsed = parse_tunneled_response(rx, debug=debug)
        if not parsed:
            raise RuntimeError("Nie udało się sparsować odpowiedzi")
        _, regs = parsed
 
        # Format JSON z timestampem
        ts = now_iso()
        out = {"ts": ts}
        out.update({str(register + i): regs[i] for i in range(len(regs))})
        return json.dumps(out, ensure_ascii=False)
 
    finally:
        try:
            conn.close()
        except Exception:
            pass
 
# ───── funkcja zapisu (write multiple registers) ─────
def smartess_write(ip, register, values: List[int], localip=None, tcp_port=502, udp_port=58899, debug=False, tid=None):
    if not localip:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            localip = s.getsockname()[0]
        except Exception:
            localip = '127.0.0.1'
        finally:
            s.close()
 
    send_udp_notify(ip, localip, udp_port=udp_port, tcp_port=tcp_port, debug=debug)
    conn = wait_for_datalogger_connection("0.0.0.0", tcp_port=tcp_port, timeout=30, debug=debug)
    if not conn:
        raise RuntimeError("Timeout oczekiwania na połączenie TCP od dataloggera")
    try:
        time.sleep(0.2)
        tid_used = tid if tid is not None else next_tid()
        frame = build_tunneled_write(tid_used, register, values, debug=debug)
        if debug:
            print(f"{now_iso()} DEBUG: Sending WRITE frame: TID=0x{tid_used:04x}, base={register}, values={values}")
        conn.sendall(frame)
        rx = read_one_modbus_tcp_frame(conn, timeout=3.0, expect_tid=tid_used, debug=debug)
        if not rx:
            raise RuntimeError("Brak odpowiedzi od dataloggera (write)")
        parsed = parse_tunneled_response(rx, debug=debug)
        if not parsed:
            raise RuntimeError("Nie udało się sparsować odpowiedzi write")
        _, info = parsed
        if not (isinstance(info, tuple) and info[0] == "write"):
            raise RuntimeError("Otrzymano nieoczekiwaną odpowiedź write")
        _, addr, qty = info
        ts = now_iso()
        out = {"ts": ts, "written_base": addr, "written_qty": qty, "values": values}
        return json.dumps(out, ensure_ascii=False)
    finally:
        try:
            conn.close()
        except Exception:
            pass
 
# ───── CLI ─────
def main():
    ap = argparse.ArgumentParser(description="Minimalny klient SmartESS (tunel Modbus w TCP).")
    ap.add_argument("ip", help="Adres IP dataloggera SmartESS")
    ap.add_argument("register", type=int, help="Adres startowy rejestru")
    ap.add_argument("--count", type=int, default=1, help="Liczba rejestrów (domyślnie 1)")
    ap.add_argument("--localip", help="Lokalny IP (autodetekcja jeśli brak)")
    ap.add_argument("--tcp-port", type=int, default=502, help="Port TCP Anenji (domyślnie 502)")
    ap.add_argument("--udp-port", type=int, default=58899, help="Port UDP Anenji (domyślnie 58899)")
    ap.add_argument("--debug", action="store_true", help="Debug")
    ap.add_argument("--set", metavar="VALUES", help='Wykonaj zapis (Write Multiple Registers). Wartości do zapisu przecinkami, np. "100,200"')
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args()
 
    try:
        if args.set is not None:
            if args.set.strip() == "":
                ap.error('Przy zapisie wymagane wartości, np. --set "100,200"')
            vals = []
            for s in args.set.split(","):
                s = s.strip()
                if not s:
                    continue
                if s.startswith("0x") or s.startswith("0X"):
                    vals.append(int(s, 16))
                else:
                    vals.append(int(s, 10))
            if not vals:
                ap.error('Przy zapisie wymagane wartości, np. --set "100,200"')
            res_json = smartess_write(
                ip=args.ip,
                register=args.register,
                values=vals,
                localip=args.localip,
                tcp_port=args.tcp_port,
                udp_port=args.udp_port,
                debug=args.debug,
            )
        else:
            res_json = smartess_read(
                ip=args.ip,
                register=args.register,
                count=args.count,
                localip=args.localip,
                tcp_port=args.tcp_port,
                udp_port=args.udp_port,
                debug=args.debug,
            )
        print(res_json)
    except Exception as e:
        print(f"Błąd: {e}", file=sys.stderr)
        sys.exit(1)
 
if __name__ == "__main__":
    main()
