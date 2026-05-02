#!/usr/bin/env python3
# Copyright (C) 2025 Tomasz Jablonowski - distributed under the GNU GPL v3 (see LICENSE).
"""
smartess_client.py - klient do odczytu/zapisu rejestrow z dataloggera SmartESS.
Uzycie:
  python smartess_client.py <IP_DATALOGGERA> <REGISTER> [--count N] [--localip X.X.X.X] [--tcp-port 502] [--udp-port 58899] [--debug]
  python smartess_client.py <IP_DATALOGGERA> <REGISTER> --set "100,200" [--localip X.X.X.X] [--tcp-port 502] [--udp-port 58899] [--debug]
"""

import argparse
import socket
import sys
import time
import json
from typing import Optional, Union, List

from smartess_protocol import (
    now_iso,
    resolve_local_ip,
    send_udp_notify,
    wait_for_datalogger_connection,
    build_tunneled_request,
    build_tunneled_write,
    read_one_modbus_tcp_frame,
    parse_tunneled_response,
)

__version__ = "1.1.1"

# ----- konfiguracja TID (jak w data_logger_v2) -----
NEXT_TID = 0x8000


def next_tid() -> int:
    global NEXT_TID
    tid = NEXT_TID
    NEXT_TID = (NEXT_TID + 1) & 0xFFFF
    if NEXT_TID == 0:
        NEXT_TID = 1
    return tid


class SmartESSSession:
    """Sesja TCP z dataloggerem utrzymywana do jawnego close()."""

    def __init__(
        self,
        ip: str,
        localip: Optional[str] = None,
        tcp_port: int = 502,
        udp_port: int = 58899,
        debug: bool = False,
        connect_timeout: int = 30,
        io_timeout: float = 3.0,
    ):
        self.ip = ip
        self.localip = resolve_local_ip(localip)
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.debug = debug
        self.connect_timeout = connect_timeout
        self.io_timeout = io_timeout
        self.conn: Optional[socket.socket] = None

    @property
    def is_connected(self) -> bool:
        return self.conn is not None

    def connect(self) -> None:
        if self.conn is not None:
            return
        send_udp_notify(self.ip, self.localip, udp_port=self.udp_port, tcp_port=self.tcp_port, debug=self.debug)
        conn = wait_for_datalogger_connection("0.0.0.0", tcp_port=self.tcp_port, timeout=self.connect_timeout, debug=self.debug)
        if not conn:
            raise RuntimeError("Timeout oczekiwania na polaczenie TCP od dataloggera")
        self.conn = conn
        time.sleep(0.2)

    def close(self) -> None:
        if self.conn is None:
            return
        try:
            self.conn.close()
        finally:
            self.conn = None

    def _send_and_parse(self, frame: bytes, tid_used: int) -> Union[List[int], tuple]:
        if self.conn is None:
            raise RuntimeError("Sesja nie jest polaczona")
        try:
            self.conn.sendall(frame)
            rx = read_one_modbus_tcp_frame(self.conn, timeout=self.io_timeout, expect_tid=tid_used, debug=self.debug)
            if not rx:
                raise RuntimeError("Brak odpowiedzi od dataloggera")
            parsed = parse_tunneled_response(rx, debug=self.debug)
            if not parsed:
                raise RuntimeError("Nie udalo sie sparsowac odpowiedzi")
            _, payload = parsed
            return payload
        except Exception:
            self.close()
            raise

    def read(self, register: int, count: int = 1, tid: Optional[int] = None) -> str:
        self.connect()
        tid_used = tid if tid is not None else next_tid()
        frame = build_tunneled_request(tid_used, register, count, debug=self.debug)
        if self.debug:
            print(f"{now_iso()} DEBUG: Sending frame: TID=0x{tid_used:04x}, base={register}, qty={count}")
            pdu = frame[7:]
            print(f"{now_iso()} DEBUG: PDU={pdu.hex()}, len={len(pdu)}, pdu[0]=0x{pdu[0]:02x}, pdu[1]=0x{pdu[1]:02x}")
            if len(pdu) >= 3 and pdu[0] == 0x04 and pdu[1] == 0x01:
                print(f"{now_iso()} DEBUG: Matched tunneled RTU")
                print(f"{now_iso()} DEBUG: Tunneled RTU fn=0x{pdu[2]:02x}")
        regs = self._send_and_parse(frame, tid_used)
        if not isinstance(regs, list):
            raise RuntimeError("Otrzymano nieoczekiwana odpowiedz read")
        ts = now_iso()
        out = {"ts": ts}
        out.update({str(register + i): regs[i] for i in range(len(regs))})
        return json.dumps(out, ensure_ascii=False)

    def write(self, register: int, values: List[int], tid: Optional[int] = None) -> str:
        self.connect()
        tid_used = tid if tid is not None else next_tid()
        frame = build_tunneled_write(tid_used, register, values, debug=self.debug)
        if self.debug:
            print(f"{now_iso()} DEBUG: Sending WRITE frame: TID=0x{tid_used:04x}, base={register}, values={values}")
        info = self._send_and_parse(frame, tid_used)
        if not (isinstance(info, tuple) and info[0] == "write"):
            raise RuntimeError("Otrzymano nieoczekiwana odpowiedz write")
        _, addr, qty = info
        ts = now_iso()
        out = {"ts": ts, "written_base": addr, "written_qty": qty, "values": values}
        return json.dumps(out, ensure_ascii=False)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


def smartess_open_session(
    ip: str,
    localip: Optional[str] = None,
    tcp_port: int = 502,
    udp_port: int = 58899,
    debug: bool = False,
    connect_timeout: int = 30,
    io_timeout: float = 3.0,
) -> SmartESSSession:
    """Utworz i polacz sesje utrzymywana do jawnego close()."""
    session = SmartESSSession(
        ip=ip,
        localip=localip,
        tcp_port=tcp_port,
        udp_port=udp_port,
        debug=debug,
        connect_timeout=connect_timeout,
        io_timeout=io_timeout,
    )
    session.connect()
    return session


def smartess_read(
    ip: str,
    register: int,
    count: int = 1,
    localip: Optional[str] = None,
    tcp_port: int = 502,
    udp_port: int = 58899,
    debug: bool = False,
    tid: Optional[int] = None,
    session: Optional[SmartESSSession] = None,
) -> str:
    """Backward-compatible read. Opcjonalnie uzywa utrzymywanej sesji."""
    if session is not None:
        return session.read(register=register, count=count, tid=tid)
    with SmartESSSession(ip=ip, localip=localip, tcp_port=tcp_port, udp_port=udp_port, debug=debug) as sess:
        return sess.read(register=register, count=count, tid=tid)


def smartess_write(
    ip: str,
    register: int,
    values: List[int],
    localip: Optional[str] = None,
    tcp_port: int = 502,
    udp_port: int = 58899,
    debug: bool = False,
    tid: Optional[int] = None,
    session: Optional[SmartESSSession] = None,
) -> str:
    """Backward-compatible write. Opcjonalnie uzywa utrzymywanej sesji."""
    if session is not None:
        return session.write(register=register, values=values, tid=tid)
    with SmartESSSession(ip=ip, localip=localip, tcp_port=tcp_port, udp_port=udp_port, debug=debug) as sess:
        return sess.write(register=register, values=values, tid=tid)


# ----- CLI -----
def main():
    ap = argparse.ArgumentParser(description="Minimalny klient SmartESS (tunel Modbus w TCP).")
    ap.add_argument("ip", help="Adres IP dataloggera SmartESS")
    ap.add_argument("register", type=int, help="Adres startowy rejestru")
    ap.add_argument("--count", type=int, default=1, help="Liczba rejestrow (domyslnie 1)")
    ap.add_argument("--localip", help="Lokalny IP (autodetekcja jesli brak)")
    ap.add_argument("--tcp-port", type=int, default=502, help="Port TCP Anenji (domyslnie 502)")
    ap.add_argument("--udp-port", type=int, default=58899, help="Port UDP Anenji (domyslnie 58899)")
    ap.add_argument("--debug", action="store_true", help="Debug")
    ap.add_argument("--set", metavar="VALUES", help='Wykonaj zapis (Write Multiple Registers). Wartosci do zapisu przecinkami, np. "100,200"')
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args()

    try:
        if args.set is not None:
            if args.set.strip() == "":
                ap.error('Przy zapisie wymagane wartosci, np. --set "100,200"')
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
                ap.error('Przy zapisie wymagane wartosci, np. --set "100,200"')
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
        print(f"Blad: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()