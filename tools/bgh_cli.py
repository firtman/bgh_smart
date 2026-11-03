#!/usr/bin/env python3
"""Cliente de línea de comandos para aires BGH Smart por UDP local, sin Home Assistant.

Sirve para probar un equipo o automatizarlo desde un script. Solo usa la librería estándar.

  bgh_cli.py --ip 192.168.1.50 status      # o con BGH_IP definida: bgh_cli.py status
  bgh_cli.py --ip 192.168.1.50 on [cool|heat|dry|fan|auto]   # no cambia temperatura ni ventilador
  bgh_cli.py --ip 192.168.1.50 off
  bgh_cli.py --ip 192.168.1.50 set cool 24 [low|medium|high]

La IP y el MAC también se pueden dar con las variables de entorno BGH_IP y BGH_MAC, para no repetirlos:
  export BGH_IP=192.168.1.50

El MAC del equipo (Device ID) se toma del primer broadcast de estado. Si no llegan broadcasts
(firewall, Docker en red bridge), pasalo con --mac aa:bb:cc:dd:ee:ff o BGH_MAC.

`status` necesita recibir broadcasts UDP en el puerto 20911. `on`, `off` y `set` solo envían un
UDP unicast al puerto 20910, así que funcionan también sin recibir broadcasts (con --mac).
"""
import argparse
import os
import select
import socket
import struct
import sys
import time

PORT_CMD, PORT_BCAST = 20910, 20911
CMD_SET_MODE, CMD_STATUS_REQUEST, CMD_STATUS = 97, 0xE4, 0xFD
MODES = {"off": 0, "cool": 1, "heat": 2, "dry": 3, "fan": 4, "auto": 254}
FANS = {"low": 1, "medium": 2, "high": 3}
# Ventilador, flags y temperatura "sin cambios": lo que manda la app oficial (ver docs/)
KEEP = bytes([255, 255, 0x00, 0x80])


def udp_send(ip, packet):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(packet, (ip, PORT_CMD))


def wait_status(ip, mac, timeout):
    """Devuelve (mac, estado) del primer broadcast de estado de `ip`, o None si no llega ninguno."""
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    rx.bind(("", PORT_BCAST))
    # El pedido de estado va dirigido al MAC del equipo (o ff:ff:ff:ff:ff:ff si no se conoce)
    udp_send(ip, bytes(7) + (mac or b"\xff" * 6) + bytes([0x59, 0x00, 0x01, CMD_STATUS_REQUEST]))
    end = time.time() + timeout
    try:
        while time.time() < end:
            if not select.select([rx], [], [], 1)[0]:
                continue
            d, (addr, _) = rx.recvfrom(2048)
            if addr == ip and len(d) == 29 and d[16] == CMD_STATUS:
                cur, tgt = struct.unpack("<HH", d[21:25])
                return d[1:7], {"mode": d[18], "fan": d[19], "current": cur / 100, "target": tgt / 100}
    finally:
        rx.close()
    return None


def send_set_mode(ip, mac, payload):
    # Cabecera: versión, MAC origen (ceros), MAC destino, secuencia, ep origen, ep destino (1), comando
    udp_send(ip, bytes(7) + mac + bytes([1, 0, 1, CMD_SET_MODE]) + payload)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ip", default=os.environ.get("BGH_IP"), help="IP del aire (o variable BGH_IP)")
    p.add_argument("--mac", default=os.environ.get("BGH_MAC"), help="MAC del aire (o variable BGH_MAC); necesario si no llegan broadcasts")
    p.add_argument("--timeout", type=int, default=20, help="segundos esperando el broadcast (default 20)")
    p.add_argument("command", choices=["status", "on", "off", "set"])
    p.add_argument("args", nargs="*", help="on: [modo]   set: <modo> <temp> [ventilador]")
    a = p.parse_args()

    if not a.ip:
        p.error("falta la IP del aire: --ip o variable BGH_IP")
    try:
        mac = bytes.fromhex(a.mac.replace(":", "")) if a.mac else None
    except ValueError:
        mac = b""
    if mac is not None and len(mac) != 6:
        p.error("--mac tiene que tener 6 bytes hexadecimales (aa:bb:cc:dd:ee:ff)")

    if a.command == "status":
        found = wait_status(a.ip, mac, a.timeout)
        if not found:
            sys.exit(f"sin broadcast de {a.ip} en {a.timeout} s: revisá firewall/Docker (puerto UDP {PORT_BCAST})")
        print(f"mac={found[0].hex(':')} {found[1]}")
        return

    if a.command == "off":
        payload = bytes([0]) + KEEP
    elif a.command == "on":
        mode = a.args[0] if a.args else "cool"
        if mode not in MODES or mode == "off" or len(a.args) > 1:
            p.error("on [cool|heat|dry|fan|auto]")
        payload = bytes([MODES[mode]]) + KEEP
    else:
        if len(a.args) not in (2, 3) or a.args[0] not in MODES or a.args[0] == "off" \
                or (len(a.args) == 3 and a.args[2] not in FANS):
            p.error("set <cool|heat|dry|fan|auto> <16-30> [low|medium|high]")
        temp = float(a.args[1])
        if not 16 <= temp <= 30:
            p.error("la temperatura tiene que estar entre 16 y 30")
        raw = int(round(temp * 100))
        fan = FANS[a.args[2]] if len(a.args) == 3 else 255  # 255 = no cambiar
        payload = bytes([MODES[a.args[0]], fan, 0, raw & 0xFF, raw >> 8])

    if not mac:
        found = wait_status(a.ip, None, a.timeout)
        if not found:
            sys.exit("no pude obtener el MAC del aire (no llegan broadcasts): pasalo con --mac")
        mac = found[0]
    send_set_mode(a.ip, mac, payload)
    print("enviado")


if __name__ == "__main__":
    main()
