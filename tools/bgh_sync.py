#!/usr/bin/env python3
"""Configuración completa de un BGH Smart Control Kit (HPA-4911) sin la app.

Reproduce el asistente de la app oficial (ConfigureDeviceViewModelHPA4911) en la red local:
  1. Detecta el kit (IP y MAC) por sus broadcasts
  2. Detiene Home Assistant para liberar el puerto UDP 20911 (y lo vuelve a iniciar al final)
  3. Custom 90 [1]            -> modo aprendizaje
  4. Custom 92 [30]           -> verifica la unidad IR (señal, batería, MAC)
  5. Custom 95 (del kit)      -> codec del control remoto, apretando ENCENDIDO dos veces
  6. Custom 88 [codec, 0]     -> fija el codec
  7. SetMode cada 3 s         -> el aire tiene que hacer "beep"
  8. Custom 88 [codec, sensor] + Custom 100 -> guarda la configuración
  9. Custom 90 [0]            -> sale del modo aprendizaje
 10. Prueba final: enciende y apaga el aire

Uso (en la Raspberry, como root o con sudo):
  sudo python3 bgh_sync.py                  # busca los kits de la red y pregunta cuál
  sudo python3 bgh_sync.py 10.0.0.12        # kit puntual
  sudo python3 bgh_sync.py 10.0.0.12 --codec 60   # saltea la lectura del control
  sudo python3 bgh_sync.py 10.0.0.12 --listen     # solo muestra lo que emite el kit

Los mensajes de diagnóstico del kit se guardan en bgh_sync.log (o se ven en pantalla con --debug).
"""
import argparse
import datetime
import select
import shutil
import socket
import subprocess
import sys
import threading
import time

PORT_DEVICE = 20910
PORT_BROADCAST = 20911

CMD_ACK = 128
CMD_NAK = 129
CMD_CUSTOM = 162
CMD_SET_MODE = 97
CMD_DEBUG = 245

CUSTOM_LEARN_MODE = 90
CUSTOM_GET_STATUS = 92
CUSTOM_LEARN_DATA = 95
CUSTOM_SET_CODEC = 88
CUSTOM_STORE = 100

MODE_OFF, MODE_COOL = 0, 1
FAN_MEDIUM = 2

# Codecs "no toggle": con el aire en otro tomacorriente la app manda sensor 0
NOT_TOGGLE = {1, 10, 12, 13, 20, 30, 50, 51, 71, 80, 90, 100, 111, 130, 140, 150}

LOG_FILE = "bgh_sync.log"

_seq = 0


def next_seq():
    global _seq
    _seq = (_seq + 1) % 256
    return _seq


def build(dst_mac, seq, cmd_id, payload=b"", dst_endpoint=0):
    return bytes([0]) + bytes(6) + dst_mac + bytes([seq, 0, dst_endpoint, cmd_id]) + payload


# Resultado de un comando: el kit lo aceptó, lo rechazó o no contestó
ACK, NAK, TIMEOUT = "ACK", "NAK", "TIMEOUT"


class Cancelled(Exception):
    """El usuario canceló el asistente o un paso necesario no se pudo confirmar."""


def codec_arg(text):
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{text}' no es un número")
    if not 0 <= value <= 255:
        raise argparse.ArgumentTypeError(f"el codec tiene que estar entre 0 y 255 (recibí {value})")
    return value


def say(msg=""):
    print(msg, flush=True)


def ask(msg, options=None):
    while True:
        r = input(msg).strip().lower()
        if options is None or r in options:
            return r
        say(f"  Respondé {' / '.join(sorted(options))}")


def open_broadcast_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(("0.0.0.0", PORT_BROADCAST))
    return s


class Kit:
    def __init__(self, ip, mac, rx, debug=False):
        self.ip = ip
        self.mac = mac
        self.rx = rx
        self.debug = debug
        self.log = open(LOG_FILE, "a", encoding="utf-8")
        self.log.write(f"\n===== {datetime.datetime.now():%Y-%m-%d %H:%M:%S}  kit {ip} =====\n")
        self.tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tx.bind(("0.0.0.0", 0))
        self.codecs = []
        self.lock = threading.Lock()
        threading.Thread(target=self._listen, daemon=True).start()

    def _note(self, text):
        self.log.write(f"{datetime.datetime.now():%H:%M:%S} {text}\n")
        self.log.flush()
        if self.debug:
            say(f"  [kit] {text}")

    def _listen(self):
        last = None
        while True:
            data, (addr, _) = self.rx.recvfrom(2048)
            if addr != self.ip or len(data) < 17:
                continue
            if data == last:  # el kit manda cada broadcast dos veces
                continue
            last = data
            cmd, body = data[16], data[17:]
            if self.mac is None:
                self.mac = data[1:7]
            if cmd == CMD_CUSTOM and body[:1] == bytes([CUSTOM_LEARN_DATA]) and len(body) > 1:
                with self.lock:
                    self.codecs.append(body[1])
                self._note(f"codec recibido: {body[1]}")
            elif cmd == CMD_DEBUG:
                self._note(body.decode("ascii", "replace").strip("\x00").strip())
            else:
                self._note(f"cmd {cmd}: {data.hex()}")

    def send(self, cmd_id, payload=b"", dst_endpoint=0, wait=True, tries=3):
        """Manda un comando y devuelve la respuesta a ESE comando (o None si no llegó).

        El kit repite en el byte 13 el número de secuencia del pedido: las respuestas
        con otra secuencia (por ejemplo, una demorada de un comando anterior) se descartan.
        """
        for _ in range(tries):
            seq = next_seq()
            self.tx.sendto(build(self.mac, seq, cmd_id, payload, dst_endpoint), (self.ip, PORT_DEVICE))
            if not wait:
                return None
            end = time.time() + 3
            while time.time() < end:
                r, _, _ = select.select([self.tx], [], [], max(0, end - time.time()))
                if not r:
                    break
                data, (addr, _) = self.tx.recvfrom(2048)
                if addr != self.ip or len(data) < 17:
                    continue
                if data[13] != seq:
                    self._note(f"respuesta descartada (seq {data[13]}, esperaba {seq}): {data.hex()}")
                    continue
                return data
        return None

    def custom(self, sub, params=b"", tries=3):
        """Devuelve ACK, NAK o TIMEOUT."""
        resp = self.send(CMD_CUSTOM, bytes([sub]) + bytes(params), tries=tries)
        if resp is None:
            return TIMEOUT
        if resp[16] == CMD_ACK:
            return ACK
        if resp[16] == CMD_NAK:
            return NAK
        self._note(f"respuesta inesperada al custom {sub}: {resp.hex()}")
        return TIMEOUT

    def ir_status(self):
        resp = self.send(CMD_CUSTOM, bytes([CUSTOM_GET_STATUS, 30]))
        if not resp or len(resp) < 21 or resp[16] != CMD_CUSTOM:
            return None
        b = resp[17:]
        irmac = resp[-6:].hex() if len(resp) >= 18 + 35 else ""
        return b[1], b[2] | (b[3] << 8), irmac

    def set_mode(self, mode, fan, temp_c):
        t = int(round(temp_c * 100))
        self.send(CMD_SET_MODE, bytes([mode, fan, 0, t & 0xFF, t >> 8]), dst_endpoint=1, wait=False)

    def wait_codec(self, timeout=60):
        with self.lock:
            self.codecs.clear()
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                if self.codecs:
                    return self.codecs[-1]
            time.sleep(0.2)
        return None


def require(label, action, hint=""):
    """Repite una operación necesaria hasta que el kit la confirme, o cancela el asistente."""
    while True:
        result = action()
        if result == ACK:
            say("  OK")
            return
        if result == NAK:
            say(f"  El kit RECHAZÓ el comando ({label}).")
        else:
            say(f"  El kit no respondió ({label}).")
        if hint:
            say(f"  {hint}")
        if ask("  ¿Reintentar o cancelar? [r/c] ", {"r", "c"}) == "c":
            raise Cancelled(f"no se pudo confirmar: {label}")


# ---------------------------------------------------------------- Home Assistant

def ha_running(name):
    if not shutil.which("docker"):
        return False
    r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name],
                       capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip() == "true"


def ha_set(name, start):
    action = "start" if start else "stop"
    say(f"  docker {action} {name} ...")
    r = subprocess.run(["docker", action, name], capture_output=True, text=True)
    if r.returncode != 0:
        say(f"  No pude ejecutar 'docker {action} {name}': {r.stderr.strip()}")
        return False
    return True


# ---------------------------------------------------------------- descubrimiento

def discover(rx, seconds=20):
    say(f"Buscando kits BGH en la red ({seconds} s)...")
    found = {}
    end = time.time() + seconds
    rx.settimeout(1)
    while time.time() < end:
        try:
            data, (addr, _) = rx.recvfrom(2048)
        except socket.timeout:
            continue
        if len(data) >= 17 and data[7:13] == b"\xff" * 6 and addr not in found:
            found[addr] = data[1:7]
            say(f"  {addr}  MAC {data[1:7].hex()}")
    rx.settimeout(None)
    return found


# ---------------------------------------------------------------- pasos

def step_ir_unit(kit):
    say("\n[2] Verificando la unidad IR...")
    while True:
        st = kit.ir_status()
        if st is None:
            say("  El kit no respondió la consulta de estado.")
        else:
            rssi, batt, irmac = st
            say(f"  Señal BLE={rssi}  Batería={batt}  MAC IR={irmac or '(ninguna)'}")
            if irmac and 0 < rssi < 85:
                if batt and batt <= 1000:
                    say("  Aviso: la batería parece baja; si algo falla, cambiá las pilas.")
                return True
            if not irmac:
                say("  La unidad IR no está vinculada a la base.")
            else:
                say("  La señal entre la base y la unidad IR es débil: acercalas.")
        say("  Para vincularla: sacá una pila de la IR, apretá su botón 'vincular',")
        say("  mantené 5 s el botón de la base hasta que se ponga roja, y volvé a poner la pila.")
        if ask("  ¿Reintentar la verificación? [s/n] ", {"s", "n"}) == "n":
            raise Cancelled("la unidad IR no quedó verificada")


def step_codec(kit):
    while True:
        say("\n[3] Apuntá el control remoto ORIGINAL del aire a la unidad IR (a unos 20 cm)")
        say("    y tocá el botón de ENCENDIDO una vez. (Esperando hasta 60 s...)")
        codec = kit.wait_codec()
        if codec is None:
            if ask("  No se detectó el control. ¿Reintentar? [s/n] ", {"s", "n"}) == "n":
                raise Cancelled("no se detectó el control remoto")
            continue
        say(f"  Control detectado (codec {codec}).")
        time.sleep(1.5)
        say("    Tocá ENCENDIDO otra vez para confirmar.")
        confirm = kit.wait_codec()
        if confirm == codec:
            say(f"  Codec confirmado: {codec}")
            return codec
        say(f"  No coincide ({codec} / {confirm}). Repetimos.")


def step_beeps(kit):
    say("\n[5] La unidad IR va a emitir cada 3 segundos.")
    say("    Acercala al display del aire (a menos de 5 cm, sin taparlo) y movela")
    say("    hasta que el aire haga 'beep' en cada emisión.")
    stop = threading.Event()

    def beeper():
        while not stop.is_set():
            # Igual que la app: mode 0, fan 255, flags 255, setpoint -327.68 (0x8000)
            kit.send(CMD_SET_MODE, bytes([0, 255, 255, 0x00, 0x80]), dst_endpoint=1, wait=False)
            stop.wait(3)

    t = threading.Thread(target=beeper, daemon=True)
    t.start()
    try:
        r = ask("    ¿Escuchás los beeps? [s = sí / n = no / c = volver a leer el control] ",
                {"s", "n", "c"})
    finally:
        stop.set()
        t.join()
    return r


def step_store(kit, codec):
    toggle = codec not in NOT_TOGGLE
    say("\n[6] ¿Cómo va a saber el kit si el aire está encendido?")
    if toggle:
        say(f"    El codec {codec} es TOGGLE: la misma señal enciende y apaga. El kit NECESITA")
        say("    un sensor para conocer el estado real; si no, va a encender cuando pidas apagar.")
    say("    1 = el aire está enchufado en el tomacorriente de la unidad Wi-Fi (sensor de consumo; recomendado)")
    say("    2 = otro tomacorriente: usa el sensor de VIBRACIÓN de la unidad IR (tiene que quedar pegada al aire)")
    say("    0 = sin sensor (experimental): el kit asume que cada orden se cumplió; si usás el")
    say("        control remoto físico se desfasa")
    sensor = int(ask("    Opción [1/2/0]: ", {"1", "2", "0"}))
    if sensor == 2 and codec in NOT_TOGGLE:
        sensor = 0
    say("    Ahora se calibra el cero del sensor de vibración (custom 100). Para eso:")
    say("      - la unidad IR tiene que estar YA PEGADA en su lugar definitivo, y")
    say("      - el aire tiene que estar APAGADO Y DETENIDO por completo (sin ventilador ni ruido).")
    ask("    Enter cuando el aire esté totalmente detenido... ")
    say(f"  Fijando codec {codec} y sensor {sensor}...")
    require("codec + sensor", lambda: kit.custom(CUSTOM_SET_CODEC, [codec, sensor], tries=5))
    say("  Calibrando el sensor y guardando la configuración...")
    while True:
        result = TIMEOUT
        for _ in range(10):
            result = kit.custom(CUSTOM_STORE, tries=1)
            if result == ACK:
                say("  Calibración del sensor y guardado: OK")
                return
            time.sleep(2)
        say("  El kit " + ("rechazó" if result == NAK else "no confirmó") +
            " el guardado (custom 100): la configuración podría NO haber quedado guardada.")
        say("  Revisá que el aire siga apagado y detenido, y que la unidad IR no se mueva.")
        if ask("  ¿Reintentar el guardado o cancelar? [r/c] ", {"r", "c"}) == "c":
            raise Cancelled("no se pudo confirmar el guardado de la configuración")


def step_final_test(kit):
    """True si funcionó, False si falló, None si no se hizo."""
    if ask("\n[8] ¿Hacemos una prueba final encendiendo el aire? [s/n] ", {"s", "n"}) == "n":
        return None
    say("  Enviando: FRÍO 24 °C, ventilador medio...")
    kit.set_mode(MODE_COOL, FAN_MEDIUM, 24)
    on = ask("  ¿Se encendió el aire? [s/n] ", {"s", "n"})
    say("  Enviando: APAGAR...")
    kit.set_mode(MODE_OFF, FAN_MEDIUM, 24)
    off = ask("  ¿Se apagó? [s/n] ", {"s", "n"})
    if on == "s" and off == "s":
        say("  ¡Funciona! Ya podés pegar la unidad IR con el sticker donde escuchaste los beeps.")
        return True
    say("  Probá acercar más la IR al receptor del aire, o repetí el script para releer el control.")
    return False


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ip", nargs="?", help="IP de la unidad Wi-Fi del kit (ej. 10.0.0.12)")
    ap.add_argument("--mac", help="MAC de la unidad Wi-Fi (ej. accf2380d646); si no, se detecta")
    ap.add_argument("--codec", type=codec_arg, help="usar este codec y saltear la lectura del control")
    ap.add_argument("--ha-container", default="homeassistant", help="contenedor de Home Assistant")
    ap.add_argument("--no-ha", action="store_true", help="no detener/iniciar Home Assistant")
    ap.add_argument("--listen", action="store_true", help="solo mostrar lo que emite el kit")
    ap.add_argument("--debug", action="store_true", help="mostrar en pantalla los mensajes del kit")
    args = ap.parse_args()
    exit_code = 0

    # Home Assistant tiene tomado el puerto 20911: lo detenemos durante la configuración
    stopped_ha = False
    if not args.no_ha and ha_running(args.ha_container):
        say(f"Home Assistant ({args.ha_container}) está corriendo y usa el puerto {PORT_BROADCAST}.")
        if ask("¿Lo detengo durante la configuración? (se vuelve a iniciar al final) [s/n] ",
               {"s", "n"}) == "s":
            stopped_ha = ha_set(args.ha_container, start=False)
            time.sleep(2)

    try:
        try:
            rx = open_broadcast_socket()
        except OSError as e:
            sys.exit(f"No pude abrir el puerto UDP {PORT_BROADCAST} ({e}). "
                     f"Detené Home Assistant: docker stop {args.ha_container}")

        ip = args.ip
        mac = bytes.fromhex(args.mac.replace(":", "")) if args.mac else None
        if not ip:
            found = discover(rx)
            if not found:
                sys.exit("No encontré kits. Verificá que estén conectados a la red.")
            ips = list(found)
            if len(ips) == 1:
                ip = ips[0]
            else:
                for i, a in enumerate(ips, 1):
                    say(f"  {i}) {a}")
                ip = ips[int(ask("¿Cuál configuro? ", {str(i) for i in range(1, len(ips) + 1)})) - 1]
            mac = mac or found[ip]

        kit = Kit(ip, mac, rx, debug=args.debug or args.listen)

        if args.listen:
            say(f"Escuchando a {ip} (Ctrl+C para salir)...")
            while True:
                time.sleep(1)

        if kit.mac is None:
            say(f"Esperando un broadcast de {ip} para obtener su MAC (hasta 90 s)...")
            end = time.time() + 90
            while kit.mac is None and time.time() < end:
                time.sleep(0.5)
            if kit.mac is None:
                sys.exit("El kit no emitió nada. Pasá la MAC con --mac.")
        say(f"\nKit {ip}  MAC {kit.mac.hex()}   (log: {LOG_FILE})")

        learn_on = False
        try:
            say("\n[1] Activando modo aprendizaje...")
            # Aunque no se confirme, al salir se intenta apagar el modo aprendizaje
            learn_on = True
            require("modo aprendizaje", lambda: kit.custom(CUSTOM_LEARN_MODE, [1], tries=5),
                    "Revisá que el kit esté encendido y que esta máquina esté en la misma red.")

            step_ir_unit(kit)

            codec = args.codec
            while True:
                if codec is None:
                    codec = step_codec(kit)
                say(f"\n[4] Fijando codec {codec}...")
                require(f"codec {codec}", lambda: kit.custom(CUSTOM_SET_CODEC, [codec, 0], tries=5))
                r = step_beeps(kit)
                if r == "s":
                    break
                if r == "c":
                    codec = None
                    continue
                say("  Sin beeps: acercá más la IR o releé el control (opción c).")
                if ask("  ¿Reintentar la prueba de beeps? [s/n] ", {"s", "n"}) == "n":
                    raise Cancelled("el aire no recibió las emisiones de prueba")

            step_store(kit, codec)

            say("\n[7] Saliendo del modo aprendizaje...")
            require("salir del modo aprendizaje", lambda: kit.custom(CUSTOM_LEARN_MODE, [0]))
            learn_on = False

            tested = step_final_test(kit)
            say(f"\nConfiguración guardada en el kit. Codec del aire: {codec}.")
            say(f"Anotalo por si tenés que reconfigurar (sudo python3 bgh_sync.py {ip} --codec {codec}).")
            if tested is False:
                exit_code = 1
        finally:
            if learn_on:
                say("\nIntentando sacar al kit del modo aprendizaje...")
                result = kit.custom(CUSTOM_LEARN_MODE, [0])
                say("  OK" if result == ACK else
                    "  Sin confirmación: si el kit no responde normalmente, desenchufalo y volvelo a enchufar.")
    except Cancelled as e:
        say(f"\nCancelado: {e}.")
        say("El kit NO quedó configurado. Podés volver a correr el script cuando quieras.")
        exit_code = 1
    except KeyboardInterrupt:
        say("\nCancelado.")
        exit_code = 1
    finally:
        if stopped_ha:
            say("\nVolviendo a iniciar Home Assistant...")
            ha_set(args.ha_container, start=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
