# BGH Smart Control Kit (HPA-4911) sin la app: guía desde cero

Guía para recuperar y configurar el **BGH Smart Control Kit** de forma 100 % local, sin la app ni la nube de BGH/Solidmation, e integrarlo en **Home Assistant**.

Sirve para un kit nuevo en caja, para uno reseteado y para uno que quedó "huérfano" cuando BGH dio de baja el servicio y la app empezó a pedir un login que ya no funciona.

> **Créditos:** esto se apoya en la integración local de [firtman/bgh_smart](https://github.com/firtman/bgh_smart) y en lo que compartió la comunidad en sus issues ([#7](https://github.com/firtman/bgh_smart/issues/7), [#8](https://github.com/firtman/bgh_smart/issues/8), [#9](https://github.com/firtman/bgh_smart/issues/9)). La parte de **sincronizar el control remoto** (elegir el protocolo IR) sale de analizar la app oficial *BGH Smart Control 2.7* (`com.solidmation.bghsmartcontrol`), cuyo asistente para el HPA-4911 hace todo por UDP en la red local.

---

## Índice

1. [Cómo es el kit](#1-cómo-es-el-kit)
2. [Qué necesitás](#2-qué-necesitás)
3. [Paso 0: Reset completo](#paso-0-reset-completo)
4. [Paso 1: Conectar la unidad Wi-Fi a tu red](#paso-1-conectar-la-unidad-wi-fi-a-tu-red)
5. [Paso 2: Vincular la unidad IR con la unidad Wi-Fi](#paso-2-vincular-la-unidad-ir-con-la-unidad-wi-fi)
6. [Paso 3: IP fija y Home Assistant](#paso-3-ip-fija-y-home-assistant)
7. [Paso 4: Sincronizar el control remoto (protocolo IR)](#paso-4-sincronizar-el-control-remoto-protocolo-ir)
8. [Diagnóstico](#diagnóstico)
9. [Referencia del protocolo](#referencia-del-protocolo)

---

## 1. Cómo es el kit

El kit tiene **dos unidades** que se comunican entre sí por **Bluetooth LE**:

| Unidad | Qué es | Cómo se comunica |
|---|---|---|
| **Unidad Wi-Fi** (base) | Va enchufada a la pared. Tiene un tomacorriente para el aire, con sensor de consumo, y un botón **vincular** con LED. En el router aparece como `HPA-4911` con una MAC `ac:cf:23:xx:xx:xx`. | Wi-Fi 2,4 GHz hacia tu red; UDP en los puertos **20910/20911** |
| **Unidad IR** (satélite) | Funciona con 3 pilas y se pega frente al display del aire. Tiene un botón **vincular** adentro, junto a las pilas, y mide la temperatura ambiente. | BLE hacia la base; infrarrojo hacia el aire |

Para que funcione, el kit tiene que estar configurado en **tres** niveles. Cada uno es un paso de esta guía:

1. **Base ↔ tu Wi-Fi** (Paso 1)
2. **Base ↔ unidad IR** (Paso 2)
3. **Unidad IR ↔ protocolo de tu control remoto**, el "codec" (Paso 4)

Si falta el tercero, el síntoma típico es este: la IR emite (se ve con la cámara del celular) pero **el aire no responde**.

### LEDs

| LED | Significado |
|---|---|
| Base: **verde parpadeando** | Modo vincular: sin red Wi-Fi, emitiendo el hotspot `BGH-…` |
| Base: **rojo parpadeando** | Conectada al Wi-Fi pero **sin unidad IR vinculada**, o sin internet |
| IR: **rojo parpadeando** | No está vinculada a ninguna base |
| Ambos fijos o apagados | Vinculados y funcionando |

---

## 2. Qué necesitás

- Una **red Wi-Fi de 2,4 GHz**. Las redes de 5 GHz no funcionan.
- Una **PC o notebook con Wi-Fi y Python 3**, para el Paso 1.
- **Home Assistant** con [HACS](https://hacs.xyz/). Si lo corrés en Docker, tiene que usar `network_mode: host`, porque el kit habla por **broadcast UDP**.
- El **control remoto original** del aire, para el Paso 4.
- **Pilas nuevas** para la unidad IR.
- Los scripts de esta guía:
  - `wifi_provision.py` de [firtman/bgh_smart](https://github.com/firtman/bgh_smart), para el Paso 1
  - `bgh_sync.py`, que acompaña esta guía, para el Paso 4

> **Importante:** el kit **solo trae códigos IR de aires BGH**. Con otras marcas no funciona.

---

## Paso 0: Reset completo

Este procedimiento sale de la ayuda oficial de BGH y deja **las dos unidades** sin configurar. Hacelo si el kit fue usado antes o si algo quedó a medias. Con un kit nuevo en caja podés saltearlo.

1. **Desenchufá la unidad Wi-Fi.**
2. **Antes de que pasen 30 segundos**, apretá con un clip el botón **vincular de la unidad IR**. Su LED tiene que empezar a **parpadear en rojo**.
3. **Sacale las pilas a la unidad IR**, para que no se vuelva a vincular sola.
4. **Enchufá la unidad Wi-Fi.** El LED queda parpadeando en rojo.
5. **Mantené apretado el botón vincular de la base unos 5 segundos.** El LED rojo se apaga y vuelve a encenderse en rojo. Soltalo: la base se desvinculó de la IR.
6. **Apretá otra vez el botón vincular de la base** y mantenelo. El LED parpadea en rojo; seguí apretando hasta que **parpadee en verde**.
7. Con el **LED verde parpadeando**, la base está en modo vincular y emite un hotspot Wi-Fi `BGH-XXX-XXXXXXXXXX`.

> Variante de la comunidad (issue #7) para resetear solo la IR: mantener apretado su botón unos **20 segundos** hasta que parpadee en rojo.

---

## Paso 1: Conectar la unidad Wi-Fi a tu red

Antes esto lo hacía la app. Ahora se hace con el script `wifi_provision.py` de firtman.

### 1.1 Preparar el script en la PC

El script viene dentro del paquete de la integración, que importa Home Assistant. Para correrlo en una PC sin Home Assistant, armá esta carpeta:

```
bgh_provision/
└── bgh_smart/
    ├── __init__.py          ← archivo vacío
    ├── const.py             ← de firtman/bgh_smart
    └── wifi_provision.py    ← de firtman/bgh_smart
```

Para comprobar que funciona, corré esto desde la carpeta `bgh_provision`:
```bash
python -m bgh_smart.wifi_provision --help
```

### 1.2 Conectarse al hotspot del kit

1. Con la base en modo vincular (LED **verde** parpadeando), conectá la notebook a la red `BGH-…`. Te vas a quedar sin internet un rato: es normal.
2. En Windows, marcá la red como **privada** y, cuando lo pregunte, **permití que Python use la red** (privada y pública). Si no, el firewall bloquea los paquetes UDP.
3. En modo vincular, la base tiene la IP **`10.10.100.254`**.

### 1.3 Obtener la MAC y enviar tu Wi-Fi

```bash
python -m bgh_smart.wifi_provision --discover
# → devuelve la MAC del kit, por ejemplo accf2380d646

python -m bgh_smart.wifi_provision --device-mac accf2380d646 --ssid "MiRed2.4" --password "MiClave"
```

En **10 a 30 segundos** el hotspot desaparece y la base aparece en el router como `HPA-4911`. Volvé a conectar la notebook a tu red.

> La clave queda en el historial de la terminal. En PowerShell se borra con `Remove-Item (Get-PSReadLineOption).HistorySavePath`.

**Si no funciona:**

| Problema | Qué hacer |
|---|---|
| `--discover` no encuentra nada | Revisá que la notebook siga conectada a `BGH-…` y el permiso del firewall. Probá con `--timeout 15`. |
| No hay respuesta al enviar | Fijate el gateway con `ipconfig` o `ip route` y pasalo con `--device-ip`. |
| Desaparece el hotspot pero el kit no aparece en el router | La clave está mal o la red no es de 2,4 GHz. Volvé al Paso 0. |

---

## Paso 2: Vincular la unidad IR con la unidad Wi-Fi

Si la base ya está en tu red pero **los dos LEDs parpadean en rojo**, falta este paso.

**Procedimiento:**
1. **Desenchufá la base.**
2. En la **unidad IR**, mantené apretado el botón vincular unos **20 s** hasta que parpadee en rojo. Después **sacale una pila**.
3. **Enchufá la base** y esperá a que se conecte al Wi-Fi: tiene que aparecer en el router.
4. **Volvé a poner la pila** en la IR. Se vinculan solas en unos minutos: primero deja de parpadear la IR y después la base.

**Recomendaciones:**
- Si tenés varios kits, vinculá **uno por vez**, con los demás desenchufados.
- Con pilas gastadas la IR no vincula.
- Todavía **no pegues la IR** en el aire.

**Cómo verificarlo:** el script del Paso 4 consulta el estado de la IR al empezar. Si muestra una `MAC IR`, quiere decir que está vinculada.

---

## Paso 3: IP fija y Home Assistant

### 3.1 IP fija

En el router, creá una **reserva DHCP** para la MAC de la base (`ac:cf:23:…`). Si la IP cambia, Home Assistant pierde el equipo.

### 3.2 Instalar la integración

1. En **HACS**, abrí el menú ⋮ → **Repositorios personalizados** → agregá `https://github.com/firtman/bgh_smart`, categoría **Integración**.
2. Instalá **BGH Smart Control** y reiniciá Home Assistant.
3. Andá a **Configuración → Dispositivos y servicios → Agregar integración → BGH Smart Control**, con un nombre y la IP del kit.

Cada kit aparece como una entidad `climate` con modos frío, calor, seco, ventilación y auto, velocidades de ventilador, temperatura objetivo y **temperatura ambiente** (que mide la unidad IR).

> **Docker:** Home Assistant tiene que usar `network_mode: host`. Para verificar que llegan los broadcasts, corré `sudo tcpdump -ni eth0 udp port 20911` en el host.

---

## Paso 4: Sincronizar el control remoto (protocolo IR)

Este es el paso que **no estaba documentado en ningún lado** y es el motivo de esta guía.

Hay muchos aires BGH, y no todos usan el mismo protocolo infrarrojo. La app tenía un paso "sincronizá tu control remoto": activaba un **modo aprendizaje** en el kit, te pedía apretar **ENCENDIDO** dos veces apuntando a la IR, y el kit identificaba el protocolo, al que llama **codec**. **Sin ese comando, la IR ignora el control.** Por eso apretar el control "a mano" no hace nada.

El script `bgh_sync.py` reproduce ese asistente completo.

### 4.1 Uso

En la máquina donde corre Home Assistant, o en cualquiera de la misma red:

```bash
sudo python3 bgh_sync.py              # busca los kits de la red y pregunta cuál configurar
sudo python3 bgh_sync.py 10.0.0.12    # un kit puntual
```

El script:
1. **Detiene Home Assistant** (te pregunta antes), porque tiene tomado el puerto UDP 20911, y **lo vuelve a iniciar al final**. El nombre del contenedor se cambia con `--ha-container`, o podés saltear esto con `--no-ha`.
2. Activa el **modo aprendizaje**.
3. **Verifica la unidad IR**: señal BLE, batería y MAC. Si no está vinculada, te explica el Paso 2.
4. Te pide **apuntar el control original a la IR y apretar ENCENDIDO**, y después **otra vez** para confirmar. Muestra el **codec** detectado.
5. Fija el codec y hace que **la IR emita cada 3 segundos**. Acercala al display del aire, a menos de 5 cm, hasta que el aire haga **"beep"** en cada emisión: esa es la posición donde va el sticker.
6. Te pregunta **dónde está enchufado el aire**, en la base o en otro tomacorriente. Esto configura el sensor de consumo.
7. **Guarda** la configuración en el kit y sale del modo aprendizaje.
8. Hace una **prueba final**: enciende el aire en frío a 24 °C y lo apaga.

Anotá el codec. Para reconfigurar después sin releer el control:
```bash
sudo python3 bgh_sync.py 10.0.0.12 --codec 60
```

Para ver en pantalla los mensajes internos del kit, usá `--debug`. Siempre quedan guardados en `bgh_sync.log`.

### 4.2 Así se ve cuando funciona (`--debug`)

```
LEARN MODE=TRUE                       ← modo aprendizaje activo
BLE Logic State = Ready               ← la IR está conectada a la base
IR-CMD <60>                           ← la IR recibió tu control
IRCodec_GetCodecForTimeArray(60)      ← identificó el protocolo
LG bytes: P0=88, P1=c0, ...           ← (codec 60 = trama tipo LG)
IRCodec_SetCodecType(60)              ← codec guardado
LEARN MODE=FALSE
>> MODE_OFF 23 FAN_MODE_MID FLAGS=00  ← emisiones de prueba ("beeps")
```

Codecs reportados por la comunidad:

| Codec | Trama | Aire / control |
|---|---|---|
| 60 | LG | BGH (agregar modelo) |

*Si lo configurás, sumá tu modelo de aire, el modelo de control y el codec a esta tabla.*

---

## Diagnóstico

### Ver qué dice el kit

La base emite mensajes de depuración **en texto** por broadcast. Son la mejor herramienta para saber qué pasa:

```bash
sudo tcpdump -ni eth0 -A udp port 20911 and host <IP_DEL_KIT>
# o:
sudo python3 bgh_sync.py <IP_DEL_KIT> --listen
```

| Mensaje | Significado |
|---|---|
| `>> MODE_HEAT 23. FAN_MODE_HIGH` | Llegó una orden (de Home Assistant o del script) |
| `BLE Connection Interval = 18` | La base se conectó por BLE a la IR (que se despierta) |
| `BLE NAK [41]` + `Retry IR-Play packet` | La IR todavía no estaba lista; la base reintenta. **Es normal** en el primer comando después de un rato sin uso. |
| `BLELogic_UpdateAmbientTemperature ... AdjustedTemp=1900` | Temperatura ambiente medida por la IR (19,00 °C) |
| `LEARN MODE=TRUE/FALSE` | Entró o salió del modo aprendizaje |
| `IR-CMD <n>` / `IRCodec_...` | La IR recibió o identificó un control remoto |

### Problemas típicos

| Síntoma | Causa probable | Solución |
|---|---|---|
| Los dos LEDs parpadean en rojo | La IR no está vinculada | Paso 2 |
| La IR emite (se ve con la cámara) pero el aire no responde | Falta el codec, o la IR está lejos del receptor | Paso 4 |
| En Home Assistant la temperatura salta a 255 °C | Paquetes ACK de 22 bytes parseados como estado | Ver el issue #3 o #5 de firtman/bgh_smart |
| Home Assistant no recibe estados | Docker sin `network_mode: host`, firewall o aislamiento de clientes Wi-Fi en el router | Revisar la red |
| `bgh_sync.py`: "No pude abrir el puerto 20911" | Home Assistant tiene tomado el puerto | `docker stop homeassistant` o dejar que el script lo detenga |

---

## Referencia del protocolo

Para quien quiera extender la integración. Todo es UDP: los **comandos** van a `IP_DEL_KIT:20910`, y los **broadcasts** del kit van a `255.255.255.255:20911`. El ACK de un comando vuelve **unicast** al puerto de origen.

### Header (17 bytes)

| Byte | Campo |
|---|---|
| 0 | Versión de protocolo (`0x00`) |
| 1-6 | MAC de origen (`000000000000` desde la app; MAC del kit en sus broadcasts) |
| 7-12 | MAC de destino (MAC del kit; `ffffffffffff` en broadcasts) |
| 13 | Número de secuencia |
| 14 | Endpoint de origen |
| 15 | Endpoint de destino (`0` = dispositivo, `1` = termostato/aire) |
| 16 | Comando |

### Comandos

| Comando | Valor | Payload |
|---|---|---|
| ACK / NAK | 128 / 129 | — |
| Status report (broadcast) | 253 | estado |
| Debug (broadcast, texto) | 245 | texto ASCII |
| HVAC SetMode (endpoint 1) | 97 | `mode, fan, flags, temp_lo, temp_hi` (temp × 100, little-endian) |
| Custom command | 162 | `subcomando, parámetros…` |

**Modos:** 0 apagado, 1 frío, 2 calor, 3 seco, 4 ventilación, 254 auto. **Ventilador:** 1 bajo, 2 medio, 3 alto.

### Subcomandos *custom* (162) del HPA-4911

Estos son los que usa el asistente de la app:

| Sub | Payload | Función |
|---|---|---|
| 90 | `[1]` / `[0]` | Activa / desactiva el **modo aprendizaje** |
| 92 | `[30]` | Pide el estado de la unidad IR. Respuesta: `92, RSSI, batería_lo, batería_hi, …, MAC_IR (últimos 6 bytes)` |
| 95 | `[codec]` | **(Kit → app, broadcast)** Codec detectado al recibir el control remoto |
| 88 | `[codec, sensor]` | Fija el codec. Sensor: 0 = ninguno, 1 = aire enchufado en la base, 2 = otro tomacorriente (3 existe en la app, sin uso documentado) |
| 100 | — | Guarda la configuración |
| 101 | `[offset_lo, offset_hi]` | Ajuste (offset) de la temperatura ambiente (× 100) |

### Secuencia del asistente de la app

```
90 [1]            → modo aprendizaje
92 [30]           → verifica IR (la app exige RSSI 1-84)
(espera 95)       → usuario aprieta ENCENDIDO
(espera 95)       → usuario aprieta ENCENDIDO otra vez; tiene que coincidir
88 [codec, 0]
97 (endpoint 1) mode 0, fan 255, flags 255, temp 0x8000   ← cada 3 s, "¿escuchás beeps?"
88 [codec, sensor]
100               → guardar
101 [offset]      → opcional
90 [0]            → salir del modo aprendizaje
```

---

*Guía armada por la comunidad. Si encontrás errores o tenés datos nuevos (codecs, modelos, comandos), sumalos.*
