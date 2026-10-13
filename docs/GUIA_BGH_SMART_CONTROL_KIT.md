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

> **¿Sirve para otras marcas?** El kit trae una tabla de protocolos IR que no se limita a BGH. Muchos aires BGH son fabricados por otras marcas, y el kit reconoce esos protocolos. Está **comprobado con un aire LG** (codec 60, ver la tabla del Paso 4). Para otras marcas, la única forma de saberlo es probar el Paso 4: si el kit identifica tu control remoto (`IR-CMD <n>` en el log), lo soporta.

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

Cada marca y modelo de aire usa su propio protocolo infrarrojo. La app tenía un paso "sincronizá tu control remoto": activaba un **modo aprendizaje** en el kit, te pedía apretar **ENCENDIDO** dos veces apuntando a la IR, y el kit identificaba el protocolo, al que llama **codec**. **Sin ese comando, la IR ignora el control.** Por eso apretar el control "a mano" no hace nada.

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
6. Te pregunta **cómo va a saber el kit si el aire está encendido**: con el sensor de consumo (aire enchufado en la base) o con el sensor de vibración de la IR (aire en otro tomacorriente). Ver [4.3](#43-codecs-toggle-por-qué-importa-el-sensor).
7. **Calibra el sensor de vibración** (comando `100`) y sale del modo aprendizaje. Para eso, **la IR tiene que estar ya pegada** en su lugar definitivo y **el aire apagado y totalmente detenido**.
8. Hace una **prueba final**: enciende el aire en frío a 24 °C y lo apaga.

**Si el kit no confirma un paso necesario** (modo aprendizaje, codec, codec + sensor o guardado), el script **no sigue de largo**. Te dice si el kit **rechazó** el comando o **no respondió**, y te deja **reintentar** o **cancelar**. Si cancelás, intenta sacar al kit del modo aprendizaje, vuelve a iniciar Home Assistant y avisa que **el kit no quedó configurado**. El mensaje "Configuración guardada en el kit" aparece solo si se confirmó el guardado.

Si el guardado no se confirma, revisá que el aire siga apagado y detenido y que la IR no se haya movido, y reintentá.

Anotá el codec. Para reconfigurar después sin releer el control:
```bash
sudo python3 bgh_sync.py 10.0.0.12 --codec 60
```
El codec es un número de 0 a 255.

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

### 4.3 Codecs toggle: por qué importa el sensor

Algunos controles no mandan "encender" o "apagar": mandan **la misma señal de power para las dos cosas** (toggle). Con esos codecs, el kit necesita **saber el estado real del aire** para decidir si manda o no la señal de power. Si no lo sabe, se desfasa: **pedís un modo y el aire se apaga, pedís apagar y se enciende**.

El kit conoce el estado gracias al sensor que se elige en el paso 6 del script:

| Valor | Sensor | Requisito |
|---|---|---|
| **1** | Consumo, medido en el tomacorriente de la base | El aire **enchufado en la unidad Wi-Fi** (recomendado) |
| **2** | Vibración, medida por la unidad IR | La IR **pegada al aire** |
| 0 | Ninguno | Solo para codecs no toggle |

Según la app, **los codecs no toggle** son 1, 10, 12, 13, 20, 30, 50, 51, 71, 80, 90, 100, 111, 130, 140 y 150. **Todos los demás son toggle**, por ejemplo 60 y 70. Con un codec toggle, terminá la configuración **con el aire apagado**, para que el kit arranque sabiendo el estado real.

**Con el sensor de vibración (2):** el comando `100` del final **calibra el cero de vibración**. Si lo corrés con la IR suelta o con el aire funcionando, el kit toma un cero incorrecto: Home Assistant muestra el aire **apagado al rato de encenderlo**, y la siguiente orden lo apaga de verdad. Solución: pegá la IR, apagá el aire, esperá a que se detenga del todo y volvé a correr `bgh_sync.py <IP> --codec <n>`.

> **Caso real (codec 70, aire BGH):** con la IR apoyada en un estante junto al aire, el sensor medía la vibración del estante. El aire aparecía apagado al rato y los modos lo apagaban. Con la IR **pegada al gabinete** y recalibrada con el aire detenido, funciona correctamente. "Pegada" significa en contacto firme con el equipo: apoyada al lado no alcanza.

### 4.4 Codecs reportados por la comunidad

| Codec | Trama | Toggle | Aire / control | Notas (según la app) |
|---|---|---|---|---|
| 60 | LG | sí | Aire **LG** (agregar modelo de aire y de control) | Mínimo 18 °C (16 °C en calor) |
| 70 | — | sí | Aire **BGH** (agregar modelo). Con la app oficial **nunca había funcionado**; con `bgh_sync.py` funciona. Aire en otro tomacorriente: **sensor de vibración (2)** con la IR pegada al gabinete y calibrada con el aire detenido. | Mínimo 18 °C; sin velocidad de ventilador en modo seco; swing vertical |

*Si lo configurás, sumá tu modelo de aire, el modelo de control y el codec a esta tabla.*

### 4.5 Todos los codecs que conoce la app

La tabla de protocolos IR vive en el **firmware de la unidad IR**, y la app no trae nombres de marcas ni de modelos, solo números. Estos son los 21 codecs que maneja la app oficial, con lo que la app sabe de cada uno:

| Codec | Toggle | Temp. mín. (°C) | Temp. máx. (°C) | Marca comprobada |
|---|---|---|---|---|
| 1 | no | 17 | 30 | |
| 10 | no | 18 | 30 | |
| 12 | no | 18 | 30 | |
| 13 | no | 18 | 30 | |
| 20 | no | 16 | 30 | |
| 30 | no | 16 | 30 | |
| 40 | **sí** | 18 | 32 | |
| 50 | no | 16 (21 en auto) | 31 (25 en auto) | |
| 51 | no | 16 | 31 | |
| 60 | **sí** | 18 (16 en calor) | 30 | LG |
| 70 | **sí** | 18 | 30 | BGH |
| 71 | no | 16 | 30 | |
| 80 | no | 16 | 32 | |
| 90 | no | 18 | 30 | |
| 100 | no | 16 | 30 | |
| 110 | **sí** | 17 | 30 | |
| 111 | no | 17 | 30 | |
| 120 | **sí** | 16 | 30 | |
| 130 | no | 18 | 32 | |
| 140 | no | 16 | 30 | |
| 150 | no | 16 | 32 | |

- **No hace falta elegir el codec:** el kit lo detecta solo cuando apretás ENCENDIDO en el control durante el modo aprendizaje. Si tu control no está en la tabla del firmware, el kit no reporta nada.
- Los números con variantes (10/12/13, 50/51, 70/71, 110/111) parecen familias de un mismo protocolo. Es una inferencia por la numeración, no está confirmado.
- **Si perdiste el control remoto:** podés forzar un codec sin leer el control y usar la prueba de beeps para encontrar el que tu aire entiende. Este método todavía no está probado:
  ```bash
  sudo python3 bgh_sync.py <IP> --codec 10    # ¿beep? si no, probá el siguiente
  ```

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
| `bgh_sync.py`: "El kit no respondió" | El kit está ocupado, se cortó el Wi-Fi o la máquina está en otra red | Reintentá; si sigue, revisá que el kit tenga IP y que la máquina esté en la misma red |
| `bgh_sync.py`: "El kit RECHAZÓ el comando" | El kit recibió el comando pero no lo aceptó (NAK) | Reintentá; si sigue, desenchufá el kit, volvé a enchufarlo y corré el script de nuevo |

---

## Referencia del protocolo

Para quien quiera extender la integración. Todo es UDP: los **comandos** van a `IP_DEL_KIT:20910`, y los **broadcasts** del kit van a `255.255.255.255:20911`. El ACK de un comando vuelve **unicast** al puerto de origen.

### Header (17 bytes)

| Byte | Campo |
|---|---|
| 0 | Versión de protocolo (`0x00`) |
| 1-6 | MAC de origen (`000000000000` desde la app; MAC del kit en sus broadcasts) |
| 7-12 | MAC de destino (MAC del kit; `ffffffffffff` en broadcasts) |
| 13 | Número de secuencia. El kit lo **repite en su respuesta**: así se sabe a qué comando corresponde cada ACK/NAK |
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
| 88 | `[codec, sensor]` | Fija el codec. Sensor: 0 = ninguno, 1 = consumo (aire enchufado en la base), 2 = vibración de la unidad IR (3 existe en la app, sin uso documentado) |
| 100 | — | **Calibra el cero del sensor de vibración** (`CalibrateZeroVibration` en la app) y cierra la configuración. Requiere la IR pegada y el aire detenido. |
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
100               → calibrar cero de vibración (IR pegada, aire detenido)
101 [offset]      → opcional
90 [0]            → salir del modo aprendizaje
```

---

*Guía armada por la comunidad. Si encontrás errores o tenés datos nuevos (codecs, modelos, comandos), sumalos.*
