# BGH Smart Control - Home Assistant Integration

Integración personalizada para controlar aires acondicionados BGH Smart vía UDP (protocolo local) para Home Assistant.

## Características

✅ Control completo del aire acondicionado:
- Encendido/Apagado
- Modos: Frío, Calor, Ventilación, Dry, Auto
- Velocidad del ventilador: Baja, Media, Alta
- Seteo de temperatura objetivo
- Lectura de temperatura ambiente
- Lectura de temperatura objetivo (setpoint)

✅ Comunicación 100% local vía UDP (no requiere cloud)

✅ Recepción de broadcasts en tiempo real

✅ Configuración vía UI (no requiere editar YAML) con la IP del equipo

✅ Soporte para múltiples equipos

## Requisitos

- Home Assistant 2023.1 o superior
- Aire acondicionado BGH Smart con control IP/WiFi
- IP fija configurada en tu router para cada equipo

NOTA: No se por el momento si funciona con el BGH Smart Control Kit (el pequeño dispositivo smart que se conecta con aires acondicionados de cualquier marca). Esto está probado con los equipos BGH.

## Instalación

### Opción 1: HACS (Recomendado)

1. Abre HACS en Home Assistant
2. Ve a "Integraciones"
3. Haz clic en los tres puntos (⋮) arriba a la derecha
4. Selecciona "Repositorios personalizados"
5. Agrega esta URL: `https://github.com/firtman/bgh_smart`
6. Categoría: `Integration`
7. Busca "BGH Smart Control" y descárgala
8. Reinicia Home Assistant

### Opción 2: Manual

1. Copia la carpeta `bgh_smart` a `config/custom_components/`
2. La estructura debe quedar así:
   ```
   config/
   └── custom_components/
       └── bgh_smart/
           ├── __init__.py
           ├── manifest.json
           ├── climate.py
           ├── config_flow.py
           ├── const.py
           ├── bgh_client.py
           ├── coordinator.py
           ├── strings.json
           └── translations/
               ├── en.json
               └── es.json
   ```
3. Reinicia Home Assistant

## Configuración

### Paso 1: Configurar IPs Fijas

**Importante:** Antes de configurar, asigna IPs fijas a tus aires en tu router DHCP.

Ejemplo:
- Living: `192.168.2.169`
- Dormitorio 1: `192.168.2.170`
- Dormitorio 2: `192.168.2.171`

### Paso 2: Agregar la Integración

1. Ve a **Configuración** → **Dispositivos y servicios**
2. Haz clic en **+ AGREGAR INTEGRACIÓN**
3. Busca "BGH Smart Control"
4. Completa el formulario:
   - **Nombre**: Nombre descriptivo (ej: "AAC Living")
   - **IP**: Dirección IP del equipo (ej: 192.168.2.169)
5. Haz clic en **ENVIAR**

Repite para cada aire acondicionado.

### Paso 3: ¡Listo!

Tus aires aparecerán como entidades `climate` en Home Assistant.

## Uso

### En la UI de Home Assistant

Los aires aparecen en el panel de control como cualquier termostato:

- **Encender/Apagar**: Botón de power
- **Modo**: Selecciona entre Frío, Calor, Ventilación, Dry, Auto
- **Ventilador**: Baja, Media, Alta
- **Temperatura objetivo**: Ajusta la temperatura deseada (16-30°C)
- **Temperatura actual**: Muestra la temperatura ambiente

### En Automatizaciones

```yaml
# Ejemplo: Encender aire en modo frío a 24°C a las 18:00
automation:
  - alias: "Encender AAC Living"
    trigger:
      - platform: time
        at: "18:00:00"
    action:
      - service: climate.set_hvac_mode
        target:
          entity_id: climate.aac_living
        data:
          hvac_mode: cool
      - service: climate.set_temperature
        target:
          entity_id: climate.aac_living
        data:
          temperature: 24
      - service: climate.set_fan_mode
        target:
          entity_id: climate.aac_living
        data:
          fan_mode: medium
```

```yaml
# Ejemplo: Apagar cuando no hay nadie en casa
automation:
  - alias: "Apagar AAC al salir"
    trigger:
      - platform: state
        entity_id: binary_sensor.anyone_home
        to: 'off'
        for:
          minutes: 5
    action:
      - service: climate.turn_off
        target:
          entity_id: climate.aac_living
```

### En Scripts

```yaml
script:
  verano_noche:
    alias: "Modo verano - Noche"
    sequence:
      - service: climate.set_hvac_mode
        target:
          entity_id:
            - climate.aac_living
            - climate.aac_dormitorio_1
        data:
          hvac_mode: cool
      - service: climate.set_temperature
        target:
          entity_id:
            - climate.aac_living
            - climate.aac_dormitorio_1
        data:
          temperature: 22
      - service: climate.set_fan_mode
        target:
          entity_id:
            - climate.aac_living
            - climate.aac_dormitorio_1
        data:
          fan_mode: low
```

## Servicios Disponibles

### climate.set_hvac_mode
Cambia el modo de operación.

**Modos disponibles:**
- `off`: Apagado
- `cool`: Frío
- `heat`: Calor
- `dry`: Deshumidificación
- `fan_only`: Solo ventilación
- `auto`: Automático

### climate.set_temperature
Cambia la temperatura objetivo.

**Rango:** 16°C - 30°C

### climate.set_fan_mode
Cambia la velocidad del ventilador.

**Velocidades:**
- `low`: Baja
- `medium`: Media
- `high`: Alta

### climate.turn_on / climate.turn_off
Enciende o apaga el equipo.

## Troubleshooting

### El equipo no se conecta

1. Verifica que la IP sea correcta
2. Asegúrate de que el aire esté encendido y conectado al WiFi
3. Verifica que Home Assistant y el aire estén en la misma red (o con routing habilitado)
4. Prueba hacer ping a la IP del aire desde Home Assistant

### Los comandos no funcionan

1. Verifica los logs de Home Assistant:
   - **Configuración** → **Sistema** → **Logs**
   - Busca errores relacionados con `bgh_smart`
2. Verifica que no haya firewall bloqueando los puertos UDP 20910/20911
3. Asegúrate de que el Device ID se haya extraído correctamente (aparece en los logs al iniciar)

### El estado no se actualiza

1. El aire envía broadcasts automáticamente cuando cambia su estado
2. También hay polling de respaldo cada 5 segundos
3. Si usas el control remoto físico, el cambio debería reflejarse casi inmediatamente

## Limitaciones Conocidas

- **Swing/Turbo**: No implementado aún (en investigación)
- **Múltiples subredes**: Puede requerir configuración de routing para broadcasts UDP

---

## Protocolo UDP BGH Smart

### Arquitectura de Comunicación

El aire BGH Smart utiliza un protocolo **UDP bidireccional**:

```
┌─────────────┐         UDP 20910          ┌─────────────┐
│   Home      │ ─────────────────────────► │    Aire     │
│  Assistant  │                            │ Acondic.    │
│             │ ◄───────────────────────── │             │
└─────────────┘    Broadcast UDP 20911     └─────────────┘
                   (255.255.255.255)
```

**Envío de comandos (HA → Aire):**
- Puerto destino: **20910**
- Protocolo: UDP unicast a la IP del aire

**Recepción de estado (Aire → HA):**
- Puerto: **20911**
- El aire envía **broadcasts** a `255.255.255.255:20911`
- Es un sistema **publish/subscribe**, no request/response
- El aire publica su estado cada vez que cambia

### Device ID

Cada aire tiene un **Device ID único** de 6 bytes que se extrae del primer broadcast recibido. Este ID es esencial para que el aire acepte los comandos.

**Ubicación en broadcast:** Bytes 1-6 (después del byte 0x00 inicial)

Ejemplo: `accf2346a750`

### Estructura de Broadcasts (29 bytes)

```
Byte  0:     0x00 (header)
Bytes 1-6:   Device ID (ej: accf2346a750)
Bytes 7-12:  0xffffffffffff (broadcast marker)
Byte  13:    Contador/Secuencia
Bytes 14-17: 0x0100fd06 (fijo)
Byte  18:    Modo actual
Byte  19:    Velocidad ventilador
Byte  20:    Flags (swing, etc.)
Bytes 21-22: Temperatura actual (little-endian, ÷100)
Bytes 23-24: Temperatura objetivo (little-endian, ÷100)
Bytes 25-28: 0x00000000 (padding)
```

**Valores de Modo (Byte 18):**
| Valor | Modo |
|-------|------|
| 0     | Off |
| 1     | Cool (Frío) |
| 2     | Heat (Calor) |
| 3     | Dry (Deshumidificar) |
| 4     | Fan Only (Ventilación) |
| 254   | Auto |

**Valores de Ventilador (Byte 19):**
| Valor | Velocidad |
|-------|-----------|
| 1     | Low (Baja) |
| 2     | Medium (Media) |
| 3     | High (Alta) |

**Decodificación de Temperatura:**
```python
# Little-endian, dividido por 100
temp_raw = byte[21] + (byte[22] << 8)
temperatura = temp_raw / 100.0

# Ejemplo: bytes 0x98, 0x08 
# = 0x0898 = 2200 
# = 22.0°C
```

### Comando de Modo/Ventilador (22 bytes)

Cambia el modo de operación y velocidad del ventilador.

```
Bytes 0-6:   0x00000000000000 (padding)
Bytes 7-12:  Device ID
Byte  13:    0xf6 (comando de modo)
Bytes 14-16: 0x000161
Byte  17:    Modo (0=off, 1=cool, 2=heat, 3=dry, 4=fan, 254=auto)
Byte  18:    Ventilador (1=low, 2=medium, 3=high)
Bytes 19-21: 0x000080
```

**Ejemplo - Modo Cool, Fan Low:**
```
00000000000000accf2346a750f60001610101000080
```

### Comando de Temperatura (22 bytes)

Cambia la temperatura objetivo (y opcionalmente modo/ventilador).

```
Bytes 0-6:   0x00000000000000 (padding)
Bytes 7-12:  Device ID
Byte  13:    0x81 (comando de temperatura)
Bytes 14-16: 0x000161
Byte  17:    Modo
Byte  18:    Ventilador
Byte  19:    Flags (0x00 normal)
Bytes 20-21: Temperatura × 100 (little-endian)
```

**Ejemplo - 24°C, Cool, Fan High:**
```
00000000000000accf2346e65081000161010300 6009
                              │  │  │  │  └──┴─ Temp: 0x0960 = 2400 = 24°C
                              │  │  │  └─────── Flags: 0x00
                              │  │  └────────── Fan: 3 (high)
                              │  └───────────── Mode: 1 (cool)
                              └──────────────── Cmd: 0x81 (temp)
```

### Comando de Status Request (17 bytes)

Fuerza al aire a enviar un broadcast con su estado actual.

```
00000000000000accf23aa3190590001e4
```

**Nota:** El Device ID en este comando puede ser genérico; el aire responde si está en la red.

### Ejemplo de Flujo Completo

```
1. HA inicia → escucha broadcasts en puerto 20911

2. Aire envía broadcast:
   00accf2346a750ffffffffffff370100fd060103006009980800000000
   → HA extrae Device ID: accf2346a750
   → HA parsea: Mode=1(cool), Fan=3(high), Temp=25°C, Target=22°C

3. Usuario cambia temperatura a 24°C en HA

4. HA envía comando de temperatura:
   00000000000000accf2346a75081000161010300 6009
   → Puerto 20910, IP del aire

5. Aire recibe, procesa, y envía nuevo broadcast:
   00accf2346a750ffffffffffff380100fd060103006009600900000000
   → Target ahora es 24°C (0x0960)

6. HA recibe broadcast → actualiza UI
```

---

## Cambio de WiFi

El cambio de WiFi no está incluido en esta integración. Tu aire ya debe estar conectado a la red.

### Del manual oficial: 

Para volver tu aire acondicionado al **MODO CONECTAR**, tomá el control remoto del equipo y llevá el aire a 29°C y luego a 30°C, repetí esta secuencia hasta que el equipo se apague. Cuando vuelvas a encender el aire acondicionado, estará en MODO CONECTAR listo para volver a vincularse.

---

## Créditos

Desarrollado mediante ingeniería inversa del protocolo BGH Smart Control UDP, motivado por el anuncio de BGH de discontinuar el servicio cloud en 2026 tras el cierre de Solidmation (2018).

Agradecimientos:
- Comunidad de Home Assistant
- Usuarios que compartieron capturas de tráfico y configuraciones de Node-RED

## Licencia

MIT License

## Contribuciones

Issues y Pull Requests son bienvenidos.

---

¿Problemas? Abre un issue en GitHub.
