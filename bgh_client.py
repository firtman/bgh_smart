"""BGH Smart AC UDP client."""
from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import Any, Callable

from .const import (
    MODES,
    UDP_RECV_PORT,
    UDP_SEND_PORT,
)

_LOGGER = logging.getLogger(__name__)


class BGHClient:
    """BGH Smart AC UDP client - Broadcast listener.
    
    CHANGES APPLIED (Fix for 22-byte ACK packets causing 255°C readings):
    - Added _is_valid_status_packet() to validate packet structure
    - Strict filtering by packet length (only process 29-byte status packets)
    - Ignore ACK packets (22 bytes), discovery packets (108 bytes), and control responses (46-47 bytes)
    - Added temperature range validation (0-50°C ambient, 16-30°C target)
    - Increased broadcast timeout from 15s to 30s for more stable polling
    """

    def __init__(self, host: str) -> None:
        """Initialize the client."""
        self.host = host
        self._send_sock: socket.socket | None = None
        self._recv_sock: socket.socket | None = None
        self._listener_task: asyncio.Task | None = None
        self._current_mode = 0
        self._current_fan = 1
        self._last_status: dict[str, Any] = {}
        self._status_callback: Callable[[dict], None] | None = None
        self._device_id: str | None = None  # Device ID extraído de broadcasts

    async def async_connect(self) -> bool:
        """Connect to the AC unit and start listening for broadcasts."""
        try:
            _LOGGER.info("=== BGH Client connecting to %s ===", self.host)
            
            # Create sockets synchronously to avoid async issues
            try:
                self._recv_sock = self._create_recv_socket()
                _LOGGER.info("✓ Broadcast receive socket created")
            except Exception as e:
                _LOGGER.error("Failed to create receive socket: %s", e)
                return False
            
            try:
                self._send_sock = self._create_send_socket()
                _LOGGER.info("✓ Send socket created")
            except Exception as e:
                _LOGGER.error("Failed to create send socket: %s", e)
                if self._recv_sock:
                    self._recv_sock.close()
                return False
            
            # Start listener task
            _LOGGER.info("Starting broadcast listener task...")
            self._listener_task = asyncio.create_task(self._broadcast_listener())
            _LOGGER.info("✓ Broadcast listener task started")
            
            _LOGGER.info("BGH Client connected for %s", self.host)
            
            # Send initial status query to trigger a broadcast
            _LOGGER.info("Sending initial status request...")
            await self.async_request_status()
            _LOGGER.info("✓ Connection complete")
            
            return True
        except Exception as err:
            _LOGGER.error("Failed to connect to %s: %s", self.host, err)
            import traceback
            _LOGGER.error("Traceback: %s", traceback.format_exc())
            return False

    def _create_send_socket(self) -> socket.socket:
        """Create UDP send socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(5)
        # Don't bind - system assigns random source port
        _LOGGER.info("Send socket created")
        return sock

    def _create_recv_socket(self) -> socket.socket:
        """Create UDP broadcast receive socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        sock.bind(("", UDP_RECV_PORT))
        sock.setblocking(False)
        _LOGGER.info("Broadcast receive socket bound to port %d", UDP_RECV_PORT)
        return sock

    def _is_valid_status_packet(self, data: bytes) -> bool:
        """Validate if packet is a valid status broadcast (29 bytes).
        
        FIX ADDED: This function prevents processing of ACK packets (22 bytes) and 
        other non-status packets that were causing the "255°C" bug.
        
        Valid status packet structure:
        - Byte 0: 0x00 (header)
        - Bytes 1-6: Device ID
        - Bytes 7-12: 0xffffffffffff (broadcast marker)
        - Byte 13: Counter/Sequence
        - Bytes 14-17: Status flags (byte 14 should be 0x00 or 0x01)
        - Byte 18: Mode
        - Byte 19: Fan speed
        - Bytes 21-22: Current temperature
        - Bytes 23-24: Target temperature
        
        Returns:
            True if packet is a valid 29-byte status broadcast
        """
        if len(data) != 29:
            return False
        
        # Byte 0 debe ser 0x00
        if data[0] != 0x00:
            return False
        
        # Bytes 7-12 deben ser 0xffffffffffff (broadcast marker)
        # This distinguishes status broadcasts from command responses
        if data[7:13] != b'\xff\xff\xff\xff\xff\xff':
            return False
        
        # Bytes 14-17 deben ser aproximadamente 0x0100fd06 (puede variar levemente)
        # Solo verificamos que byte 14 sea razonable (0x00 o 0x01)
        if data[14] not in (0x00, 0x01):
            return False
        
        return True

    async def _broadcast_listener(self) -> None:
        """Listen for UDP broadcasts from the AC unit.
        
        FIX APPLIED: Added strict packet filtering to ignore:
        - 22-byte ACK packets (responses to commands)
        - 46-47 byte control response packets
        - 108-byte discovery packets
        Only 29-byte valid status broadcasts are processed.
        """
        _LOGGER.info("🎧 Broadcast listener started for %s", self.host)
        _LOGGER.info("   Listening on port %d for broadcasts from %s", UDP_RECV_PORT, self.host)
        
        broadcast_timeout = 0
        
        while True:
            try:
                if not self._recv_sock:
                    _LOGGER.warning("Receive socket is None, stopping listener")
                    break
                    
                loop = asyncio.get_event_loop()
                
                # Try to receive with timeout
                try:
                    data, addr = await asyncio.wait_for(
                        loop.sock_recvfrom(self._recv_sock, 1024),
                        timeout=30.0  # FIX: Increased from 15s to 30s for more stable operation
                    )
                    
                    # Reset timeout counter on successful receive
                    broadcast_timeout = 0
                    
                    # Only process broadcasts from our AC unit
                    if addr[0] != self.host:
                        continue
                    
                    _LOGGER.debug("📡 Received UDP packet from %s: %d bytes", addr, len(data))
                    
                    # FIX: STRICT PACKET FILTERING
                    # Problem: The AC sends multiple packet types:
                    # - 22 bytes: ACK responses to commands (contains garbage data)
                    # - 29 bytes: Valid status broadcasts (what we want)
                    # - 46-47 bytes: Control response packets
                    # - 108 bytes: Discovery/multicast packets
                    # Solution: Only process 29-byte packets with valid structure
                    
                    if len(data) == 22:
                        _LOGGER.debug("   Ignoring ACK packet (22 bytes) - causes 255°C bug")
                        continue
                    elif len(data) == 108:
                        _LOGGER.debug("   Ignoring discovery packet (108 bytes)")
                        continue
                    elif len(data) == 46 or len(data) == 47:
                        _LOGGER.debug("   Ignoring control response packet (%d bytes)", len(data))
                        continue
                    elif len(data) != 29:
                        _LOGGER.debug("   Ignoring unknown packet (%d bytes)", len(data))
                        continue
                    
                    # FIX: Validate packet structure before parsing
                    # This prevents processing malformed 29-byte packets
                    if not self._is_valid_status_packet(data):
                        _LOGGER.warning("   Invalid packet structure (29 bytes but wrong format)")
                        _LOGGER.debug("   Packet: %s", data.hex())
                        continue
                    
                    _LOGGER.info("✅ Valid status broadcast from %s: 29 bytes", addr)
                    
                    # Extract device ID from first broadcast (bytes 1-6, after initial 0x00)
                    if not self._device_id:
                        self._device_id = data[1:7].hex()
                        _LOGGER.info(">>> DEVICE ID EXTRACTED <<<")
                        _LOGGER.debug("    Raw broadcast: %s", data.hex())
                        _LOGGER.info("    Device ID: %s", self._device_id)
                    
                    status = self._parse_status(data)
                    
                    if status:
                        self._last_status = status
                        _LOGGER.info("   Parsed: mode=%s, fan=%s, temp=%.1f°C, target=%.1f°C", 
                                   status.get('mode'), 
                                   status.get('fan_speed'), 
                                   status.get('current_temperature', 0),
                                   status.get('target_temperature', 0))
                        if self._status_callback:
                            self._status_callback(status)
                        
                except asyncio.TimeoutError:
                    # No broadcast received in 30 seconds
                    broadcast_timeout += 1
                    
                    if broadcast_timeout == 1:
                        _LOGGER.warning("⚠️  No broadcasts received from %s (network issue?)", self.host)
                        _LOGGER.info("   Switching to polling mode...")
                    
                    # Request status when no broadcasts arrive
                    _LOGGER.debug("Polling: Requesting status from %s", self.host)
                    await self.async_request_status()
                    
                    # Wait a bit for the AC to respond with broadcast
                    await asyncio.sleep(2)
                            
            except asyncio.CancelledError:
                _LOGGER.info("Broadcast listener stopped for %s", self.host)
                break
            except Exception as err:
                _LOGGER.error("Error in broadcast listener: %s", err)
                import traceback
                _LOGGER.error("Traceback: %s", traceback.format_exc())
                await asyncio.sleep(1)

    async def async_request_status(self) -> None:
        """Request status update (triggers a broadcast from the AC)."""
        try:
            # Status command doesn't need device ID
            CMD_STATUS = "00000000000000accf23aa3190590001e4"
            command = bytes.fromhex(CMD_STATUS)
            await self._send_command(command)
            _LOGGER.debug("Status request sent to %s", self.host)
        except Exception as err:
            _LOGGER.error("Failed to request status: %s", err)

    async def async_get_status(self) -> dict[str, Any] | None:
        """Get current status (returns last received broadcast)."""
        # If we don't have status yet, request one and wait a bit
        if not self._last_status:
            await self.async_request_status()
            await asyncio.sleep(1)
        
        return self._last_status if self._last_status else None

    async def async_set_mode(
        self,
        mode: int,
        fan_speed: int | None = None,
    ) -> bool:
        """Set AC mode and fan speed."""
        try:
            # Wait for device ID to be extracted from broadcasts
            if not self._device_id:
                _LOGGER.warning("Device ID not yet extracted, waiting for broadcast...")
                await asyncio.sleep(2)
                if not self._device_id:
                    _LOGGER.error("Cannot send command without Device ID")
                    return False
            
            # Update current state
            self._current_mode = mode
            if fan_speed is not None:
                self._current_fan = fan_speed

            # Build control command with device ID
            # Format: 00000000000000[DEVICE_ID]f6000161[MODE][FAN]000080
            # Based on Node-RED: mode at byte 17, fan at byte 18
            cmd_base = f"00000000000000{self._device_id}f60001610402000080"
            command = bytearray(bytes.fromhex(cmd_base))
            command[17] = self._current_mode
            command[18] = self._current_fan

            _LOGGER.info("Sending mode command: mode=%d, fan=%d, device_id=%s",
                        self._current_mode, self._current_fan, self._device_id)
            await self._send_command(bytes(command))
            
            # Wait a bit for AC to process
            await asyncio.sleep(0.5)  # FIX: Reduced from 0.3s to 0.5s for better reliability
            
            # Request status update (will trigger broadcast)
            await self.async_request_status()
            
            return True
        except Exception as err:
            _LOGGER.error("Failed to set mode on %s: %s", self.host, err)
            import traceback
            _LOGGER.error("Traceback: %s", traceback.format_exc())
            return False

    async def async_set_temperature(self, temperature: float) -> bool:
        """Set target temperature."""
        try:
            # Wait for device ID to be extracted from broadcasts
            if not self._device_id:
                _LOGGER.warning("Device ID not yet extracted, waiting for broadcast...")
                await asyncio.sleep(2)
                if not self._device_id:
                    _LOGGER.error("Cannot send command without Device ID")
                    return False

            # Build temperature command with device ID
            # Format: 00000000000000[DEVICE_ID]8100016101[MODE][FAN]00[TEMP_LO][TEMP_HI]
            # Byte 13 = 0x81 (temperature command)
            # Bytes 17-18 = mode and fan (current values)
            # Bytes 20-21 = temperature * 100 in little-endian
            cmd_base = f"00000000000000{self._device_id}810001610100000000"
            command = bytearray(bytes.fromhex(cmd_base))
            command[17] = self._current_mode
            command[18] = self._current_fan
            
            # Temperature as 16-bit little-endian, multiplied by 100
            temp_raw = int(temperature * 100)
            command[20] = temp_raw & 0xFF         # Low byte
            command[21] = (temp_raw >> 8) & 0xFF  # High byte

            _LOGGER.info("Sending temperature command: temp=%.1f°C, mode=%d, fan=%d, device_id=%s",
                        temperature, self._current_mode, self._current_fan, self._device_id)
            _LOGGER.debug("Temperature command hex: %s", bytes(command).hex())
            await self._send_command(bytes(command))
            
            # Wait a bit for AC to process
            await asyncio.sleep(0.5)  # FIX: Reduced from 0.3s to 0.5s
            
            # Request status update (will trigger broadcast)
            await self.async_request_status()
            
            return True
        except Exception as err:
            _LOGGER.error("Failed to set temperature on %s: %s", self.host, err)
            import traceback
            _LOGGER.error("Traceback: %s", traceback.format_exc())
            return False

    async def _send_command(self, command: bytes) -> None:
        """Send UDP command - creates new socket each time like working test."""
        _LOGGER.debug("Sending %d bytes to %s:%d", len(command), self.host, UDP_SEND_PORT)
        
        # Create new socket, send, close - just like the working test script
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(command, (self.host, UDP_SEND_PORT))
            _LOGGER.debug("Sent command: %s", command.hex())
        finally:
            sock.close()

    def _parse_status(self, data: bytes) -> dict[str, Any]:
        """Parse status response.
        
        FIX APPLIED: Added temperature range validation to prevent 255°C readings
        from corrupted/invalid packets.
        """
        if len(data) < 25:
            _LOGGER.warning("Invalid status data length: %d", len(data))
            return {}

        try:
            # Extract data according to Node-RED flow
            mode = data[18]
            fan_speed = data[19]
            
            # Temperature is in bytes 21-22 (little-endian, divided by 100)
            temp_raw = struct.unpack("<H", data[21:23])[0]
            current_temp = temp_raw / 100.0
            
            # Setpoint is in bytes 23-24
            setpoint_raw = struct.unpack("<H", data[23:25])[0]
            target_temp = setpoint_raw / 100.0

            # FIX: Validate temperature ranges
            # Problem: 22-byte ACK packets were parsed as status, resulting in 
            # garbage data being interpreted as temperature (e.g., 25500 = 255°C)
            # Solution: Reject packets with unreasonable temperature values
            if not (0 <= current_temp <= 50):
                _LOGGER.warning("Invalid current temperature: %.1f°C (out of range 0-50)", current_temp)
                return {}
            
            if not (16 <= target_temp <= 30):
                _LOGGER.warning("Invalid target temperature: %.1f°C (out of range 16-30)", target_temp)
                return {}

            status = {
                "mode": MODES.get(mode, "unknown"),
                "mode_raw": mode,
                "fan_speed": fan_speed,
                "current_temperature": current_temp,
                "target_temperature": target_temp,
                "is_on": mode != 0,
            }

            # Update internal state
            self._current_mode = mode
            self._current_fan = fan_speed

            _LOGGER.debug("Parsed status from %s: %s", self.host, status)
            return status
            
        except Exception as e:
            _LOGGER.error("Error parsing status: %s", e)
            return {}

    async def async_close(self) -> None:
        """Close the connection."""
        if self._listener_task:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
            self._listener_task = None
            
        if self._send_sock:
            self._send_sock.close()
            self._send_sock = None
            
        if self._recv_sock:
            self._recv_sock.close()
            self._recv_sock = None
