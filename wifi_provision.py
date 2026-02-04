"""BGH Smart AC WiFi provisioning module.

This module implements the WiFi provisioning protocol for BGH Smart AC units,
allowing devices in setup mode to receive WiFi credentials via UDP.

Protocol reverse-engineered from the official BGH Smart Control mobile app.

Usage:
    from bgh_smart.wifi_provision import BGHWiFiProvisioner

    provisioner = BGHWiFiProvisioner()

    # Discover device MAC (optional - listens for broadcasts)
    device_mac = await provisioner.async_discover_device()

    # Send WiFi credentials
    success = await provisioner.async_provision_wifi(
        device_ip="10.10.100.254",
        device_mac="aabbccddeeff",
        ssid="MyNetwork",
        password="MyPassword123",
        security_type=BGHWiFiProvisioner.SECURITY_WPA2,
        encryption_type=BGHWiFiProvisioner.ENCRYPTION_AES,
    )
"""
from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import Callable

from .const import UDP_RECV_PORT, UDP_SEND_PORT

_LOGGER = logging.getLogger(__name__)


class BGHWiFiProvisioner:
    """BGH Smart AC WiFi provisioning client.

    Implements the WiFi provisioning protocol used by BGH Smart AC units
    when in setup/provisioning mode (device broadcasting its own hotspot).

    Protocol details:
    - Command ID: 0xA1 (Join command)
    - Sub-Command: 0x03 (WiFi join request)
    - Packet size: 86 bytes (17-byte header + 69-byte payload)
    - UDP port: 20910 (command), 20911 (response/broadcast)
    """

    # Protocol constants
    PROTOCOL_VERSION = 0x00
    COMMAND_ID_JOIN = 0xA1  # 161 decimal
    SUBCMD_JOIN_REQUEST = 0x03
    SUBCMD_ENUMERATE = 0x04
    MAC_NONE = b'\x00' * 6

    # Packet sizes
    HEADER_SIZE = 17
    SSID_SIZE = 33
    PASSWORD_SIZE = 33
    PAYLOAD_SIZE = 69  # 1 + 33 + 1 + 1 + 33
    TOTAL_PACKET_SIZE = 86  # 17 + 69
    RESPONSE_SIZE = 17

    # Security types
    SECURITY_OPEN = 0x00
    SECURITY_WEP = 0x01
    SECURITY_WPA = 0x02
    SECURITY_WPA2 = 0x03

    # Encryption types
    ENCRYPTION_NONE = 0x00
    ENCRYPTION_WEP64 = 0x01
    ENCRYPTION_WEP128 = 0x02
    ENCRYPTION_TKIP = 0x03
    ENCRYPTION_AES = 0x04

    # Response codes
    RESPONSE_SUCCESS = 0x80

    # Default settings
    DEFAULT_DEVICE_IP = "10.10.100.254"
    DEFAULT_TIMEOUT = 3.0
    DEFAULT_RETRIES = 10

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
    ) -> None:
        """Initialize WiFi provisioner.

        Args:
            timeout: Socket timeout in seconds
            retries: Number of retry attempts for response
        """
        self._timeout = timeout
        self._retries = retries
        self._sequence_num = 1
        self._discovered_mac: bytes | None = None

    @staticmethod
    def parse_mac_address(mac_str: str) -> bytes:
        """Parse MAC address string to bytes.

        Supports formats: "aabbccddeeff", "aa:bb:cc:dd:ee:ff",
        "aa-bb-cc-dd-ee-ff", "aa.bb.cc.dd.ee.ff"

        Args:
            mac_str: MAC address as string

        Returns:
            6-byte MAC address

        Raises:
            ValueError: If MAC address format is invalid
        """
        mac_clean = mac_str.replace(':', '').replace('-', '').replace('.', '')
        if len(mac_clean) != 12:
            raise ValueError(
                f"Invalid MAC address: {mac_str}. Expected 12 hex characters."
            )
        try:
            return bytes.fromhex(mac_clean)
        except ValueError as err:
            raise ValueError(f"Invalid MAC address format: {mac_str}") from err

    @staticmethod
    def _pad_string(text: str, size: int) -> bytes:
        """Convert string to UTF-8 bytes and pad with null bytes.

        Args:
            text: String to encode
            size: Target size in bytes

        Returns:
            Padded byte array of exactly `size` bytes
        """
        encoded = text.encode('utf-8')
        if len(encoded) > size:
            encoded = encoded[:size]
        return encoded + b'\x00' * (size - len(encoded))

    def _build_header(self, device_mac: bytes) -> bytes:
        """Build 17-byte command header.

        Header structure:
        - Byte 0: Protocol version (0x00)
        - Bytes 1-6: Source MAC (0x00 × 6)
        - Bytes 7-12: Destination MAC (device MAC)
        - Byte 13: Sequence number
        - Byte 14: Source endpoint (0x00)
        - Byte 15: Destination endpoint (0x00)
        - Byte 16: Command ID (0xA1)

        Args:
            device_mac: 6-byte device MAC address

        Returns:
            17-byte header
        """
        return struct.pack(
            'B6s6sBBBB',
            self.PROTOCOL_VERSION,
            self.MAC_NONE,
            device_mac,
            self._sequence_num,
            0x00,  # Source endpoint
            0x00,  # Destination endpoint
            self.COMMAND_ID_JOIN,
        )

    def _build_payload(
        self,
        ssid: str,
        password: str,
        security_type: int,
        encryption_type: int,
    ) -> bytes:
        """Build 69-byte WiFi join request payload.

        Payload structure:
        - Byte 0: Sub-command (0x03)
        - Bytes 1-33: SSID (UTF-8, null-padded)
        - Byte 34: Security type
        - Byte 35: Encryption type
        - Bytes 36-68: Password (UTF-8, null-padded)

        Args:
            ssid: WiFi network name
            password: WiFi password
            security_type: Security type code (0-3)
            encryption_type: Encryption type code (0-4)

        Returns:
            69-byte payload
        """
        ssid_bytes = self._pad_string(ssid, self.SSID_SIZE)
        password_bytes = self._pad_string(password, self.PASSWORD_SIZE)

        return struct.pack(
            'B33sBB33s',
            self.SUBCMD_JOIN_REQUEST,
            ssid_bytes,
            security_type,
            encryption_type,
            password_bytes,
        )

    def build_provision_packet(
        self,
        device_mac: bytes,
        ssid: str,
        password: str,
        security_type: int = SECURITY_WPA2,
        encryption_type: int = ENCRYPTION_AES,
    ) -> bytes:
        """Build complete 86-byte WiFi provisioning packet.

        Args:
            device_mac: 6-byte device MAC address
            ssid: WiFi network name
            password: WiFi password
            security_type: Security type (default: WPA2)
            encryption_type: Encryption type (default: AES)

        Returns:
            86-byte provisioning packet

        Raises:
            RuntimeError: If packet size doesn't match expected
        """
        header = self._build_header(device_mac)
        payload = self._build_payload(ssid, password, security_type, encryption_type)
        packet = header + payload

        if len(packet) != self.TOTAL_PACKET_SIZE:
            raise RuntimeError(
                f"Packet size mismatch: {len(packet)} != {self.TOTAL_PACKET_SIZE}"
            )

        return packet

    def _validate_response(self, response: bytes) -> bool:
        """Validate WiFi join response packet.

        Expected response:
        - Length: 17 bytes
        - Byte 13: Matches sent sequence number
        - Byte 16: 0x80 (success code)

        Args:
            response: Response packet from device

        Returns:
            True if response is valid, False otherwise
        """
        if response is None:
            return False

        if len(response) != self.RESPONSE_SIZE:
            _LOGGER.debug(
                "Response size mismatch: %d != %d",
                len(response),
                self.RESPONSE_SIZE,
            )
            return False

        if response[13] != self._sequence_num:
            _LOGGER.debug(
                "Sequence number mismatch: %d != %d",
                response[13],
                self._sequence_num,
            )
            return False

        if response[16] != self.RESPONSE_SUCCESS:
            _LOGGER.debug(
                "Response code not success: 0x%02x != 0x%02x",
                response[16],
                self.RESPONSE_SUCCESS,
            )
            return False

        return True

    async def async_discover_device(
        self,
        timeout: float | None = None,
        callback: Callable[[bytes, tuple], None] | None = None,
    ) -> bytes | None:
        """Discover device MAC address from broadcasts.

        Listens for device broadcasts on UDP port 20911 to extract
        the device's MAC address. Device must be in provisioning mode.

        Args:
            timeout: Discovery timeout in seconds (default: instance timeout)
            callback: Optional callback for each received packet

        Returns:
            Device MAC as bytes, or None if discovery fails
        """
        if timeout is None:
            timeout = self._timeout * 2  # Allow more time for discovery

        _LOGGER.info("Discovering device MAC on UDP port %d...", UDP_RECV_PORT)

        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setblocking(False)

        try:
            sock.bind(('0.0.0.0', UDP_RECV_PORT))

            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 1024),
                    timeout=timeout,
                )

                _LOGGER.debug(
                    "Received %d bytes from %s: %s",
                    len(data),
                    addr,
                    data.hex(),
                )

                if callback:
                    callback(data, addr)

                # Device MAC is at bytes 1-6 (after initial 0x00)
                if len(data) >= 7:
                    mac = data[1:7]
                    self._discovered_mac = mac
                    _LOGGER.info("Discovered device MAC: %s", mac.hex())
                    return mac

                _LOGGER.warning("Packet too short to extract MAC: %d bytes", len(data))
                return None

            except asyncio.TimeoutError:
                _LOGGER.warning(
                    "Discovery timeout - no broadcasts received in %.1f seconds",
                    timeout,
                )
                return None

        except OSError as err:
            _LOGGER.error("Failed to bind discovery socket: %s", err)
            return None
        finally:
            sock.close()

    async def async_provision_wifi(
        self,
        device_ip: str,
        device_mac: str | bytes,
        ssid: str,
        password: str,
        security_type: int = SECURITY_WPA2,
        encryption_type: int = ENCRYPTION_AES,
    ) -> bool:
        """Send WiFi credentials to device.

        Args:
            device_ip: IP address of device (e.g., "10.10.100.254")
            device_mac: Device MAC as string or bytes
            ssid: WiFi network SSID
            password: WiFi network password
            security_type: Security type (0=Open, 1=WEP, 2=WPA, 3=WPA2)
            encryption_type: Encryption type (0=None, 1=WEP64, 2=WEP128, 3=TKIP, 4=AES)

        Returns:
            True if provisioning succeeded, False otherwise
        """
        # Parse MAC if string
        if isinstance(device_mac, str):
            device_mac_bytes = self.parse_mac_address(device_mac)
        else:
            device_mac_bytes = device_mac

        # Build packet
        packet = self.build_provision_packet(
            device_mac_bytes,
            ssid,
            password,
            security_type,
            encryption_type,
        )

        _LOGGER.info("WiFi provisioning:")
        _LOGGER.info("  Device IP: %s", device_ip)
        _LOGGER.info("  Device MAC: %s", device_mac_bytes.hex())
        _LOGGER.info("  SSID: %s", ssid)
        _LOGGER.info("  Security: %s", self._security_name(security_type))
        _LOGGER.info("  Encryption: %s", self._encryption_name(encryption_type))
        _LOGGER.debug("  Packet (%d bytes): %s", len(packet), packet.hex())

        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)

        try:
            # Send packet
            await loop.sock_sendto(sock, packet, (device_ip, UDP_SEND_PORT))
            _LOGGER.info("Sent provisioning packet to %s:%d", device_ip, UDP_SEND_PORT)

            # Wait for response with retries
            for attempt in range(self._retries):
                try:
                    response, addr = await asyncio.wait_for(
                        loop.sock_recvfrom(sock, 1024),
                        timeout=self._timeout,
                    )

                    _LOGGER.debug(
                        "Attempt %d/%d: Received %d bytes from %s",
                        attempt + 1,
                        self._retries,
                        len(response),
                        addr,
                    )
                    _LOGGER.debug("  Response: %s", response.hex())

                    if self._validate_response(response):
                        _LOGGER.info("✓ WiFi provisioning successful!")
                        _LOGGER.info(
                            "  Device should connect to '%s' within 10-30 seconds",
                            ssid,
                        )
                        return True

                except asyncio.TimeoutError:
                    _LOGGER.debug(
                        "Attempt %d/%d: No response (timeout)",
                        attempt + 1,
                        self._retries,
                    )
                    continue

            _LOGGER.warning("✗ WiFi provisioning failed - no valid response")
            return False

        except OSError as err:
            _LOGGER.error("Socket error during provisioning: %s", err)
            return False
        finally:
            sock.close()
            # Increment sequence number for next command
            self._sequence_num = (self._sequence_num + 1) % 256

    @staticmethod
    def _security_name(security_type: int) -> str:
        """Get human-readable security type name."""
        names = {
            0x00: "Open",
            0x01: "WEP",
            0x02: "WPA",
            0x03: "WPA2",
        }
        return names.get(security_type, f"Unknown ({security_type})")

    @staticmethod
    def _encryption_name(encryption_type: int) -> str:
        """Get human-readable encryption type name."""
        names = {
            0x00: "None",
            0x01: "WEP64",
            0x02: "WEP128",
            0x03: "TKIP",
            0x04: "AES",
        }
        return names.get(encryption_type, f"Unknown ({encryption_type})")

    @property
    def discovered_mac(self) -> bytes | None:
        """Return the last discovered device MAC."""
        return self._discovered_mac

    @property
    def discovered_mac_str(self) -> str | None:
        """Return the last discovered device MAC as hex string."""
        if self._discovered_mac:
            return self._discovered_mac.hex()
        return None


# Standalone usage support
async def provision_wifi_cli(
    device_ip: str,
    device_mac: str,
    ssid: str,
    password: str,
    security: int = BGHWiFiProvisioner.SECURITY_WPA2,
    encryption: int = BGHWiFiProvisioner.ENCRYPTION_AES,
) -> bool:
    """CLI helper for WiFi provisioning.

    Args:
        device_ip: Device IP address
        device_mac: Device MAC address
        ssid: WiFi SSID
        password: WiFi password
        security: Security type (default: WPA2)
        encryption: Encryption type (default: AES)

    Returns:
        True if successful
    """
    provisioner = BGHWiFiProvisioner()
    return await provisioner.async_provision_wifi(
        device_ip=device_ip,
        device_mac=device_mac,
        ssid=ssid,
        password=password,
        security_type=security,
        encryption_type=encryption,
    )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="BGH Smart AC WiFi Provisioning Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Provision WiFi with WPA2/AES (default)
  python -m bgh_smart.wifi_provision \\
    --device-ip 10.10.100.254 \\
    --device-mac aabbccddeeff \\
    --ssid "MyNetwork" \\
    --password "MyPassword123"

  # Discover device MAC first
  python -m bgh_smart.wifi_provision --discover

Security Types: 0=Open, 1=WEP, 2=WPA, 3=WPA2 (default)
Encryption Types: 0=None, 1=WEP64, 2=WEP128, 3=TKIP, 4=AES (default)
        """,
    )

    parser.add_argument(
        '--device-ip',
        default=BGHWiFiProvisioner.DEFAULT_DEVICE_IP,
        help=f'Device IP (default: {BGHWiFiProvisioner.DEFAULT_DEVICE_IP})',
    )
    parser.add_argument('--device-mac', help='Device MAC address')
    parser.add_argument('--ssid', help='WiFi SSID')
    parser.add_argument('--password', help='WiFi password')
    parser.add_argument(
        '--security',
        type=int,
        default=BGHWiFiProvisioner.SECURITY_WPA2,
        help='Security type (default: 3 for WPA2)',
    )
    parser.add_argument(
        '--encryption',
        type=int,
        default=BGHWiFiProvisioner.ENCRYPTION_AES,
        help='Encryption type (default: 4 for AES)',
    )
    parser.add_argument(
        '--discover',
        action='store_true',
        help='Discover device MAC from broadcasts',
    )
    parser.add_argument(
        '--timeout',
        type=float,
        default=BGHWiFiProvisioner.DEFAULT_TIMEOUT,
        help='Socket timeout in seconds',
    )

    args = parser.parse_args()

    # Configure logging for CLI
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s',
    )

    async def main() -> int:
        provisioner = BGHWiFiProvisioner(timeout=args.timeout)

        if args.discover:
            mac = await provisioner.async_discover_device()
            if mac:
                print(f"\nDiscovered device MAC: {mac.hex()}")
                print(f"Use with: --device-mac {mac.hex()}")
                return 0
            return 1

        if not args.device_mac or not args.ssid or not args.password:
            parser.print_help()
            print("\nError: --device-mac, --ssid, and --password are required")
            return 1

        success = await provisioner.async_provision_wifi(
            device_ip=args.device_ip,
            device_mac=args.device_mac,
            ssid=args.ssid,
            password=args.password,
            security_type=args.security,
            encryption_type=args.encryption,
        )

        return 0 if success else 1

    sys.exit(asyncio.run(main()))
