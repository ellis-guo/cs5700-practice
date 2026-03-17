"""
Module A: Packet
Role: Convert between fields and bytes. Nothing else.
"""

import socket
import struct

from constants import REQUEST, DATA, ACK, FIN, FIN_ACK

# Custom protocol header: type(1B) + seq(4B) + ack(4B) + data_len(2B) + checksum(2B)
CUSTOM_HEADER_FORMAT = "!BIIHH"
CUSTOM_HEADER_SIZE   = 13


def compute_checksum(data):
    """
    Standard Internet Checksum over arbitrary bytes. Returns 16-bit int.

    Args:
        data: bytes to checksum (will be padded if odd length)

    Returns:
        16-bit checksum value
    """
    if not data:
        return 0

    # Pad to even length if necessary
    if len(data) % 2 != 0:
        data += b'\x00'

    total = 0
    for i in range(0, len(data), 2):
        word = struct.unpack("!H", data[i:i+2])[0]
        total += word

    # Fold 32-bit sum into 16 bits by adding carry back
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return ~total & 0xFFFF


def compute_udp_checksum(src_ip, dst_ip, udp_header, payload):
    """
    Compute UDP checksum including pseudo-header.

    UDP checksum = checksum(pseudo-header + UDP header + payload)
    Pseudo-header: src_ip(4) + dst_ip(4) + zero(1) + protocol(1) + udp_len(2)

    Args:
        src_ip: source IP string (e.g., "192.168.1.1")
        dst_ip: destination IP string
        udp_header: UDP header bytes (8 bytes with checksum=0)
        payload: UDP payload bytes

    Returns:
        16-bit UDP checksum value (0 if computation fails)
    """
    try:
        src_bytes = socket.inet_aton(src_ip)
        dst_bytes = socket.inet_aton(dst_ip)
    except (OSError, socket.error):
        # Invalid IP address - return 0 (checksum disabled)
        return 0

    udp_len = len(udp_header) + len(payload)

    # Validate UDP length fits in 16 bits
    if udp_len > 65535:
        return 0

    # Build pseudo-header: src_ip(4) + dst_ip(4) + zero(1) + protocol(1) + udp_len(2)
    pseudo_header = src_bytes + dst_bytes + b'\x00' + struct.pack("!BH", socket.IPPROTO_UDP, udp_len)

    # Compute checksum over pseudo-header + UDP header + payload
    return compute_checksum(pseudo_header + udp_header + payload)


def build_packet(src_ip, dst_ip, src_port, dst_port, pkt_type, seq, ack, data):
    """
    Build a complete raw packet: IP header + UDP header + custom header + data.

    Returns bytes ready to pass to socket.sendto().
    """
    if isinstance(data, str):
        data = data.encode('utf-8')

    data_len = len(data)

    # Build custom header with checksum=0, compute real checksum, rebuild
    custom_header = struct.pack(CUSTOM_HEADER_FORMAT, pkt_type, seq, ack, data_len, 0)
    checksum      = compute_checksum(custom_header + data)
    custom_header = struct.pack(CUSTOM_HEADER_FORMAT, pkt_type, seq, ack, data_len, checksum)

    # UDP header: build with checksum=0, then compute real checksum
    payload = custom_header + data
    udp_length = 8 + len(payload)

    # Build UDP header with checksum=0 first
    udp_header_zeroed = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)

    # Compute real UDP checksum (including pseudo-header)
    udp_checksum = compute_udp_checksum(src_ip, dst_ip, udp_header_zeroed, payload)

    # Rebuild UDP header with real checksum
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, udp_checksum)

    # IP header: build twice — first to compute checksum, then with real value
    src_bytes    = socket.inet_aton(src_ip)
    dst_bytes    = socket.inet_aton(dst_ip)
    total_length = 20 + 8 + len(payload)

    ip_header   = struct.pack("!BBHHHBBH4s4s",
                    (4 << 4) + 5, 0, total_length, 1, 0,
                    64, socket.IPPROTO_UDP, 0, src_bytes, dst_bytes)
    ip_checksum = compute_checksum(ip_header)
    ip_header   = struct.pack("!BBHHHBBH4s4s",
                    (4 << 4) + 5, 0, total_length, 1, 0,
                    64, socket.IPPROTO_UDP, ip_checksum, src_bytes, dst_bytes)

    return ip_header + udp_header + custom_header + data


def parse_packet(raw_bytes):
    """
    Parse a raw packet from the network.

    Returns a dict of fields, or None if the packet is too short or malformed.
    Validates both UDP checksum and custom protocol checksum.
    Caller should check checksum_valid and udp_checksum_valid before accepting packet.

    Returns:
        dict with packet fields, or None if packet is invalid
    """
    # Minimum packet: IP(20) + UDP(8) + Custom(13) = 41 bytes
    if not raw_bytes or len(raw_bytes) < 41:
        return None

    try:
        # IP header
        ip_fields = struct.unpack("!BBHHHBBH4s4s", raw_bytes[0:20])
        src_ip    = socket.inet_ntoa(ip_fields[8])
        dst_ip    = socket.inet_ntoa(ip_fields[9])

        # UDP header
        udp_fields = struct.unpack("!HHHH", raw_bytes[20:28])
        src_port          = udp_fields[0]
        dst_port          = udp_fields[1]
        udp_length        = udp_fields[2]
        received_udp_csum = udp_fields[3]

        # Validate UDP length
        if udp_length < 8 or udp_length > len(raw_bytes) - 20:
            return None

        # Extract UDP payload
        udp_payload = raw_bytes[28:20 + udp_length]

        # Verify UDP checksum (if not 0, which means disabled)
        udp_checksum_valid = True
        if received_udp_csum != 0:
            # Recompute UDP checksum
            udp_header_zeroed = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)
            computed_udp_csum = compute_udp_checksum(src_ip, dst_ip, udp_header_zeroed, udp_payload)
            udp_checksum_valid = (computed_udp_csum == received_udp_csum)

        # Custom protocol header (minimum 13 bytes)
        if len(udp_payload) < CUSTOM_HEADER_SIZE:
            return None

        custom_fields     = struct.unpack(CUSTOM_HEADER_FORMAT, udp_payload[0:CUSTOM_HEADER_SIZE])
        pkt_type          = custom_fields[0]
        seq               = custom_fields[1]
        ack               = custom_fields[2]
        data_len          = custom_fields[3]
        received_checksum = custom_fields[4]

        # Validate data_len
        if data_len < 0 or CUSTOM_HEADER_SIZE + data_len > len(udp_payload):
            return None

        # Extract data
        data = udp_payload[CUSTOM_HEADER_SIZE:CUSTOM_HEADER_SIZE + data_len]

        # Verify custom protocol checksum
        custom_header_zeroed = struct.pack(CUSTOM_HEADER_FORMAT, pkt_type, seq, ack, data_len, 0)
        checksum_valid       = (compute_checksum(custom_header_zeroed + data) == received_checksum)

        return {
            "src_ip":              src_ip,
            "dst_ip":              dst_ip,
            "src_port":            src_port,
            "dst_port":            dst_port,
            "pkt_type":            pkt_type,
            "seq":                 seq,
            "ack":                 ack,
            "data_len":            data_len,
            "data":                data,
            "checksum_valid":      checksum_valid,
            "udp_checksum_valid":  udp_checksum_valid
        }

    except (struct.error, IndexError, OSError):
        # Malformed packet - return None
        return None