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
    """Standard Internet Checksum over arbitrary bytes. Returns 16-bit int."""
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

    # UDP header (checksum=0, optional in IPv4)
    payload    = custom_header + data
    udp_header = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)

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

    Returns a dict of fields, or None if the packet is too short.
    Does NOT discard invalid packets — caller decides what to do with checksum_valid=False.
    """
    if len(raw_bytes) < 41:
        return None

    # IP header
    ip_fields = struct.unpack("!BBHHHBBH4s4s", raw_bytes[0:20])
    src_ip    = socket.inet_ntoa(ip_fields[8])
    dst_ip    = socket.inet_ntoa(ip_fields[9])

    # UDP header
    udp_fields = struct.unpack("!HHHH", raw_bytes[20:28])
    src_port   = udp_fields[0]
    dst_port   = udp_fields[1]

    # Custom protocol header
    custom_fields     = struct.unpack(CUSTOM_HEADER_FORMAT, raw_bytes[28:41])
    pkt_type          = custom_fields[0]
    seq               = custom_fields[1]
    ack               = custom_fields[2]
    data_len          = custom_fields[3]
    received_checksum = custom_fields[4]

    # Data
    data = raw_bytes[41:41 + data_len]

    # Verify checksum: zero out checksum field, recompute, compare
    custom_header_zeroed = struct.pack(CUSTOM_HEADER_FORMAT, pkt_type, seq, ack, data_len, 0)
    checksum_valid       = (compute_checksum(custom_header_zeroed + data) == received_checksum)

    return {
        "src_ip":         src_ip,
        "dst_ip":         dst_ip,
        "src_port":       src_port,
        "dst_port":       dst_port,
        "pkt_type":       pkt_type,
        "seq":            seq,
        "ack":            ack,
        "data_len":       data_len,
        "data":           data,
        "checksum_valid": checksum_valid
    }