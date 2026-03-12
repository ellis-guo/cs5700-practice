"""
Module B: Socket
Role: Send bytes out, receive bytes in. Nothing else.

Does NOT parse packets, does NOT filter by port, does NOT make decisions.
Timeout control is the caller's responsibility (use recv_sock.settimeout()).
"""

import socket


def create_sockets():
    """
    Create one send socket and one receive socket.

    Returns:
        (send_sock, recv_sock)

    Requires root/sudo privilege.
    """
    # IPPROTO_RAW: we supply the complete IP header ourselves
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Increase send buffer for better throughput with large files
    send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)  # 4MB

    # IPPROTO_UDP: receives all UDP traffic arriving at this machine
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

    # Increase receive buffer to handle high packet rate
    recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)  # 4MB

    return send_sock, recv_sock


def send(send_sock, packet_bytes, dst_ip):
    """
    Send a complete packet. packet_bytes must already contain IP and UDP headers.

    Port is 0 because destination port is already encoded inside packet_bytes.
    """
    send_sock.sendto(packet_bytes, (dst_ip, 0))


def recv(recv_sock):
    """
    Block until a packet arrives. Returns raw bytes including IP and UDP headers.

    Caller is responsible for setting timeout via recv_sock.settimeout().
    """
    raw_bytes, _ = recv_sock.recvfrom(65535)
    return raw_bytes