"""
SRFT_UDPClient.py
Orchestrates file receiving using Modules A, B, C, D.

Usage:
    sudo python3 SRFT_UDPClient.py
"""

import threading
import time
import struct
import sys

from constants    import REQUEST, DATA, ACK, FIN, FIN_ACK
from packet       import build_packet, parse_packet
from raw_socket   import create_sockets, send, recv
from reliability  import RecvBuffer
from file_handler import assemble_file, compute_md5

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SERVER_IP   = "127.0.0.1"
SERVER_PORT = 9999
CLIENT_PORT = 8888
SAVE_DIR    = "./client_downloads"

ACK_INTERVAL = 0.05   # seconds between cumulative ACK sends


# ---------------------------------------------------------------------------
# Thread: receive DATA packets
# ---------------------------------------------------------------------------

def data_recv_thread(recv_sock, buffer, client_port, server_ip, server_port, stop_event):
    recv_sock.settimeout(1.0)

    while not stop_event.is_set():
        try:
            raw = recv(recv_sock)
        except Exception:
            continue

        pkt = parse_packet(raw)
        if pkt is None:
            continue
        if pkt["dst_port"] != client_port:
            continue
        if not pkt["checksum_valid"]:
            print(f"[Client] Dropped packet: checksum invalid (seq={pkt['seq']})")
            continue
        if pkt["src_ip"] != server_ip or pkt["src_port"] != server_port:
            continue

        if pkt["pkt_type"] == DATA:
            buffer.receive_data(pkt["seq"], pkt["data"])

        elif pkt["pkt_type"] == FIN:
            # FIN payload carries total_chunks
            total_chunks = struct.unpack("!I", pkt["data"])[0]
            buffer.set_total_chunks(total_chunks)
            print(f"[Client] Received FIN — total chunks: {total_chunks}")
            stop_event.set()
            break


# ---------------------------------------------------------------------------
# Thread: send cumulative ACK packets
# ---------------------------------------------------------------------------

def ack_send_thread(send_sock, buffer, client_ip, client_port, server_ip, server_port, stop_event):
    while not stop_event.is_set():
        ack_num = buffer.get_cumulative_ack()

        pkt = build_packet(
            client_ip, server_ip,
            client_port, server_port,
            ACK, 0, ack_num, b""
        )
        send(send_sock, pkt, server_ip)

        time.sleep(ACK_INTERVAL)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    filename = input("Enter filename to request: ").strip()
    if not filename:
        print("[Client] No filename provided.")
        return

    send_sock, recv_sock = create_sockets()

    # Determine local IP (used as src_ip in packets)
    import socket
    client_ip = socket.gethostbyname(socket.gethostname())

    # ── Phase 1: send REQUEST ────────────────────────────────────────────

    req_pkt = build_packet(
        client_ip, SERVER_IP,
        CLIENT_PORT, SERVER_PORT,
        REQUEST, 0, 0, filename.encode("utf-8")
    )
    send(send_sock, req_pkt, SERVER_IP)
    print(f"[Client] Sent REQUEST for '{filename}'")

    buffer     = RecvBuffer()
    stop_flag  = threading.Event()

    # ── Phase 2: receive file ────────────────────────────────────────────

    t_data = threading.Thread(
        target=data_recv_thread,
        args=(recv_sock, buffer, CLIENT_PORT, SERVER_IP, SERVER_PORT, stop_flag),
        daemon=True
    )
    t_ack = threading.Thread(
        target=ack_send_thread,
        args=(send_sock, buffer, client_ip, CLIENT_PORT, SERVER_IP, SERVER_PORT, stop_flag),
        daemon=True
    )

    t_data.start()
    t_ack.start()
    t_data.join()

    # Give ACK thread one last cycle to send final ACK, then stop it
    time.sleep(ACK_INTERVAL * 2)
    stop_flag.set()
    t_ack.join()

    # ── Phase 3: assemble, verify, send FIN_ACK ─────────────────────────

    if not buffer.is_complete():
        total    = buffer.total_chunks
        received = len(buffer.buffer)
        print(f"[Client] Transfer incomplete: got {received}/{total} chunks")
        return

    print("[Client] All chunks received, assembling file...")

    output_path = f"{SAVE_DIR}/{filename}"
    chunks_dict = buffer.get_all_chunks()

    try:
        assemble_file(chunks_dict, output_path)
    except (ValueError, IOError) as e:
        print(f"[Client] Assembly failed: {e}")
        return

    received_md5 = compute_md5(output_path)
    print(f"[Client] MD5: {received_md5}")

    # Send FIN_ACK
    fin_ack_pkt = build_packet(
        client_ip, SERVER_IP,
        CLIENT_PORT, SERVER_PORT,
        FIN_ACK, 0, 0, b""
    )
    send(send_sock, fin_ack_pkt, SERVER_IP)
    print("[Client] Sent FIN_ACK")
    print(f"[Client] File saved to: {output_path}")


if __name__ == "__main__":
    main()