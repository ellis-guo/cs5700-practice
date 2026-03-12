"""
SRFT_UDPServer.py
Orchestrates file transfer using Modules A, B, C, D.

Usage:
    sudo python3 SRFT_UDPServer.py
"""

import threading
import time
import struct
import socket

from constants    import REQUEST, DATA, ACK, FIN, FIN_ACK
from packet       import build_packet, parse_packet
from raw_socket   import create_sockets, send, recv
from reliability  import SendWindow
from file_handler import find_file, compute_md5
import os

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SERVER_IP   = "127.0.0.1"
SERVER_PORT = 9999
FILES_DIR   = "./server_files"

CHUNK_SIZE  = 1024
WINDOW_SIZE = 64   # Increased for better throughput
TIMEOUT_MS  = 1000  # Increased timeout for reliability

FIN_RETRIES = 5
FIN_TIMEOUT = 2.0


# ---------------------------------------------------------------------------
# Thread: send data packets
# ---------------------------------------------------------------------------

def send_thread(send_sock, window, client_ip, client_port, stop_event):
    last_progress = -1

    while not stop_event.is_set():
        window.check_timeouts()

        result = window.get_next_to_send()

        if result is None:
            if window.all_acked():
                break
            time.sleep(0.001)
            continue

        seq, chunk = result
        packet = build_packet(
            SERVER_IP, client_ip,
            SERVER_PORT, client_port,
            DATA, seq, 0, chunk
        )
        send(send_sock, packet, client_ip)
        window.mark_sent(seq)

        # Progress display (every 10%)
        progress = int((window.window_base / window.total_chunks) * 100)
        if progress // 10 > last_progress // 10:
            print(f"[Server] Progress: {progress}% ({window.window_base}/{window.total_chunks} chunks acked)")
            last_progress = progress

        if window.all_acked():
            break


# ---------------------------------------------------------------------------
# Thread: receive ACK packets (dedicated socket)
# ---------------------------------------------------------------------------

def ack_recv_thread(ack_sock, window, client_ip, client_port, stop_event):
    ack_sock.settimeout(0.5)

    while not stop_event.is_set():
        try:
            raw = recv(ack_sock)
        except Exception:
            if window.all_acked():
                break
            continue

        pkt = parse_packet(raw)
        if pkt is None:
            continue
        if pkt["dst_port"] != SERVER_PORT:
            continue
        if not pkt["checksum_valid"]:
            continue
        if pkt["pkt_type"] != ACK:
            continue
        if pkt["src_ip"] != client_ip or pkt["src_port"] != client_port:
            continue

        window.receive_ack(pkt["ack"])

        if window.all_acked():
            break


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    send_sock, recv_sock = create_sockets()

    # Dedicated socket for receiving ACKs during transfer
    # Keeps ACK traffic separate from the main recv_sock used for REQUEST/FIN
    ack_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

    print(f"[Server] Listening on {SERVER_IP}:{SERVER_PORT} ...")

    while True:

        # ── Phase 1: wait for REQUEST ─────────────────────────────────────
        recv_sock.settimeout(None)   # blocking, no timeout

        while True:
            raw = recv(recv_sock)
            pkt = parse_packet(raw)

            if pkt is None:
                continue
            if pkt["dst_port"] != SERVER_PORT:
                continue
            if not pkt["checksum_valid"]:
                continue
            if pkt["pkt_type"] != REQUEST:
                continue

            client_ip   = pkt["src_ip"]
            client_port = pkt["src_port"]
            filename    = pkt["data"].decode("utf-8").strip()

            print(f"[Server] REQUEST from {client_ip}:{client_port} — '{filename}'")
            break

        # ── Prepare file ──────────────────────────────────────────────────

        try:
            filepath     = find_file(filename, FILES_DIR)
            total_size   = os.path.getsize(filepath)
            total_chunks = (total_size + CHUNK_SIZE - 1) // CHUNK_SIZE  # ceil division
            original_md5 = compute_md5(filepath)
        except (FileNotFoundError, ValueError) as e:
            print(f"[Server] Error: {e}")
            continue

        print(f"[Server] Sending '{filename}' — {total_chunks} chunks, {total_size} bytes")

        window     = SendWindow(filepath, CHUNK_SIZE, total_chunks, WINDOW_SIZE, TIMEOUT_MS)
        stop_flag  = threading.Event()
        start_time = time.time()

        # ── Phase 2: transfer ─────────────────────────────────────────────

        t_send = threading.Thread(
            target=send_thread,
            args=(send_sock, window, client_ip, client_port, stop_flag),
            daemon=True
        )
        t_ack = threading.Thread(
            target=ack_recv_thread,
            args=(ack_sock, window, client_ip, client_port, stop_flag),
            daemon=True
        )

        t_send.start()
        t_ack.start()
        t_send.join()
        t_ack.join()

        stop_flag.set()

        # ── Phase 3: send FIN, wait for FIN_ACK ──────────────────────────

        fin_data = struct.pack("!I", total_chunks)
        fin_pkt  = build_packet(
            SERVER_IP, client_ip,
            SERVER_PORT, client_port,
            FIN, 0, 0, fin_data
        )

        recv_sock.settimeout(FIN_TIMEOUT)

        for attempt in range(FIN_RETRIES):
            send(send_sock, fin_pkt, client_ip)
            print(f"[Server] Sent FIN (attempt {attempt + 1})")

            try:
                raw = recv(recv_sock)
                pkt = parse_packet(raw)

                if (pkt and pkt["dst_port"] == SERVER_PORT
                        and pkt["checksum_valid"]
                        and pkt["pkt_type"] == FIN_ACK
                        and pkt["src_ip"] == client_ip):
                    print("[Server] Received FIN_ACK")
                    break
            except Exception:
                print("[Server] FIN_ACK timeout, retrying...")
        else:
            print("[Server] Warning: no FIN_ACK received after retries")

        # ── Report ────────────────────────────────────────────────────────

        elapsed = time.time() - start_time
        stats   = window.get_stats()
        hh, rem = divmod(int(elapsed), 3600)
        mm, ss  = divmod(rem, 60)

        report = f"""
==================================================
Name of the transferred file:              {filename}
Size of the transferred file:              {total_size} bytes
Number of packets sent from the server:    {stats['total_sent']}
Number of retransmitted packets:           {stats['total_retrans']}
Number of packets received from client:    {stats['total_acks']}
Time duration of the file transfer:        {hh:02d}:{mm:02d}:{ss:02d}
Original file MD5:                         {original_md5}
==================================================
"""
        print(report)

        report_path = f"./server_report_{filename}.txt"
        with open(report_path, "w") as f:
            f.write(report)
        print(f"[Server] Report saved to {report_path}")
        print(f"[Server] Listening on {SERVER_IP}:{SERVER_PORT} ...")


if __name__ == "__main__":
    main()