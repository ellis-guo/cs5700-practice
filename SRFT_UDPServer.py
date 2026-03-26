"""
SRFT_UDPServer.py
Orchestrates file transfer using Modules A, B, C, D.

Usage:
    sudo python3 SRFT_UDPServer.py [--ip IP] [--port PORT] [--files-dir DIR]
"""

import argparse
import threading
import time
import struct
import socket
import os
import hashlib
import hmac

from constants    import REQUEST, DATA, ACK, FIN, FIN_ACK, START, CHALLENGE, AUTH, AUTH_FAIL
from packet       import build_packet, parse_packet
from raw_socket   import create_sockets, send, recv
from reliability  import SendWindow
from file_handler import find_file, compute_md5

# ---------------------------------------------------------------------------
# Default Config (can be overridden by command-line arguments)
# ---------------------------------------------------------------------------

DEFAULT_SERVER_IP   = "127.0.0.1"
DEFAULT_SERVER_PORT = 9999
DEFAULT_FILES_DIR   = "./server_files"

CHUNK_SIZE  = 1400
WINDOW_SIZE = 256
TIMEOUT_MS  = 300

FIN_RETRIES = 5
FIN_TIMEOUT = 2.0

AUTH_TIMEOUT  = 5.0   # seconds to wait for AUTH after sending CHALLENGE
AUTH_RETRIES  = 3     # how many times to resend CHALLENGE before giving up


def load_psk():
    """Load pre-shared key from SRFT_PSK environment variable."""
    psk = os.environ.get("SRFT_PSK", "")
    if not psk:
        print("[Server] Error: SRFT_PSK environment variable not set.")
        print("[Server] Usage: export SRFT_PSK='your-secret-key'")
        raise SystemExit(1)
    return psk.encode("utf-8")


# ---------------------------------------------------------------------------
# Thread: send data packets
# ---------------------------------------------------------------------------

def send_thread(send_sock, window, server_ip, server_port, client_ip, client_port, stop_event):
    last_progress = -1
    last_timeout_check = time.time()

    while not stop_event.is_set():
        now = time.time()
        if now - last_timeout_check >= 0.1:
            window.check_timeouts()
            last_timeout_check = now

        result = window.get_next_to_send()

        if result is None:
            if window.all_acked():
                break
            time.sleep(0.001)
            continue

        seq, chunk = result
        packet = build_packet(
            server_ip, client_ip,
            server_port, client_port,
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

def ack_recv_thread(ack_sock, window, server_port, client_ip, client_port, stop_event):
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
        if pkt["dst_port"] != server_port:
            continue
        if not pkt["checksum_valid"] or not pkt["udp_checksum_valid"]:
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
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="SRFT UDP Server - Reliable file transfer over raw UDP sockets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: sudo python3 SRFT_UDPServer.py --ip 0.0.0.0 --port 8888"
    )
    parser.add_argument('--ip', type=str, default=DEFAULT_SERVER_IP,
                        help=f'Server IP address (default: {DEFAULT_SERVER_IP})')
    parser.add_argument('--port', type=int, default=DEFAULT_SERVER_PORT,
                        help=f'Server port (default: {DEFAULT_SERVER_PORT})')
    parser.add_argument('--files-dir', type=str, default=DEFAULT_FILES_DIR,
                        help=f'Directory containing files to serve (default: {DEFAULT_FILES_DIR})')
    args = parser.parse_args()

    # Validate arguments
    SERVER_IP = args.ip
    SERVER_PORT = args.port
    FILES_DIR = args.files_dir

    # Validate port range
    if not (1 <= SERVER_PORT <= 65535):
        print(f"[Server] Error: Invalid port {SERVER_PORT}. Must be 1-65535.")
        return

    # Validate IP address format
    try:
        socket.inet_aton(SERVER_IP)
    except socket.error:
        print(f"[Server] Error: Invalid IP address '{SERVER_IP}'")
        return

    # Validate files directory
    if not os.path.exists(FILES_DIR):
        print(f"[Server] Error: Files directory '{FILES_DIR}' does not exist")
        return
    if not os.path.isdir(FILES_DIR):
        print(f"[Server] Error: '{FILES_DIR}' is not a directory")
        return

    PSK = load_psk()

    send_sock, recv_sock = create_sockets()

    # Dedicated socket for receiving ACKs during transfer
    # Keeps ACK traffic separate from the main recv_sock used for REQUEST/FIN
    ack_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

    print(f"[Server] Listening on {SERVER_IP}:{SERVER_PORT} ...")
    print(f"[Server] Serving files from: {FILES_DIR}")

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
            if not pkt["checksum_valid"] or not pkt["udp_checksum_valid"]:
                continue
            if pkt["pkt_type"] != REQUEST:
                continue

            client_ip   = pkt["src_ip"]
            client_port = pkt["src_port"]
            filename    = pkt["data"].decode("utf-8").strip()

            print(f"[Server] REQUEST from {client_ip}:{client_port} — '{filename}'")
            break

        # ── Phase 1b: PSK challenge-response ─────────────────────────────

        auth_ok = False
        for attempt in range(AUTH_RETRIES):
            nonce = os.urandom(16)
            challenge_pkt = build_packet(
                SERVER_IP, client_ip,
                SERVER_PORT, client_port,
                CHALLENGE, 0, 0, nonce
            )
            send(send_sock, challenge_pkt, client_ip)
            print(f"[Server] Sent CHALLENGE (attempt {attempt + 1})")

            recv_sock.settimeout(AUTH_TIMEOUT)
            try:
                raw = recv(recv_sock)
            except Exception:
                print("[Server] AUTH timeout, resending CHALLENGE...")
                continue

            pkt = parse_packet(raw)
            if (pkt is None
                    or pkt["dst_port"] != SERVER_PORT
                    or not pkt["checksum_valid"]
                    or not pkt["udp_checksum_valid"]
                    or pkt["pkt_type"] != AUTH
                    or pkt["src_ip"] != client_ip
                    or pkt["src_port"] != client_port):
                print("[Server] Unexpected packet during auth, retrying...")
                continue

            expected = hmac.new(PSK, nonce, hashlib.sha256).digest()
            if hmac.compare_digest(expected, pkt["data"]):
                auth_ok = True
                print("[Server] AUTH successful")
                break
            else:
                print("[Server] AUTH failed: wrong HMAC")
                break

        if not auth_ok:
            fail_pkt = build_packet(
                SERVER_IP, client_ip,
                SERVER_PORT, client_port,
                AUTH_FAIL, 0, 0, b""
            )
            send(send_sock, fail_pkt, client_ip)
            print("[Server] Sent AUTH_FAIL, dropping connection")
            continue

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

        try:
            window     = SendWindow(filepath, CHUNK_SIZE, total_chunks, WINDOW_SIZE, TIMEOUT_MS)
        except IOError as e:
            print(f"[Server] Error creating send window: {e}")
            continue

        stop_flag  = threading.Event()
        start_time = time.time()

        # ── Send START packet to inform client of total chunks ──────────

        start_data = struct.pack("!I", total_chunks)
        start_pkt = build_packet(
            SERVER_IP, client_ip,
            SERVER_PORT, client_port,
            START, 0, 0, start_data
        )

        # Send START with retry (in case of packet loss)
        for attempt in range(3):
            send(send_sock, start_pkt, client_ip)
            time.sleep(0.05)  # Small delay between retries

        print(f"[Server] Sent START packet — total chunks: {total_chunks}")

        # ── Phase 2: transfer ─────────────────────────────────────────────

        try:
            t_send = threading.Thread(
                target=send_thread,
                args=(send_sock, window, SERVER_IP, SERVER_PORT, client_ip, client_port, stop_flag),
                daemon=True
            )
            t_ack = threading.Thread(
                target=ack_recv_thread,
                args=(ack_sock, window, SERVER_PORT, client_ip, client_port, stop_flag),
                daemon=True
            )

            t_send.start()
            t_ack.start()
            t_send.join()
            t_ack.join()

            stop_flag.set()
        finally:
            # Ensure file descriptor is always closed, even if exception occurs
            window.close()

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