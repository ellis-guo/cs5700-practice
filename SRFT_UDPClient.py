"""
SRFT_UDPClient.py
Orchestrates file receiving using Modules A, B, C, D.

Usage:
    sudo python3 SRFT_UDPClient.py [--server-ip IP] [--server-port PORT] [--client-port PORT] [--save-dir DIR] [filename]
"""

import argparse
import threading
import time
import struct
import sys
import os
import hashlib
import hmac

from constants    import REQUEST, DATA, ACK, FIN, FIN_ACK, START, CHALLENGE, AUTH, AUTH_FAIL
from packet       import build_packet, parse_packet
from raw_socket   import create_sockets, send, recv
from reliability  import RecvBuffer
from file_handler import assemble_file, compute_md5

# ---------------------------------------------------------------------------
# Default Config (can be overridden by command-line arguments)
# ---------------------------------------------------------------------------

DEFAULT_SERVER_IP   = "127.0.0.1"
DEFAULT_SERVER_PORT = 9999
DEFAULT_CLIENT_PORT = 8888
DEFAULT_SAVE_DIR    = "./client_downloads"

ACK_BATCH_SIZE     = 16      # batch trigger: send ACK every N new packets
ACK_TIMEOUT        = 0.02    # 20ms timeout trigger for tail packets
ACK_CHECK_INTERVAL = 0.001   # 1ms polling interval

AUTH_TIMEOUT = 5.0   # seconds to wait for CHALLENGE after sending REQUEST


def load_psk():
    """Load pre-shared key from SRFT_PSK environment variable."""
    psk = os.environ.get("SRFT_PSK", "")
    if not psk:
        print("[Client] Error: SRFT_PSK environment variable not set.")
        print("[Client] Usage: export SRFT_PSK='your-secret-key'")
        raise SystemExit(1)
    return psk.encode("utf-8")


# ---------------------------------------------------------------------------
# Thread: receive DATA packets
# ---------------------------------------------------------------------------

def data_recv_thread(recv_sock, buffer, client_port, server_ip, server_port, stop_event):
    recv_sock.settimeout(1.0)
    last_progress = -1  # Track progress for display (every 10%)

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
        if not pkt["checksum_valid"] or not pkt["udp_checksum_valid"]:
            buffer.record_checksum_error()
            print(f"[Client] Dropped packet: checksum invalid (seq={pkt.get('seq', 'unknown')})")
            continue
        if pkt["src_ip"] != server_ip or pkt["src_port"] != server_port:
            continue

        if pkt["pkt_type"] == START:
            # START packet: server tells us total chunks before data transfer
            if len(pkt["data"]) >= 4:
                total_chunks = struct.unpack("!I", pkt["data"][:4])[0]
                buffer.set_total_chunks(total_chunks)
                print(f"[Client] Received START — total chunks: {total_chunks}")

        elif pkt["pkt_type"] == DATA:
            buffer.receive_data(pkt["seq"], pkt["data"])

            # Display progress (every 10% if total_chunks is known)
            if buffer.total_chunks and buffer.total_chunks > 0:
                received_count = len(buffer.buffer)
                progress = int((received_count / buffer.total_chunks) * 100)
                if progress // 10 > last_progress // 10:
                    print(f"[Client] Progress: {progress}% ({received_count}/{buffer.total_chunks} chunks received)")
                    last_progress = progress

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
    """Send cumulative ACKs using batch + timeout strategy."""
    last_ack_time  = time.time()
    last_acked_seq = 0

    while not stop_event.is_set():
        ack_num = buffer.get_cumulative_ack()

        should_send = False
        if ack_num - last_acked_seq >= ACK_BATCH_SIZE:
            should_send = True
        elif ack_num > 0 and time.time() - last_ack_time >= ACK_TIMEOUT:
            should_send = True

        if should_send:
            pkt = build_packet(
                client_ip, server_ip,
                client_port, server_port,
                ACK, 0, ack_num, b""
            )
            send(send_sock, pkt, server_ip)
            last_acked_seq = ack_num
            last_ack_time  = time.time()

        time.sleep(ACK_CHECK_INTERVAL)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="SRFT UDP Client - Request and receive files via reliable UDP transfer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: sudo python3 SRFT_UDPClient.py --server-ip 10.0.0.5 --server-port 8888 photo.jpg"
    )
    parser.add_argument('--server-ip', type=str, default=DEFAULT_SERVER_IP,
                        help=f'Server IP address (default: {DEFAULT_SERVER_IP})')
    parser.add_argument('--server-port', type=int, default=DEFAULT_SERVER_PORT,
                        help=f'Server port (default: {DEFAULT_SERVER_PORT})')
    parser.add_argument('--client-port', type=int, default=DEFAULT_CLIENT_PORT,
                        help=f'Client port (default: {DEFAULT_CLIENT_PORT})')
    parser.add_argument('--save-dir', type=str, default=DEFAULT_SAVE_DIR,
                        help=f'Directory to save received files (default: {DEFAULT_SAVE_DIR})')
    parser.add_argument('filename', nargs='?', type=str,
                        help='Filename to request from server (optional, will prompt if not provided)')
    args = parser.parse_args()

    # Validate arguments
    SERVER_IP = args.server_ip
    SERVER_PORT = args.server_port
    CLIENT_PORT = args.client_port
    SAVE_DIR = args.save_dir

    # Validate port ranges
    if not (1 <= SERVER_PORT <= 65535):
        print(f"[Client] Error: Invalid server port {SERVER_PORT}. Must be 1-65535.")
        return
    if not (1 <= CLIENT_PORT <= 65535):
        print(f"[Client] Error: Invalid client port {CLIENT_PORT}. Must be 1-65535.")
        return

    # Validate IP address format
    import socket
    try:
        socket.inet_aton(SERVER_IP)
    except socket.error:
        print(f"[Client] Error: Invalid server IP address '{SERVER_IP}'")
        return

    # Get filename from argument or prompt
    filename = args.filename
    if not filename:
        filename = input("Enter filename to request: ").strip()
    if not filename:
        print("[Client] No filename provided.")
        return

    print(f"[Client] Connecting to {SERVER_IP}:{SERVER_PORT}")
    print(f"[Client] Files will be saved to: {SAVE_DIR}")

    PSK = load_psk()

    send_sock, recv_sock = create_sockets()

    # Determine local IP (used as src_ip in packets)
    client_ip = socket.gethostbyname(socket.gethostname())

    # ── Phase 1: send REQUEST ────────────────────────────────────────────

    req_pkt = build_packet(
        client_ip, SERVER_IP,
        CLIENT_PORT, SERVER_PORT,
        REQUEST, 0, 0, filename.encode("utf-8")
    )
    send(send_sock, req_pkt, SERVER_IP)
    print(f"[Client] Sent REQUEST for '{filename}'")

    # ── Phase 1b: PSK challenge-response ────────────────────────────────

    recv_sock.settimeout(AUTH_TIMEOUT)
    while True:
        try:
            raw = recv(recv_sock)
        except Exception:
            print("[Client] Timeout waiting for CHALLENGE, resending REQUEST...")
            send(send_sock, req_pkt, SERVER_IP)
            continue

        pkt = parse_packet(raw)
        if (pkt is None
                or pkt["dst_port"] != CLIENT_PORT
                or not pkt["checksum_valid"]
                or not pkt["udp_checksum_valid"]
                or pkt["src_ip"] != SERVER_IP
                or pkt["src_port"] != SERVER_PORT):
            continue

        if pkt["pkt_type"] == AUTH_FAIL:
            print("[Client] Server rejected authentication. Check SRFT_PSK.")
            return

        if pkt["pkt_type"] != CHALLENGE:
            continue

        nonce = pkt["data"]
        digest = hmac.new(PSK, nonce, hashlib.sha256).digest()
        auth_pkt = build_packet(
            client_ip, SERVER_IP,
            CLIENT_PORT, SERVER_PORT,
            AUTH, 0, 0, digest
        )
        send(send_sock, auth_pkt, SERVER_IP)
        print("[Client] Sent AUTH")
        break

    recv_sock.settimeout(None)

    buffer     = RecvBuffer()
    stop_flag  = threading.Event()
    start_time = time.time()  # Track transfer duration

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
    time.sleep(ACK_TIMEOUT * 2)
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

    # Send FIN_ACK
    fin_ack_pkt = build_packet(
        client_ip, SERVER_IP,
        CLIENT_PORT, SERVER_PORT,
        FIN_ACK, 0, 0, b""
    )
    send(send_sock, fin_ack_pkt, SERVER_IP)
    print("[Client] Sent FIN_ACK")

    # ── Generate and save report ─────────────────────────────────────────

    elapsed = time.time() - start_time
    stats = buffer.get_stats()
    hh, rem = divmod(int(elapsed), 3600)
    mm, ss = divmod(rem, 60)

    # Get file size from assembled file
    total_size = os.path.getsize(output_path) if os.path.exists(output_path) else 0

    report = f"""
==================================================
CLIENT REPORT
==================================================
Name of the transferred file:              {filename}
Size of the transferred file:              {total_size} bytes
Number of packets received from server:    {stats['total_received']}
Number of duplicate packets:               {stats['duplicate_count']}
Number of out-of-order packets:            {stats['out_of_order_count']}
Number of packets with checksum errors:    {stats['checksum_errors']}
Time duration of the file transfer:        {hh:02d}:{mm:02d}:{ss:02d}
Received file MD5:                         {received_md5}
==================================================
"""
    print(report)

    # Save report to file
    try:
        os.makedirs(SAVE_DIR, exist_ok=True)

        report_path = f"{SAVE_DIR}/client_report_{filename}.txt"
        with open(report_path, "w") as f:
            f.write(report)
        print(f"[Client] Report saved to {report_path}")
    except (OSError, IOError) as e:
        print(f"[Client] Warning: Failed to save report: {e}")

    print(f"[Client] File saved to: {output_path}")


if __name__ == "__main__":
    main()