import socket
import struct
from file_handler import find_file, split_file, compute_md5

# Config
SERVER_IP = "127.0.0.1"
SERVER_PORT = 9999

# Packet types
REQUEST = 0
DATA = 1
FIN = 2

# Parse IP header
def parse_ip_header(data):
    ip_header = data[:20]
    fields = struct.unpack("!BBHHHBBH4s4s", ip_header)
    src_ip = socket.inet_ntoa(fields[8])
    return src_ip

# Parse UDP header
def parse_udp_header(data):
    udp_header = data[20:28]
    fields = struct.unpack("!HHHH", udp_header)
    src_port = fields[0]
    dst_port = fields[1]
    return src_port, dst_port

# Create socket
def create_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    return sock

# Checksum
def compute_checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        word = struct.unpack("!H", data[i:i+2])[0]
        total += word
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF

# Build IP header
def build_ip_header(src_ip, dst_ip, data_length):
    version_ihl = (4 << 4) + 5
    tos = 0
    total_length = 20 + 8 + data_length
    packet_id = 1
    flags_offset = 0
    ttl = 64
    protocol = socket.IPPROTO_UDP
    checksum = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    ip_header = struct.pack("!BBHHHBBH4s4s",
        version_ihl, tos, total_length,
        packet_id, flags_offset,
        ttl, protocol, checksum,
        src, dst
    )

    checksum = compute_checksum(ip_header)

    ip_header = struct.pack("!BBHHHBBH4s4s",
        version_ihl, tos, total_length,
        packet_id, flags_offset,
        ttl, protocol, checksum,
        src, dst
    )

    return ip_header

# Build UDP header
def build_udp_header(src_port, dst_port, payload):
    length = 8 + len(payload)
    checksum = 0
    udp_header = struct.pack("!HHHH", src_port, dst_port, length, checksum)
    return udp_header

# Build packet
def build_packet(src_ip, dst_ip, src_port, dst_port, payload):
    if isinstance(payload, str):
        payload = payload.encode('utf-8')
    ip_header = build_ip_header(src_ip, dst_ip, len(payload))
    udp_header = build_udp_header(src_port, dst_port, payload)
    return ip_header + udp_header + payload

# Send packet
def send_packet(sock, packet, dst_ip):
    sock.sendto(packet, (dst_ip, 0))

def main():
    # Create sockets
    recv_sock = create_socket()
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    print(f"[Server] Listening on port {SERVER_PORT}...")
    
    while True:
        # Wait for REQUEST
        raw_data, addr = recv_sock.recvfrom(65535)
        
        src_ip = parse_ip_header(raw_data)
        src_port, dst_port = parse_udp_header(raw_data)
        
        # Filter by port
        if dst_port != SERVER_PORT:
            continue
        
        # Parse payload
        payload = raw_data[28:]
        
        # Check packet type
        packet_type = payload[0]
        
        if packet_type == REQUEST:
            # Extract filename
            filename = payload[1:].decode('utf-8')
            print(f"\n[Server] Received REQUEST from {src_ip}:{src_port}")
            print(f"[Server] Requested file: {filename}")
            
            try:
                # Find file
                filepath = find_file(filename, "./server_files")
                
                # Split file
                chunks, total_size, total_chunks = split_file(filepath, 1024)
                
                print(f"[Server] Sending {total_chunks} chunks...")
                
                # Send each chunk
                for seq, data in chunks:
                    # Build payload: [type(1B)] + [seq(4B)] + [data]
                    chunk_payload = struct.pack("!BI", DATA, seq) + data
                    
                    # Send
                    packet = build_packet(SERVER_IP, src_ip, SERVER_PORT, src_port, chunk_payload)
                    send_packet(send_sock, packet, src_ip)
                    
                    if seq % 10 == 0:  # Print every 10 chunks
                        print(f"[Server] Sent chunk {seq}/{total_chunks-1}")
                
                print(f"[Server] Sent all {total_chunks} chunks")
                
                # Send FIN
                fin_payload = struct.pack("!B", FIN)
                packet = build_packet(SERVER_IP, src_ip, SERVER_PORT, src_port, fin_payload)
                send_packet(send_sock, packet, src_ip)
                print("[Server] Sent FIN")
                
                # Compute MD5
                original_md5 = compute_md5(filepath)
                print(f"[Server] Original file MD5: {original_md5}")
                
            except FileNotFoundError as e:
                print(f"[Server] Error: {e}")
                # TODO: Send error response
                
            except ValueError as e:
                print(f"[Server] Error: {e}")
                # TODO: Send error response

if __name__ == "__main__":
    main()