import socket
import struct
from file_handler import assemble_file, compute_md5

# Config
SERVER_IP = "127.0.0.1"
SERVER_PORT = 9999
CLIENT_PORT = 8888

# Packet types
REQUEST = 0
DATA = 1
FIN = 2

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
    
def main():
    # Create sockets
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    
    # Get filename from user
    filename = input("Enter filename to request (e.g., alice.txt): ").strip()
    
    # Send REQUEST
    request_payload = struct.pack("!B", REQUEST) + filename.encode('utf-8')
    packet = build_packet(SERVER_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, request_payload)
    send_packet(send_sock, packet, SERVER_IP)
    print(f"[Client] Sent REQUEST for '{filename}'")
    
    # Receive chunks
    chunks_dict = {}
    received_count = 0
    
    print("[Client] Receiving chunks...")
    
    while True:
        raw_data, addr = recv_sock.recvfrom(65535)
        
        src_ip = parse_ip_header(raw_data)
        src_port, dst_port = parse_udp_header(raw_data)
        
        # Filter by port
        if dst_port != CLIENT_PORT:
            continue
        
        # Parse payload
        payload = raw_data[28:]
        
        # Check packet type
        packet_type = payload[0]
        
        if packet_type == DATA:
            # Extract seq and data
            seq = struct.unpack("!I", payload[1:5])[0]
            data = payload[5:]
            
            # Store chunk
            chunks_dict[seq] = data
            received_count += 1
            
            if received_count % 10 == 0:  # Print every 10 chunks
                print(f"[Client] Received {received_count} chunks...")
        
        elif packet_type == FIN:
            print(f"[Client] Received FIN. Total chunks: {received_count}")
            break
    
    # Assemble file
    print("[Client] Assembling file...")
    output_path = f"./client_downloads/{filename}"
    
    try:
        assemble_file(chunks_dict, output_path)
        
        # Verify MD5
        received_md5 = compute_md5(output_path)
        print(f"[Client] Received file MD5: {received_md5}")
        print(f"\n✓ File transfer complete!")
        
    except ValueError as e:
        print(f"[Client] Error: {e}")
        print("Some chunks may be missing!")

if __name__ == "__main__":
    main()