import socket
import struct

# Config
SERVER_IP = "127.0.0.1"
SERVER_PORT = 9999

# 1. Parse IP header
def parse_ip_header(data):
    ip_header = data[:20]
    fields = struct.unpack("!BBHHHBBH4s4s", ip_header)
    src_ip = socket.inet_ntoa(fields[8])  # 9th field is source IP
    return src_ip

# 2. UDP header
def parse_udp_header(data):
    udp_header = data[20:28]
    fields = struct.unpack("!HHHH", udp_header)
    src_port = fields[0]
    dst_port = fields[1]
    return src_port, dst_port

# Create a socket
def create_socket():
    # IPPROTO_UDP = receive all UDP packets on this machine
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    return sock

# --From client--
# 3. check sum
def compute_checksum(data):
    # Pad with zero byte if length is odd
    if len(data) % 2 != 0:
        data += b'\x00'
    
    total = 0
    # Sum all 16-bit words
    for i in range(0, len(data), 2):
        word = struct.unpack("!H", data[i:i+2])[0]
        total += word
    
    # Fold carries back into 16 bits
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    
    # One's complement
    return ~total & 0xFFFF

# 4. IP header
def build_ip_header(src_ip, dst_ip, data_length):
    version_ihl = (4 << 4) + 5  # IPv4, header length = 5 * 4 = 20 bytes
    tos = 0                      # Type of Service, just set to 0
    total_length = 20 + 8 + data_length  # IP header + UDP header + payload
    packet_id = 1                # Identification, arbitrary value
    flags_offset = 0             # No fragmentation
    ttl = 64                     # Time to Live, standard value
    protocol = socket.IPPROTO_UDP  # 17, tells receiver this is UDP
    checksum = 0                 # Set to 0 first, calculate later
    src = socket.inet_aton(src_ip)   # Convert "x.x.x.x" string to 4 bytes
    dst = socket.inet_aton(dst_ip)

    # Pack all fields into binary, checksum=0 for now
    ip_header = struct.pack("!BBHHHBBH4s4s",
        version_ihl, tos, total_length,
        packet_id, flags_offset,
        ttl, protocol, checksum,
        src, dst
    )

    # Now calculate the real checksum over the header
    checksum = compute_checksum(ip_header)

    # Repack with the real checksum
    ip_header = struct.pack("!BBHHHBBH4s4s",
        version_ihl, tos, total_length,
        packet_id, flags_offset,
        ttl, protocol, checksum,
        src, dst
    )

    return ip_header

# 5. UDP header
def build_udp_header(src_port, dst_port, payload):
    length = 8 + len(payload)  # UDP header (8 bytes) + payload
    checksum = 0               # UDP checksum is optional, set to 0
    
    udp_header = struct.pack("!HHHH",
        src_port,
        dst_port,
        length,
        checksum
    )
    
    return udp_header

# 6. Build packet
def build_packet(src_ip, dst_ip, src_port, dst_port, payload):
    if isinstance(payload, str):
        payload = payload.encode('utf-8')
    
    ip_header = build_ip_header(src_ip, dst_ip, len(payload))
    udp_header = build_udp_header(src_port, dst_port, payload)
    
    return ip_header + udp_header + payload

# 7. Send packet
def send_packet(sock, packet, dst_ip):
    # sendto sends the packet to the destination IP
    sock.sendto(packet, (dst_ip, 0))

def main():
    sock = create_socket()
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    print(f"[Server] Listening on port {SERVER_PORT}...")
    
    while True:
        raw_data, addr = sock.recvfrom(65535)
        
        src_ip = parse_ip_header(raw_data)
        src_port, dst_port = parse_udp_header(raw_data)
        
        if dst_port != SERVER_PORT:
            continue
        
        payload = raw_data[28:]
        print(f"[Server] Received from {src_ip}:{src_port}")
        print(f"[Server] Message: {payload.decode('utf-8', errors='replace')}")
        
        # Reply to client
        reply = "Hello from server!"
        packet = build_packet(SERVER_IP, src_ip, SERVER_PORT, src_port, reply)
        send_packet(send_sock, packet, src_ip)
        print(f"[Server] Replied: {reply}")

if __name__ == "__main__":
    main()