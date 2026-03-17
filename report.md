# SRFT 系统设计与实现详解

## 目录
- [Part 1: 整体框架与各部分逻辑](#part-1-整体框架与各部分逻辑)
- [Part 2: 模拟文件传输流程](#part-2-模拟文件传输流程)

---

# Part 1: 整体框架与各部分逻辑

## 系统架构图

```
┌─────────────────────────────────────────────────────────────┐
│                     SRFT 系统架构                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐                        ┌──────────────┐  │
│  │ SRFT_UDP     │                        │ SRFT_UDP     │  │
│  │ Client.py    │◄──────网络通信────────►│ Server.py    │  │
│  │              │                        │              │  │
│  │ (主控逻辑)   │                        │ (主控逻辑)   │  │
│  └──────┬───────┘                        └──────┬───────┘  │
│         │                                       │          │
│         │ 调用                                  │ 调用     │
│         ▼                                       ▼          │
│  ┌─────────────────────────────────────────────────────┐  │
│  │           共享的底层模块（工具箱）                   │  │
│  ├─────────────────────────────────────────────────────┤  │
│  │                                                      │  │
│  │  reliability.py    packet.py      raw_socket.py    │  │
│  │  ┌──────────┐      ┌─────────┐    ┌─────────┐     │  │
│  │  │RecvBuffer│      │build_   │    │create_  │     │  │
│  │  │SendWindow│      │packet() │    │sockets()│     │  │
│  │  │          │      │parse_   │    │send()   │     │  │
│  │  │(窗口管理)│      │packet() │    │recv()   │     │  │
│  │  └──────────┘      └─────────┘    └─────────┘     │  │
│  │                                                      │  │
│  │  file_handler.py   constants.py                    │  │
│  │  ┌──────────┐      ┌─────────┐                    │  │
│  │  │split_    │      │REQUEST  │                    │  │
│  │  │file()    │      │DATA     │                    │  │
│  │  │assemble_ │      │ACK, FIN │                    │  │
│  │  │file()    │      │START    │                    │  │
│  │  │compute_  │      └─────────┘                    │  │
│  │  │md5()     │                                      │  │
│  │  └──────────┘                                      │  │
│  └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 各模块的职责和核心功能

### 📦 constants.py - 协议定义

```python
REQUEST = 0    # 客户端请求文件
DATA    = 1    # 数据传输
ACK     = 2    # 确认
FIN     = 3    # 结束
FIN_ACK = 4    # 结束确认
START   = 5    # 开始（告知总包数）
```

**作用：** 定义包类型，全局共享

---

### 🔧 packet.py - 包的编码/解码

#### 核心函数

**1. `build_packet(src_ip, dst_ip, src_port, dst_port, pkt_type, seq, ack, data)`**
- 输入：包的所有字段
- 输出：完整的字节流（IP header + UDP header + Custom header + data）
- 计算两层 checksum（UDP + Custom）

**2. `parse_packet(raw_bytes)`**
- 输入：网络收到的原始字节
- 输出：字典 `{"src_ip": ..., "seq": ..., "data": ..., "checksum_valid": True/False}`
- 验证两层 checksum

**作用：** 序列化和反序列化，其他模块不用关心字节格式

#### 数据包结构

```
┌─────────────────────────────────────┐
│  IP Header (20 bytes)               │  ← 寄信人地址、收信人地址
├─────────────────────────────────────┤
│  UDP Header (8 bytes)               │  ← 寄信人端口、收信人端口
├─────────────────────────────────────┤
│  Custom Protocol Header (13 bytes)  │  ← 我们的控制信息
├─────────────────────────────────────┤
│  Data (可变长度)                     │  ← 真正的文件内容
└─────────────────────────────────────┘
```

#### IP Header (20 bytes)

```python
ip_header = struct.pack("!BBHHHBBH4s4s",
    (4 << 4) + 5,    # 版本(4) + 头部长度(5个32位字 = 20字节)
    0,               # 服务类型
    total_length,    # 总长度
    1,               # 标识
    0,               # 标志 + 片偏移
    64,              # TTL（生存时间）
    socket.IPPROTO_UDP,  # 协议类型：UDP
    ip_checksum,     # IP 校验和
    src_bytes,       # 源 IP（4字节）
    dst_bytes        # 目的 IP（4字节）
)
```

**为什么要两次构建？**
- 第一次：checksum=0，计算出真实 checksum
- 第二次：用真实 checksum 重建 header
- 这就像"自己给自己签名" - 需要先留空，签完再填回去

#### UDP Header (8 bytes)

```python
udp_header = struct.pack("!HHHH",
    src_port,      # 源端口（2字节）
    dst_port,      # 目的端口（2字节）
    udp_length,    # UDP总长度（包括header + payload）
    udp_checksum   # UDP校验和
)
```

**UDP checksum 的特殊之处：**

UDP checksum 不只校验 UDP header 和 payload，还要加上**伪头部（pseudo-header）**：

```
Pseudo-header:
┌────────────────┐
│ 源IP (4 bytes) │
│ 目的IP (4 bytes)│
│ 0 (1 byte)     │
│ 协议 (1 byte)  │  ← IPPROTO_UDP = 17
│ UDP长度(2 bytes)│
└────────────────┘
```

**为什么要伪头部？**
- 防止包被路由错误（IP 层和 UDP 层的地址要一致）
- 如果有人篡改了 IP 地址，但忘记改 UDP checksum，就会被发现

#### Custom Protocol Header (13 bytes)

```python
CUSTOM_HEADER_FORMAT = "!BIIHH"

struct.pack("!BIIHH",
    pkt_type,      # B: 1字节，包类型（REQUEST, DATA, ACK, FIN...）
    seq,           # I: 4字节，序列号（这是第几个包）
    ack,           # I: 4字节，确认号（我收到了第几个包）
    data_len,      # H: 2字节，数据长度
    checksum       # H: 2字节，自定义协议的校验和
)
```

**为什么有两层 checksum？**
1. **UDP checksum**：网络层的保护，验证传输过程中是否损坏
2. **Custom checksum**：应用层的保护，额外一层验证

双重保险，更安全。

---

### 🌐 raw_socket.py - Socket 收发

#### 核心函数

**1. `create_sockets()`**
```python
# 发送 socket：IPPROTO_RAW
send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  # 我们自己提供 IP header

# 接收 socket：IPPROTO_UDP（接收所有 UDP 包）
recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
```

**为什么要两个 socket？**
- **发送 socket**：`IPPROTO_RAW` - 我们完全控制包的内容，包括 IP header
- **接收 socket**：`IPPROTO_UDP` - 内核会捕获所有到达的 UDP 包给我们

**2. `send(send_sock, packet_bytes, dst_ip)`**
```python
def send(send_sock, packet_bytes, dst_ip):
    """packet_bytes 已经包含完整的 IP + UDP + 数据"""
    send_sock.sendto(packet_bytes, (dst_ip, 0))  # port=0 因为已经在包里了
```

**3. `recv(recv_sock)`**
```python
def recv(recv_sock):
    """返回原始字节，包含 IP + UDP + 数据"""
    raw_bytes, _ = recv_sock.recvfrom(65535)
    return raw_bytes
```

**设计原则：**
- `raw_socket.py` 只负责"发字节"和"收字节"
- 它**不知道**包的内容是什么
- 它**不做**任何过滤或解析

---

### 🎯 reliability.py - 可靠性核心 ⭐

这是系统最核心的模块，实现了**滑动窗口协议**。

#### SendWindow（服务端发送窗口）

**问题：如何高效地发送大文件？**

如果每发一个包就等 ACK：
```
发送包0 → 等待ACK0 → 收到ACK0 → 发送包1 → 等待ACK1 → ...
```
太慢了！800MB = 819200 个包，每个来回 10ms，就要 8192 秒！

**解决方案：管道化（pipelining）**

同时发送多个包，不用等：
```
发送包0, 1, 2, ..., 63 (窗口大小=64)
↓
等待 ACK
↓
收到 ACK30 → 说明前 30 个包都收到了
↓
可以继续发包 64, 65, ..., 93
```

**滑动窗口示意：**

```
[已确认] [窗口内：可以发送] [未来：等待]
0...29  |30...93|  94...819199
        ↑       ↑
    window_base  window_base + window_size
```

**状态变量：**
```python
class SendWindow:
    def __init__(self, filepath, chunk_size, total_chunks, window_size=64, timeout_ms=1000):
        self.window_base = 0     # 窗口左边界：最小的未确认序列号
        self.next_seq = 0        # 下一个要首次发送的序列号

        self.sent_times = {}     # {seq: 发送时间} - 用于超时检测
        self.acked = {}          # {seq: True} - 已确认的包

        self.file_fd = os.open(filepath, os.O_RDONLY)  # 文件描述符
```

**为什么用 `os.open()` 而不是 `open()`？**

多线程环境下，如果每次读都 `with open(...)`：
```python
# 糟糕的方式
def read_chunk(self, seq):
    with open(self.filepath, 'rb') as f:  # 每次都打开文件！
        f.seek(seq * self.chunk_size)
        return f.read(self.chunk_size)
```

800MB 文件，30 万次重传 = 100 万次 `open()` 调用！

**优化后（os.pread）：**
```python
def __init__(self, ...):
    self.file_fd = os.open(filepath, os.O_RDONLY)  # 只打开一次

def read_chunk(self, seq):
    offset = seq * self.chunk_size
    return os.pread(self.file_fd, self.chunk_size, offset)  # 位置无关读取
```

`os.pread()` 的优点：
- ✅ 不改变文件指针（线程安全）
- ✅ 只打开文件一次
- ✅ 系统调用开销极小

**核心方法：**

**1. `get_next_to_send()`** - 发送策略
```python
def get_next_to_send(self):
    with self.lock:  # 线程安全
        # 优先级1: 重传超时的包
        for seq in range(self.window_base, self.window_base + self.window_size):
            if seq >= self.total_chunks:
                break
            if seq not in self.sent_times and seq not in self.acked:
                # 超时的包：sent_times 被删除了，但还没 ACK
                chunk_data = self.read_chunk(seq)
                return (seq, chunk_data)

        # 优先级2: 发送新的包（如果窗口有空间）
        if self.next_seq - self.window_base < self.window_size:
            if self.next_seq < self.total_chunks:
                seq = self.next_seq
                self.next_seq += 1
                chunk_data = self.read_chunk(seq)
                return (seq, chunk_data)

        return None  # 窗口满了，等待 ACK
```

**理解重点：**
- 窗口满了就不发（等待 ACK 滑动窗口）
- 超时的包优先重传
- 新包其次

**2. `receive_ack(ack_num)`** - 处理 ACK
```python
def receive_ack(self, ack_num):
    """ACK 是累积的：ack_num=30 表示 0-29 都收到了"""
    with self.lock:
        if ack_num <= self.window_base:
            return  # 旧的 ACK，忽略

        # 标记 0 到 ack_num-1 都已确认
        for seq in range(self.window_base, ack_num):
            self.acked[seq] = True
            self.sent_times.pop(seq, None)  # 不再需要超时检测

        self.window_base = ack_num  # 窗口滑动！
```

**累积 ACK 的好处：**
- 即使个别 ACK 丢失，后续的 ACK 也能确认前面的包
- 例如：ACK10 丢了，但 ACK20 到达，说明 0-19 都收到了

**3. `check_timeouts()`** - 超时检测
```python
def check_timeouts(self):
    now = time.time()
    threshold = self.timeout_ms / 1000.0  # 1秒

    with self.lock:
        timed_out = [
            seq for seq, t in self.sent_times.items()
            if seq not in self.acked and now - t > threshold
        ]
        for seq in timed_out:
            del self.sent_times[seq]  # 删除时间戳，等待重传
```

**删除 `sent_times` 的巧妙之处：**
- 删除后，`get_next_to_send()` 会把这个 seq 当作"未发送"
- 自动进入重传队列

---

#### RecvBuffer（客户端接收缓冲区）

客户端的任务：
1. 收到包 → 存入 buffer
2. 按序组装文件
3. 定期发送累积 ACK

**状态变量：**
```python
class RecvBuffer:
    def __init__(self):
        self.buffer = {}           # {seq: data}
        self.expected_seq = 0      # 下一个期待的序列号
        self.total_chunks = None   # 总包数（START 包会告诉我们）

        # 统计信息
        self.total_received = 0
        self.duplicate_count = 0
        self.out_of_order_count = 0
        self.checksum_errors = 0
```

**核心方法：**

**1. `receive_data(seq, data)`**
```python
def receive_data(self, seq, data):
    with self.lock:
        self.total_received += 1

        # 检测重复
        if seq in self.buffer:
            self.duplicate_count += 1
            return

        # 检测乱序
        if seq > self.expected_seq:
            self.out_of_order_count += 1

        self.buffer[seq] = data

        # 尝试滑动 expected_seq（连续包）
        while self.expected_seq in self.buffer:
            self.expected_seq += 1
```

**expected_seq 的巧妙之处：**
```
收到：seq=0, 1, 3, 2, 4
buffer: {0, 1, 3}
expected_seq = 2（缺seq=2）

收到seq=2后：
buffer: {0, 1, 2, 3, 4}
expected_seq 滑动到 5！（连续跳过0,1,2,3,4）
```

`expected_seq` 永远指向"第一个缺失的包"。

---

### 📁 file_handler.py - 文件操作

**核心函数：**

**1. `find_file(filename, repository_dir)`** - 安全查找文件
```python
# 防止路径遍历攻击
if ".." in filename or filename.startswith("/"):
    raise ValueError("Invalid filename")

full_path = os.path.join(repository_dir, filename)

# 验证 symlink 攻击
if not os.path.realpath(full_path).startswith(os.path.realpath(repository_dir)):
    raise ValueError("Path outside repository")
```

**2. `assemble_file(chunks_dict, output_path)`** - 组装文件
```python
# 验证所有块都存在且连续
seq_numbers = sorted(chunks_dict.keys())
expected_seqs = list(range(len(seq_numbers)))

if seq_numbers != expected_seqs:
    raise ValueError(f"Missing chunks")

# 按序写入
with open(output_path, 'wb') as f:
    for seq in seq_numbers:
        f.write(chunks_dict[seq])
```

**3. `compute_md5(filepath)`** - 计算 MD5
```python
md5_hash = hashlib.md5()
with open(filepath, 'rb') as f:
    while chunk := f.read(8192):  # 每次读8KB
        md5_hash.update(chunk)
return md5_hash.hexdigest()
```

**作用：** 文件级别的操作，不关心网络

---

### 🖥️ SRFT_UDPServer.py - 服务端主控

**主线程逻辑：**
```
main() {
    创建 sockets
    ↓
    while True:
        阶段1: 等待 REQUEST
        阶段2: 准备文件
        阶段3: 发送 START 包
        阶段4: 启动两个线程传输
        阶段5: 发送 FIN，等待 FIN_ACK
        阶段6: 生成报告
}
```

**为什么要 3 个 socket？**

原来的设计（2个socket）会出现竞态：
```
recv_sock 收到 ACK 包
    ↓
send_thread 和 ack_recv_thread 同时调用 recv_sock.recvfrom()
    ↓
操作系统随机选一个线程给它
    ↓
如果 send_thread 拿到了 ACK → 它不知道怎么处理 → 丢弃
    ↓
ACK 丢失！服务端永远等不到确认 → 超时重传
```

**解决方案（3个socket）：**
```python
send_sock = ...  # 只用于发送 DATA/FIN/START
recv_sock = ...  # 只用于接收 REQUEST/FIN_ACK
ack_sock = ...   # 专门接收 ACK（ack_recv_thread 独占）
```

每个线程有自己专属的 socket，不会抢。

**两个工作线程：**

**1. `send_thread`** - 循环发送数据
```python
def send_thread(send_sock, window, server_ip, server_port, client_ip, client_port, stop_event):
    while not stop_event.is_set():
        window.check_timeouts()  # 检测超时包

        result = window.get_next_to_send()
        if result is None:
            if window.all_acked():
                break  # 全部确认，结束
            time.sleep(0.001)  # 窗口满了，等一下
            continue

        seq, chunk = result
        packet = build_packet(...)
        send(send_sock, packet, client_ip)
        window.mark_sent(seq)  # 记录发送时间
```

**2. `ack_recv_thread`** - 接收 ACK
```python
def ack_recv_thread(ack_sock, window, server_port, client_ip, client_port, stop_event):
    ack_sock.settimeout(0.5)

    while not stop_event.is_set():
        try:
            raw = recv(ack_sock)
        except socket.timeout:
            continue

        pkt = parse_packet(raw)

        # 过滤：只要来自正确客户端的 ACK 包
        if (pkt and pkt["pkt_type"] == ACK and
            pkt["src_ip"] == client_ip):
            window.receive_ack(pkt["ack"])
```

---

### 💻 SRFT_UDPClient.py - 客户端主控

**主线程逻辑：**
```
main() {
    发送 REQUEST
    ↓
    启动两个线程
    ↓
    等待线程结束
    ↓
    组装文件、计算 MD5、生成报告
}
```

**两个工作线程：**

**1. `data_recv_thread`** - 接收数据
```python
def data_recv_thread(...):
    last_progress = -1

    while not stop_event.is_set():
        pkt = parse_packet(recv(recv_sock))

        # 验证 checksum（两层）
        if not pkt["checksum_valid"] or not pkt["udp_checksum_valid"]:
            buffer.record_checksum_error()
            continue

        if pkt["pkt_type"] == START:
            total_chunks = struct.unpack("!I", pkt["data"])[0]
            buffer.set_total_chunks(total_chunks)

        elif pkt["pkt_type"] == DATA:
            buffer.receive_data(pkt["seq"], pkt["data"])

            # 显示进度（每10%）
            progress = int((len(buffer.buffer) / buffer.total_chunks) * 100)
            if progress // 10 > last_progress // 10:
                print(f"Progress: {progress}%")
                last_progress = progress

        elif pkt["pkt_type"] == FIN:
            stop_event.set()
            break
```

**2. `ack_send_thread`** - 批量 + 超时发送累积 ACK
```python
ACK_BATCH_SIZE     = 16      # 批量触发：每收到 16 个新包发一次 ACK
ACK_TIMEOUT        = 0.05    # 50ms 超时触发：兜底尾部包
ACK_CHECK_INTERVAL = 0.001   # 1ms 轮询间隔

def ack_send_thread(...):
    last_ack_time  = time.time()
    last_acked_seq = 0

    while not stop_event.is_set():
        ack_num = buffer.get_cumulative_ack()

        should_send = False
        if ack_num - last_acked_seq >= ACK_BATCH_SIZE:
            should_send = True   # 批量触发
        elif ack_num > last_acked_seq and time.time() - last_ack_time >= ACK_TIMEOUT:
            should_send = True   # 超时触发

        if should_send:
            pkt = build_packet(..., ACK, 0, ack_num, b"")
            send(send_sock, pkt, server_ip)
            last_acked_seq = ack_num
            last_ack_time  = time.time()

        time.sleep(ACK_CHECK_INTERVAL)  # 1ms 轮询
```

**两个触发条件**：
- **批量**：`ack_num - last_acked_seq >= 16` → 高速传输时，每 16 个包发一次 ACK
- **超时**：`ack_num > last_acked_seq` 且 50ms 没发过 → 兜底尾部/慢速场景
- **无数据**：`ack_num == last_acked_seq` → 两个条件都不满足，不发送冗余 ACK

---

# Part 2: 模拟文件传输流程

## 场景设置

**文件：** `photo.jpg`，大小 **10 KB**
- chunk_size = 1024 bytes
- total_chunks = 10
- 窗口大小 = 4（为了演示方便，实际是64）

**角色：**
- 服务端：127.0.0.1:9999
- 客户端：127.0.0.1:8888

---

## 时间线：函数调用流程

### ⏰ T=-∞ (初始态): 服务端启动并等待

```python
# 服务端 Terminal
$ sudo python3 SRFT_UDPServer.py

# ── main() 函数开始 ──

# 1. 解析参数
parser = argparse.ArgumentParser(...)
args = parser.parse_args()
SERVER_IP = "127.0.0.1"
SERVER_PORT = 9999
FILES_DIR = "./server_files"

# 2. 验证参数
if not (1 <= SERVER_PORT <= 65535):
    print("[Server] Error: Invalid port")
    return

socket.inet_aton(SERVER_IP)  # 验证 IP 格式
os.path.exists(FILES_DIR)    # 验证文件目录

# 3. 创建 sockets
send_sock, recv_sock = create_sockets()
  └─> raw_socket.create_sockets()
      └─> send_sock = socket.socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
      └─> recv_sock = socket.socket(AF_INET, SOCK_RAW, IPPROTO_UDP)

# 创建专用 ACK socket（用于数据传输阶段）
ack_sock = socket.socket(AF_INET, SOCK_RAW, IPPROTO_UDP)

print(f"[Server] Listening on {SERVER_IP}:{SERVER_PORT} ...")
print(f"[Server] Serving files from: {FILES_DIR}")

# 4. 进入主循环，阻塞等待 REQUEST
while True:
    recv_sock.settimeout(None)  # 无超时，永久等待

    # ═══ 服务端在此阻塞，等待客户端连接 ═══
```

**状态：** 服务端进入阻塞状态，等待第一个客户端的 REQUEST 包

---

### ⏰ T=0ms: 客户端启动

```python
# 客户端 Terminal
$ sudo python3 SRFT_UDPClient.py photo.jpg

# ── main() 函数开始 ──

# 1. 解析参数
parser = argparse.ArgumentParser(...)
args = parser.parse_args()
SERVER_IP = "127.0.0.1"
SERVER_PORT = 9999
filename = "photo.jpg"

# 2. 验证参数
if not (1 <= SERVER_PORT <= 65535):
    print("[Client] Error: Invalid server port")
    return

socket.inet_aton(SERVER_IP)  # 验证 IP 格式

if not filename:
    print("[Client] No filename provided.")
    return

print(f"[Client] Connecting to {SERVER_IP}:{SERVER_PORT}")

# 3. 创建 sockets
send_sock, recv_sock = create_sockets()
  └─> raw_socket.create_sockets()
      └─> send_sock = socket.socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
      └─> recv_sock = socket.socket(AF_INET, SOCK_RAW, IPPROTO_UDP)

# 获取本地 IP
client_ip = socket.gethostbyname(socket.gethostname())  # "127.0.0.1"

# 4. 构建 REQUEST 包
req_pkt = build_packet(
    client_ip="127.0.0.1",
    server_ip="127.0.0.1",
    client_port=8888,
    server_port=9999,
    pkt_type=REQUEST,  # 0
    seq=0,
    ack=0,
    data=b"photo.jpg"
)
  └─> packet.build_packet()
      └─> 构建 IP header (20 bytes)
      └─> 计算 UDP checksum
      └─> 构建 UDP header (8 bytes)
      └─> 构建 Custom header (13 bytes)
      └─> 返回 41 + 9 = 50 bytes

# 5. 发送 REQUEST
send(send_sock, req_pkt, SERVER_IP)
  └─> raw_socket.send()
      └─> send_sock.sendto(req_pkt, ("127.0.0.1", 0))

print("[Client] Sent REQUEST for 'photo.jpg'")
```

**网络：** REQUEST 包在路上 → 服务端

---

### ⏰ T=1ms: 服务端收到 REQUEST，准备文件

```python
# ── 服务端 main() 的 while True 循环中 ──

# 阶段1: 等待 REQUEST
while True:
    raw = recv(recv_sock)  # 阻塞等待
      └─> raw_socket.recv()
          └─> recv_sock.recvfrom(65535)
          └─> 返回 50 bytes

    pkt = parse_packet(raw)
      └─> packet.parse_packet()
          └─> 解析 IP header → src_ip="127.0.0.1"
          └─> 解析 UDP header → src_port=8888
          └─> 验证 UDP checksum ✓
          └─> 解析 Custom header → pkt_type=0 (REQUEST)
          └─> 验证 Custom checksum ✓
          └─> 返回 {"pkt_type": 0, "data": b"photo.jpg", ...}

    if pkt["pkt_type"] == REQUEST:
        filename = pkt["data"].decode("utf-8")  # "photo.jpg"
        client_ip = pkt["src_ip"]    # "127.0.0.1"
        client_port = pkt["src_port"] # 8888
        print(f"[Server] REQUEST from {client_ip}:{client_port} — 'photo.jpg'")
        break

# 阶段2: 准备文件
filepath = find_file(filename, FILES_DIR)
  └─> file_handler.find_file("photo.jpg", "./server_files")
      └─> 验证路径安全（无 ".."）
      └─> 返回 "./server_files/photo.jpg"

total_size = os.path.getsize(filepath)    # 10240 bytes
total_chunks = (10240 + 1023) // 1024      # 10 chunks

original_md5 = compute_md5(filepath)
  └─> file_handler.compute_md5()
      └─> hashlib.md5()
      └─> 返回 "a1b2c3d4e5f6..."

print(f"[Server] Sending 'photo.jpg' — 10 chunks, 10240 bytes")
```

---

### ⏰ T=2ms: 服务端发送 START 包

```python
# 阶段3: 发送 START 包（告诉客户端总包数）

start_data = struct.pack("!I", total_chunks)  # 10 → 4 bytes

start_pkt = build_packet(
    SERVER_IP, client_ip,
    SERVER_PORT, client_port,
    START,  # 5
    0, 0, start_data
)
  └─> packet.build_packet()
      └─> 返回完整包（45 bytes）

# 发送 3 次（防丢包）
for attempt in range(3):
    send(send_sock, start_pkt, client_ip)
    time.sleep(0.05)

print("[Server] Sent START packet — total chunks: 10")
```

**网络：** 3 个 START 包在路上 → 客户端

---

### ⏰ T=3ms: 客户端启动接收线程

```python
# 客户端 main() 继续

buffer = RecvBuffer()
  └─> reliability.RecvBuffer.__init__()
      └─> self.buffer = {}
      └─> self.expected_seq = 0
      └─> self.total_chunks = None

stop_flag = threading.Event()
start_time = time.time()  # 记录开始时间

# 启动两个线程
t_data = threading.Thread(
    target=data_recv_thread,
    args=(recv_sock, buffer, CLIENT_PORT, SERVER_IP, SERVER_PORT, stop_flag)
)

t_ack = threading.Thread(
    target=ack_send_thread,
    args=(send_sock, buffer, client_ip, CLIENT_PORT, SERVER_IP, SERVER_PORT, stop_flag)
)

t_data.start()  # 接收线程开始运行
t_ack.start()   # ACK线程开始运行
```

---

### ⏰ T=4ms: 客户端接收线程收到第1个 START

```python
# ── data_recv_thread 函数 ──

def data_recv_thread(recv_sock, buffer, client_port, server_ip, server_port, stop_event):
    recv_sock.settimeout(1.0)
    last_progress = -1

    while not stop_event.is_set():
        try:
            raw = recv(recv_sock)  # 收到 45 bytes
              └─> raw_socket.recv()
        except socket.timeout:
            continue

        pkt = parse_packet(raw)
          └─> packet.parse_packet()
              └─> {"pkt_type": 5, "data": b"\x00\x00\x00\x0a", ...}  # 10

        # 过滤
        if pkt["dst_port"] != client_port:  # 8888 == 8888 ✓
            continue
        if not pkt["checksum_valid"] or not pkt["udp_checksum_valid"]:
            buffer.record_checksum_error()
            continue
        if pkt["src_ip"] != server_ip:  # ✓
            continue

        # 处理 START
        if pkt["pkt_type"] == START:
            total_chunks = struct.unpack("!I", pkt["data"][:4])[0]  # 10
            buffer.set_total_chunks(total_chunks)
              └─> reliability.RecvBuffer.set_total_chunks()
                  └─> self.total_chunks = 10

            print(f"[Client] Received START — total chunks: 10")
```

**注意：** 接下来还会收到第2、3个 START（重复发送），会再打印 2 次

---

### ⏰ T=5ms: 客户端 ACK 线程开始轮询

```python
# ── ack_send_thread 函数 ──

def ack_send_thread(...):
    last_ack_time  = time.time()
    last_acked_seq = 0

    while not stop_event.is_set():
        ack_num = buffer.get_cumulative_ack()
          └─> return self.expected_seq  # 0（还没收到数据）

        # ack_num(0) - last_acked_seq(0) = 0 < 16 → 批量不触发
        # ack_num(0) == last_acked_seq(0) → 超时不触发
        # should_send = False → 不发送（无冗余 ACK）

        time.sleep(ACK_CHECK_INTERVAL)  # sleep 1ms
```

**注意：** 与旧版不同，此时没有收到数据，ACK 线程不会发送任何包（避免冗余 ACK）

---

### ⏰ T=6ms: 服务端启动传输线程

```python
# 服务端 main() 继续

# 阶段4: 创建 SendWindow
try:
    window = SendWindow(filepath, CHUNK_SIZE, total_chunks, WINDOW_SIZE, TIMEOUT_MS)
      └─> reliability.SendWindow.__init__()
          └─> self.file_fd = os.open("./server_files/photo.jpg", O_RDONLY)
          └─> self.window_base = 0
          └─> self.next_seq = 0
          └─> self.window_size = 4  # 演示用
          └─> self.timeout_ms = 1000
except IOError as e:
    print(f"[Server] Error: {e}")
    continue

stop_flag = threading.Event()
start_time = time.time()

# 启动两个线程
try:
    t_send = threading.Thread(
        target=send_thread,
        args=(send_sock, window, SERVER_IP, SERVER_PORT, client_ip, client_port, stop_flag)
    )

    t_ack = threading.Thread(
        target=ack_recv_thread,
        args=(ack_sock, window, SERVER_PORT, client_ip, client_port, stop_flag)
    )

    t_send.start()
    t_ack.start()
```

---

### ⏰ T=7ms: 服务端发送线程开始工作

```python
# ── send_thread 函数 ──

def send_thread(send_sock, window, server_ip, server_port, client_ip, client_port, stop_event):
    last_progress = -1

    while not stop_event.is_set():
        # 1. 检测超时
        window.check_timeouts()
          └─> reliability.SendWindow.check_timeouts()
              └─> 现在 sent_times={}, 无超时

        # 2. 获取下一个要发送的包
        result = window.get_next_to_send()
          └─> reliability.SendWindow.get_next_to_send()
              └─> 窗口状态: base=0, next=0, 窗口大小=4
              └─> 检查超时包：无
              └─> 发送新包：seq=0 < 10, 窗口未满
                  └─> seq = 0
                  └─> self.next_seq = 1
                  └─> chunk_data = self.read_chunk(0)
                      └─> os.pread(file_fd, 1024, 0*1024)
                      └─> 返回前 1024 bytes
                  └─> return (0, chunk_data)

        if result is None:
            if window.all_acked():
                break
            time.sleep(0.001)
            continue

        seq, chunk = result  # seq=0, chunk=1024 bytes

        # 3. 构建 DATA 包
        packet = build_packet(
            server_ip, client_ip,
            server_port, client_port,
            DATA, seq, 0, chunk  # pkt_type=1, seq=0
        )
          └─> packet.build_packet()
              └─> 返回 41 + 1024 = 1065 bytes

        # 4. 发送
        send(send_sock, packet, client_ip)

        # 5. 记录
        window.mark_sent(seq)
          └─> reliability.SendWindow.mark_sent()
              └─> seq=0 不在 sent_times（首次发送）
              └─> self.total_sent += 1  # 统计
              └─> self.sent_times[0] = time.time()

        # 循环继续，立即发送下一个包
```

**循环 4 次后：**
- 发送了 seq=0, 1, 2, 3（窗口填满）
- `sent_times = {0: t0, 1: t1, 2: t2, 3: t3}`
- `next_seq = 4`

**第 5 次循环：**
```python
result = window.get_next_to_send()
  └─> 窗口状态: base=0, next=4
  └─> 窗口满了（4 - 0 = 4 >= window_size）
  └─> return None

if result is None:
    if window.all_acked():  # base=0 < 10, False
        break
    time.sleep(0.001)  # 等待 ACK
    continue
```

**网络：** 4 个 DATA 包在路上 → 客户端

---

### ⏰ T=8ms: 客户端接收第1个 DATA 包

```python
# ── data_recv_thread 继续循环 ──

raw = recv(recv_sock)  # 收到 1065 bytes (seq=0)

pkt = parse_packet(raw)
  └─> {"pkt_type": 1, "seq": 0, "data": <1024 bytes>, ...}

# 过滤、验证（省略）

if pkt["pkt_type"] == DATA:
    buffer.receive_data(pkt["seq"], pkt["data"])
      └─> reliability.RecvBuffer.receive_data(0, data)
          └─> with self.lock:
              └─> self.total_received += 1  # 统计
              └─> seq=0 不在 buffer（非重复）
              └─> seq(0) == expected_seq(0)（不是乱序）
              └─> self.buffer[0] = data
              └─> # 滑动 expected_seq
                  while self.expected_seq in self.buffer:  # 0 in buffer ✓
                      self.expected_seq += 1  # 0 → 1

    # 显示进度
    if buffer.total_chunks:  # 10
        received_count = len(buffer.buffer)  # 1
        progress = int((1 / 10) * 100)  # 10%
        if progress // 10 > last_progress // 10:  # 1 > -1 ✓
            print(f"[Client] Progress: 10% (1/10 chunks received)")
            last_progress = 10
```

---

### ⏰ T=9ms: 客户端接收 seq=1, 2, 3

**连续接收 3 个包，类似流程：**

```python
# 收到 seq=1
buffer.receive_data(1, data)
  └─> buffer[1] = data
  └─> expected_seq: 1 → 2

# 收到 seq=2
buffer.receive_data(2, data)
  └─> buffer[2] = data
  └─> expected_seq: 2 → 3

# 收到 seq=3
buffer.receive_data(3, data)
  └─> buffer[3] = data
  └─> expected_seq: 3 → 4
  └─> progress = 40%
  └─> print("[Client] Progress: 40% (4/10 chunks)")
```

**现在客户端状态：**
- `buffer = {0, 1, 2, 3}`
- `expected_seq = 4`

---

### ⏰ T=15ms: 客户端 ACK 线程批量触发

```python
# ── ack_send_thread 轮询检测到新数据 ──

ack_num = buffer.get_cumulative_ack()
  └─> return self.expected_seq  # 4（已收到 seq 0-3）

# ack_num(4) - last_acked_seq(0) = 4 < 16 → 批量不触发（才4个包）
# 但此时 10 个包的小文件，假设全部快速到达...
# 当 expected_seq 达到 16 或超时 50ms，触发发送

# 实际对于 10 个包的文件：超时触发（50ms 后）
# ack_num(4) > last_acked_seq(0) 且距上次 50ms+ → 超时触发

pkt = build_packet(..., ACK, 0, ack_num=4, b"")
send(send_sock, pkt, server_ip)
last_acked_seq = 4
last_ack_time = time.time()
```

**网络：** ACK(ack=4) → 服务端（表示：我收到了 0-3，期待 4）

---

### ⏰ T=16ms: 服务端 ACK 接收线程收到 ACK

```python
# ── ack_recv_thread 函数 ──

def ack_recv_thread(ack_sock, window, server_port, client_ip, client_port, stop_event):
    ack_sock.settimeout(0.5)

    while not stop_event.is_set():
        try:
            raw = recv(ack_sock)  # 收到 41 bytes
              └─> raw_socket.recv()
        except socket.timeout:
            if window.all_acked():
                break
            continue

        pkt = parse_packet(raw)
          └─> {"pkt_type": 2, "ack": 4, ...}

        # 过滤
        if pkt["dst_port"] != server_port:  # ✓
            continue
        if not pkt["checksum_valid"] or not pkt["udp_checksum_valid"]:
            continue
        if pkt["pkt_type"] != ACK:  # ✓
            continue
        if pkt["src_ip"] != client_ip:  # ✓
            continue

        # 处理 ACK
        window.receive_ack(pkt["ack"])
          └─> reliability.SendWindow.receive_ack(4)
              └─> with self.lock:
                  └─> ack_num(4) > window_base(0) ✓
                  └─> for seq in range(0, 4):  # 0, 1, 2, 3
                      └─> self.acked[seq] = True
                      └─> self.sent_times.pop(seq, None)  # 删除
                  └─> self.window_base = 4  # 窗口滑动！
                  └─> self.total_acks += 1

        if window.all_acked():  # 4 < 10, False
            break
```

**窗口滑动后：**
- `window_base = 4`
- `sent_times = {}`（0-3 都删除了）
- `acked = {0: True, 1: True, 2: True, 3: True}`

---

### ⏰ T=17ms: 服务端发送线程继续发送

```python
# ── send_thread 还在循环中 ──

# 之前在 sleep(0.001), 现在醒来

result = window.get_next_to_send()
  └─> 窗口状态: base=4, next=4
  └─> 窗口未满（4 - 4 = 0 < 4）
  └─> seq = 4, next_seq = 5
  └─> chunk_data = read_chunk(4)
  └─> return (4, chunk_data)

# 发送 seq=4
packet = build_packet(..., DATA, 4, 0, chunk)
send(send_sock, packet, client_ip)
window.mark_sent(4)

# 循环，继续发送 seq=5, 6, 7
# ...窗口再次填满
```

**服务端现在发送了：**
- seq=4, 5, 6, 7
- `next_seq = 8`
- `sent_times = {4: t4, 5: t5, 6: t6, 7: t7}`

---

### ⏰ T=18-30ms: 重复上述过程

**客户端：**
- 接收 seq=4, 5, 6, 7
- `expected_seq = 8`
- Progress: 80%

**客户端 ACK 线程（T=25ms，超时触发）：**
- ack_num(8) > last_acked_seq(4) 且距上次 50ms+ → 发送 ACK(ack=8)

**服务端 ACK 线程：**
- 收到 ACK(8)
- `window_base = 8`
- 窗口滑动

**服务端发送线程：**
- 发送 seq=8, 9
- `next_seq = 10`
- 窗口再次填满

---

### ⏰ T=31ms: 客户端接收最后两个包

```python
# 收到 seq=8
buffer.receive_data(8, data)
  └─> expected_seq: 8 → 9

# 收到 seq=9
buffer.receive_data(9, data)
  └─> expected_seq: 9 → 10
  └─> progress = 100%
  └─> print("[Client] Progress: 100% (10/10 chunks)")
```

---

### ⏰ T=35ms: 客户端 ACK 线程发送最后的 ACK

```python
# ── ack_send_thread ──

ack_num = buffer.get_cumulative_ack()  # 10

# ack_num(10) > last_acked_seq(4) 且距上次 50ms+ → 超时触发
pkt = build_packet(..., ACK, 0, 10, b"")
send(send_sock, pkt, server_ip)
last_acked_seq = 10
last_ack_time = time.time()
```

**网络：** ACK(ack=10) → 服务端

---

### ⏰ T=36ms: 服务端确认全部完成

```python
# ── ack_recv_thread ──

raw = recv(ack_sock)
pkt = parse_packet(raw)  # {"ack": 10}

window.receive_ack(10)
  └─> for seq in range(8, 10):
      └─> acked[seq] = True
  └─> window_base = 10

if window.all_acked():
  └─> return window_base >= total_chunks  # 10 >= 10 ✓
  └─> break  # ack_recv_thread 退出
```

---

### ⏰ T=37ms: 服务端发送线程检测完成

```python
# ── send_thread ──

result = window.get_next_to_send()
  └─> next_seq = 10 >= total_chunks
  └─> return None

if result is None:
    if window.all_acked():  # True
        break  # send_thread 退出
```

**两个线程都退出了。**

---

### ⏰ T=38ms: 服务端主线程回收

```python
# ── main() finally 块 ──

t_send.join()  # 等待 send_thread 结束
t_ack.join()   # 等待 ack_recv_thread 结束

stop_flag.set()

finally:
    window.close()
      └─> reliability.SendWindow.close()
          └─> os.close(self.file_fd)
```

---

### ⏰ T=39ms: 服务端发送 FIN

```python
# 阶段5: 发送 FIN

fin_data = struct.pack("!I", total_chunks)  # 10
fin_pkt = build_packet(
    SERVER_IP, client_ip,
    SERVER_PORT, client_port,
    FIN, 0, 0, fin_data
)

recv_sock.settimeout(FIN_TIMEOUT)  # 2秒

for attempt in range(FIN_RETRIES):  # 最多5次
    send(send_sock, fin_pkt, client_ip)
    print(f"[Server] Sent FIN (attempt {attempt + 1})")

    try:
        raw = recv(recv_sock)
        pkt = parse_packet(raw)

        if (pkt and pkt["pkt_type"] == FIN_ACK
                and pkt["src_ip"] == client_ip):
            print("[Server] Received FIN_ACK")
            break
    except socket.timeout:
        print("[Server] FIN_ACK timeout, retrying...")
```

**网络：** FIN → 客户端

---

### ⏰ T=40ms: 客户端收到 FIN

```python
# ── data_recv_thread ──

raw = recv(recv_sock)
pkt = parse_packet(raw)  # {"pkt_type": 3, "data": b"\x00\x00\x00\x0a"}

elif pkt["pkt_type"] == FIN:
    total_chunks = struct.unpack("!I", pkt["data"])[0]  # 10
    buffer.set_total_chunks(total_chunks)  # 重复设置（无影响）
    print(f"[Client] Received FIN — total chunks: 10")
    stop_event.set()  # 通知 ack_send_thread 停止
    break  # data_recv_thread 退出
```

---

### ⏰ T=41ms: 客户端 ACK 线程检测停止信号

```python
# ── ack_send_thread 在 sleep(0.001) 中 ──

while not stop_event.is_set():  # stop_event 被设置了
    # 退出循环
```

**ACK 线程退出。**

---

### ⏰ T=42ms: 客户端主线程回收

```python
# ── main() ──

t_data.join()  # data_recv_thread 已退出
time.sleep(ACK_TIMEOUT * 2)  # 等待 100ms，确保最后的 ACK 发出
stop_flag.set()
t_ack.join()  # ack_send_thread 退出
```

---

### ⏰ T=43ms: 客户端组装文件

```python
# 阶段3: 检查完整性

if not buffer.is_complete():
  └─> return (total_chunks is not None and len(buffer) == total_chunks)
  └─> 10 is not None and 10 == 10 ✓

print("[Client] All chunks received, assembling file...")

output_path = f"{SAVE_DIR}/photo.jpg"
chunks_dict = buffer.get_all_chunks()
  └─> return dict(self.buffer)  # {0: data0, 1: data1, ..., 9: data9}

try:
    assemble_file(chunks_dict, output_path)
      └─> file_handler.assemble_file()
          └─> seq_numbers = [0, 1, 2, ..., 9]
          └─> 验证连续性 ✓
          └─> with open("./client_downloads/photo.jpg", 'wb') as f:
              └─> for seq in [0..9]:
                  └─> f.write(chunks_dict[seq])
          └─> print("[FileHandler] Assembled 10 chunks into '...'")
except (ValueError, IOError) as e:
    print(f"[Client] Assembly failed: {e}")
    return
```

---

### ⏰ T=44ms: 客户端计算 MD5

```python
received_md5 = compute_md5(output_path)
  └─> file_handler.compute_md5()
      └─> md5_hash = hashlib.md5()
      └─> while chunk := f.read(8192):
          └─> md5_hash.update(chunk)
      └─> return "a1b2c3d4e5f6..."
```

---

### ⏰ T=45ms: 客户端发送 FIN_ACK

```python
fin_ack_pkt = build_packet(
    client_ip, SERVER_IP,
    CLIENT_PORT, SERVER_PORT,
    FIN_ACK, 0, 0, b""
)

send(send_sock, fin_ack_pkt, SERVER_IP)
print("[Client] Sent FIN_ACK")
```

**网络：** FIN_ACK → 服务端

---

### ⏰ T=46ms: 服务端收到 FIN_ACK

```python
# ── 服务端 main() FIN 循环中 ──

raw = recv(recv_sock)
pkt = parse_packet(raw)

if (pkt and pkt["pkt_type"] == FIN_ACK):
    print("[Server] Received FIN_ACK")
    break  # 退出 FIN 重试循环
```

---

### ⏰ T=47ms: 双方生成报告

**服务端：**
```python
elapsed = time.time() - start_time  # 0.047 秒
stats = window.get_stats()
  └─> return {"total_sent": 10, "total_retrans": 0, "total_acks": 3}

hh, mm, ss = 0, 0, 0

report = f"""
==================================================
Name of the transferred file:              photo.jpg
Size of the transferred file:              10240 bytes
Number of packets sent from the server:    10
Number of retransmitted packets:           0
Number of packets received from client:    3
Time duration of the file transfer:        00:00:00
Original file MD5:                         a1b2c3d4e5f6...
==================================================
"""

print(report)

with open("./server_report_photo.jpg.txt", "w") as f:
    f.write(report)

print("[Server] Report saved")
print("[Server] Listening on 127.0.0.1:9999 ...")  # 继续等待下一个客户端
```

**客户端：**
```python
elapsed = time.time() - start_time  # 0.047 秒
stats = buffer.get_stats()
  └─> return {
      "total_received": 10,
      "duplicate_count": 0,
      "out_of_order_count": 0,
      "checksum_errors": 0
  }

total_size = os.path.getsize(output_path)  # 10240

report = f"""
==================================================
CLIENT REPORT
==================================================
Name of the transferred file:              photo.jpg
Size of the transferred file:              10240 bytes
Number of packets received from server:    10
Number of duplicate packets:               0
Number of out-of-order packets:            0
Number of packets with checksum errors:    0
Time duration of the file transfer:        00:00:00
Received file MD5:                         a1b2c3d4e5f6...
==================================================
"""

print(report)

os.makedirs(SAVE_DIR, exist_ok=True)
with open(f"{SAVE_DIR}/client_report_photo.jpg.txt", "w") as f:
    f.write(report)

print("[Client] Report saved")
print(f"[Client] File saved to: {output_path}")
```

---

## 🎉 传输完成！

**完整时间线说明**：

本时间线从服务端启动（T=-∞）开始，展示了一次完整的文件传输过程：

1. **初始化阶段**（T=-∞ ~ T=0）：服务端启动并阻塞等待，客户端启动
2. **握手阶段**（T=0 ~ T=6）：REQUEST → START → 双方启动传输线程
3. **数据传输阶段**（T=7 ~ T=38）：滑动窗口 + 累积 ACK，传输 10 个数据块
4. **终止握手阶段**（T=39 ~ T=46）：FIN → FIN_ACK 四次握手
5. **报告生成阶段**（T=47）：双方生成传输报告

### 总结时间线

| 时间 | 客户端 | 服务端 | 网络 |
|------|--------|--------|------|
| T=-∞ | （未启动） | `main()` 启动 → 创建 sockets → 进入阻塞等待 | - |
| T=0 | `main()` 启动 → 创建 sockets → 发送 REQUEST | （阻塞中） | → |
| T=1 | （等待响应） | 收到 REQUEST → 验证文件 → 准备 SendWindow | - |
| T=2 | （等待响应） | 发送 3× START 包 | → |
| T=3 | 启动 2 个线程 (data_recv, ack_send) | （准备传输） | - |
| T=4 | `data_recv_thread` 收到 START | - | - |
| T=5 | `ack_send_thread` 开始轮询（无数据，不发送） | - | - |
| T=6 | （接收中） | 启动 2 个线程 (send, ack_recv) | - |
| T=7-10 | （接收中） | `send_thread` 发送 seq=0,1,2,3 | → |
| T=11-14 | `data_recv_thread` 接收 seq=0,1,2,3 | （发送中） | - |
| T=15 | `ack_send_thread` 发送 ACK(4) | - | → |
| T=16 | （接收中） | `ack_recv_thread` 收到 ACK(4) → 窗口滑动 | - |
| T=17-30 | 接收剩余包 (seq=4-9) | 发送剩余包 (seq=4-9) | ↔ |
| T=35 | `ack_send_thread` 发送 ACK(10) | - | → |
| T=36 | （接收中） | `ack_recv_thread` 收到 ACK(10) → 全部确认 → 2 个线程退出 | - |
| T=37 | （接收中） | `send_thread` 检测完成 → 退出 | - |
| T=38 | （接收中） | 主线程回收子线程 → 关闭 file_fd | - |
| T=39 | （接收中） | 发送 FIN（携带 total_chunks） | → |
| T=40 | `data_recv_thread` 收到 FIN → 设置 stop_event | （等待 FIN_ACK） | - |
| T=41 | `ack_send_thread` 检测 stop_event → 退出 | （等待 FIN_ACK） | - |
| T=42 | 主线程回收子线程 (join) | （等待 FIN_ACK） | - |
| T=43 | 检查完整性 → 组装文件 (assemble_file) | （等待 FIN_ACK） | - |
| T=44 | 计算 MD5 校验 (compute_md5) | （等待 FIN_ACK） | - |
| T=45 | 发送 FIN_ACK | （等待 FIN_ACK） | → |
| T=46 | （生成报告中） | 收到 FIN_ACK → 退出 FIN 重试循环 | - |
| T=47 | 生成客户端报告 ✓ | 生成服务端报告 → 回到 while True 等待下一个客户端 ✓ | - |

---

## 🔍 关键设计理解

### 1. 为什么用两个线程？
- **服务端**：发送线程专心发包，ACK 接收线程专心处理确认，互不干扰
- **客户端**：接收线程专心收包，ACK 发送线程按批量/超时策略汇报

### 2. 窗口滑动的时机
- 收到 ACK(ack_num) 时立即滑动：`window_base = ack_num`
- 窗口滑动后，发送线程自动发送新的包

### 3. 累积 ACK 的妙处
- 客户端只需报告 `expected_seq`（下一个期待的序列号）
- 服务端自动知道前面所有包都收到了
- 如果每个包都单独 ACK，需要发送 819200 个 ACK！
- 累积 ACK 只需要 819200 / 64 = 12800 个

### 4. 超时重传的触发
- `check_timeouts()` 删除超时包的 `sent_times[seq]`
- `get_next_to_send()` 检测到"未在 sent_times 且未 acked"，当作新包发送

### 5. 为什么用批量 + 超时的 ACK 策略？
- **批量（16 包）**：高速传输时，每 16 个包发一次 ACK，避免 ACK 泛滥
- **超时（50ms）**：尾部/慢速时兜底，确保不漏 ACK
- **无数据不发**：`ack_num == last_acked_seq` 时两个条件都不满足，零冗余 ACK

### 6. 为什么用 os.pread？
- 800MB 文件 + 30万次重传 = 100 万次读取
- 反复 `open()/close()` = 200 万次系统调用
- `os.pread()` = 1 次 `open()` + 100 万次 `pread()`
- 而且 `os.pread()` 线程安全（不改变文件指针）

---

## 📈 实际性能数据

**测试文件：** 800MB
**传输时间：** 6分31秒 ≈ 2 MB/s
**重传率：** 0.017%（139 个重复包 / 819339 个总包）
**Checksum 错误：** 0
**MD5 验证：** 通过 ✓

---

## 🎓 总结

我们从零开始构建了一个完整的可靠文件传输系统：

1. **底层网络**：手动构建 IP + UDP 头部（packet.py, raw_socket.py）
2. **可靠性**：滑动窗口 + 超时重传 + 累积ACK（reliability.py）
3. **效率**：管道化发送、懒加载、os.pread（性能优化）
4. **正确性**：双层 checksum、MD5 验证（数据完整性）
5. **用户体验**：实时进度、统计报告、配置化（易用性）

**设计原则：**
- 模块化、职责单一
- 信息隐藏
- 线程安全
- Defensive coding
- 性能优化

---

生成日期：2026-03-16

---

# Part 3: 批量 + 超时 ACK 优化（2026-03-16 更新）

## 问题背景

课程要求："Cumulative Acknowledgement numbers (you must avoid sending an ack per packet)"

### 原始实现的问题

```python
# SRFT_UDPClient.py - 原始版本
ACK_INTERVAL = 0.01   # 每 10ms 发送一次 ACK

def ack_send_thread(...):
    while not stop_event.is_set():
        ack_num = buffer.get_cumulative_ack()
        pkt = build_packet(..., ACK, 0, ack_num, b"")
        send(send_sock, pkt, server_ip)
        time.sleep(ACK_INTERVAL)  # 无条件睡眠 10ms
```

**核心问题**：
- **定时轮询**：每 10ms 无条件发送一次 ACK，不管是否收到新数据
- **ACK 泛滥**：800MB 文件传输发送 ~38,047 个 ACK，而实际只需要 ~12,800 个（3倍冗余）
- **资源浪费**：无效的网络带宽和 CPU 周期

---

## 优化方案：批量 + 超时

使用简单的轮询方式，所有状态为 ACK 线程的本地变量，无共享可变计数器，无竞态条件。

### 设计原理

```
┌─────────────────────────────────────────────────────┐
│           批量 + 超时 ACK 策略                        │
├─────────────────────────────────────────────────────┤
│                                                      │
│  触发条件 1（批量）：                                │
│    ack_num - last_acked_seq >= 16                    │
│    → 高速传输时，每 16 个包发一次 ACK               │
│                                                      │
│  触发条件 2（超时）：                                │
│    ack_num > last_acked_seq 且距上次 >= 50ms         │
│    → 兜底尾部包/慢速场景                             │
│                                                      │
│  无数据：ack_num == last_acked_seq                   │
│    → 两个条件都不满足，不发送（零冗余 ACK）         │
│                                                      │
└─────────────────────────────────────────────────────┘
```

**关键参数**：

| 参数 | 值 | 说明 |
|------|-----|------|
| `ACK_BATCH_SIZE` | 16 | 批量触发阈值 |
| `ACK_TIMEOUT` | 0.05 (50ms) | 超时触发阈值 |
| `ACK_CHECK_INTERVAL` | 0.001 (1ms) | 轮询间隔 |

---

## 实现细节

### 1. RecvBuffer 简化（reliability.py）

RecvBuffer 只保留最简单的职责：存储数据、报告 `expected_seq`。

```python
class RecvBuffer:
    def __init__(self):
        self.buffer       = {}
        self.expected_seq = 0
        self.total_chunks = None
        self.lock         = Lock()  # 简单的互斥锁，无需 Condition

    def receive_data(self, seq, data):
        with self.lock:
            # ... 检查重复、乱序、更新 buffer ...
            while self.expected_seq in self.buffer:
                self.expected_seq += 1

    def get_cumulative_ack(self):
        """返回累积 ACK 值（expected_seq）"""
        with self.lock:
            return self.expected_seq
```

**与旧版的区别**：
- `Lock` 而非 `Condition`（不需要线程通知机制）
- 无 `last_acked_seq`、`packets_since_last_ack`（ACK 状态全在 ACK 线程本地）
- 无 `should_send_ack()`、`mark_ack_sent()` 方法

### 2. ACK 发送线程（SRFT_UDPClient.py）

所有 ACK 决策状态为线程本地变量，不与 RecvBuffer 共享：

```python
ACK_BATCH_SIZE     = 16      # 批量触发阈值
ACK_TIMEOUT        = 0.05    # 50ms 超时触发
ACK_CHECK_INTERVAL = 0.001   # 1ms 轮询间隔

def ack_send_thread(send_sock, buffer, client_ip, client_port,
                    server_ip, server_port, stop_event):
    """Send cumulative ACKs using batch + timeout strategy."""
    last_ack_time  = time.time()   # 本地变量
    last_acked_seq = 0              # 本地变量

    while not stop_event.is_set():
        ack_num = buffer.get_cumulative_ack()

        should_send = False
        if ack_num - last_acked_seq >= ACK_BATCH_SIZE:
            should_send = True   # 批量触发
        elif ack_num > last_acked_seq and time.time() - last_ack_time >= ACK_TIMEOUT:
            should_send = True   # 超时触发

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
```

---

## 工作流程详解

### 场景 1：高速传输（批量触发）

```
时间轴：
t=0ms:    开始接收数据
t=1-8ms:  快速收到 seq=0..15
          → ack_num=16, last_acked_seq=0
          → 16 - 0 = 16 >= ACK_BATCH_SIZE
          → 发送 ACK(16)
          → last_acked_seq=16

t=9-16ms: 继续收到 seq=16..31
          → ack_num=32, last_acked_seq=16
          → 32 - 16 = 16 >= ACK_BATCH_SIZE
          → 发送 ACK(32)
          ... 重复
```

**效果**：每 16 个包发一次 ACK，ACK 数量 = 数据包数 / 16

### 场景 2：尾部包（超时触发）

```
时间轴：
t=0ms:    last_acked_seq=96, 收到最后 4 个包 seq=96..99
          → ack_num=100, 100 - 96 = 4 < 16 → 批量不触发

t=1-49ms: 没有新数据，ack_num 不变（100）
          → 每 1ms 轮询，超时条件未满足

t=50ms:   ack_num(100) > last_acked_seq(96) 且 50ms 到
          → 超时触发
          → 发送 ACK(100)
```

**效果**：尾部包最多延迟 50ms 被确认，不会漏 ACK

### 场景 3：无数据（不发送）

```
时间轴：
t=0ms:    传输尚未开始，ack_num=0, last_acked_seq=0
          → 0 - 0 = 0 < 16 → 批量不触发
          → 0 == 0 → 超时条件中 ack_num > last_acked_seq 不成立
          → should_send = False → 不发送
```

**效果**：零冗余 ACK

---

## 正确性分析

### 为什么没有竞态条件？

| 变量 | 读写线程 | 共享？ |
|------|---------|--------|
| `last_acked_seq` | ACK 线程 | 否（本地变量） |
| `last_ack_time` | ACK 线程 | 否（本地变量） |
| `expected_seq` | 数据线程写，ACK 线程读 | 是，受 `Lock` 保护 |

- `get_cumulative_ack()` 获取锁后读取 `expected_seq`，返回一个不可变整数
- ACK 线程拿到这个整数后，所有判断逻辑都在本地完成
- 没有"读-判断-写"跨线程的复合操作

### 三个触发条件的覆盖

| 场景 | 批量触发 | 超时触发 | 结果 |
|------|---------|---------|------|
| 高速接收（>=16包） | ✓ | - | 立即发送 |
| 慢速接收/尾部包 | ✗ | ✓（50ms后） | 延迟发送 |
| 无新数据 | ✗ | ✗ | 不发送 |

---

## 兼容性说明

- **服务器无需改动**：ACK 优化仅在客户端
- **协议不变**：仍然是累积 ACK，服务器无感知
- **向前兼容**：新客户端可与旧服务器互操作

### 代码改动范围

| 文件 | 改动类型 | 说明 |
|------|---------|------|
| `reliability.py` | RecvBuffer 简化 | 移除 Condition、共享计数器、多余方法 |
| `SRFT_UDPClient.py` | ack_send_thread 重写 | 批量+超时策略，本地变量 |
| 其他文件 | 无改动 | - |

---

## 设计思考

### 为什么批量阈值是 16？

1. 窗口大小 64 → 每 16 包发一次 ACK → 一个窗口内 4 次 ACK → 足够频繁
2. 服务端超时 500ms → 50ms 超时兜底 → 远小于服务端超时
3. 比每包都 ACK 减少 93.75%（1/16），比每 2 包减少更多

### 为什么超时是 50ms？

1. 服务端超时 500ms → 50ms 远小于此，不会触发重传
2. 尾部包最多延迟 50ms → 对总传输时间影响微小
3. 比 TCP 标准的 40-50ms Delayed ACK 在同一范围

### 为什么用轮询而不是 Condition？

之前尝试过 `threading.Condition` 的事件驱动方案，但：
- 共享可变计数器（`packets_since_last_ack`）导致竞态条件
- `notify()/wait()` 的交互增加了复杂性
- 实际性能反而下降（3x slowdown）

轮询方案的优势：
- **简单**：所有决策状态在 ACK 线程本地，无共享可变状态
- **正确**：不可能有竞态条件
- **高效**：1ms 轮询间隔，CPU 开销可忽略

---

**更新日期**: 2026-03-16
**参考**: 课程要求 "Cumulative Acknowledgement numbers (you must avoid sending an ack per packet)"

