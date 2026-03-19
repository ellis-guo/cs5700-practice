"""
Module C: Reliability
Role: Manage the state of reliable transfer. Nothing else.

Does NOT send or receive packets. Does NOT touch the network.
Server uses SendWindow. Client uses RecvBuffer.
Both classes are thread-safe via internal Lock.
"""

import os
import time
from threading import Lock


class SendWindow:
    """
    Sending-side sliding window. Used by Server.

    Shared between Send Thread and ACK Recv Thread.
    All methods acquire self.lock before touching internal state.

    Uses lazy loading: reads chunks from file on-demand instead of loading all into memory.
    """

    def __init__(self, filepath, chunk_size, total_chunks, window_size=64, timeout_ms=500):
        self.filepath     = filepath     # path to file (kept for reference)
        self.chunk_size   = chunk_size   # bytes per chunk
        self.total_chunks = total_chunks # total number of chunks
        self.window_size  = window_size
        self.timeout_ms   = timeout_ms

        self.window_base  = 0            # left edge: smallest unacked seq
        self.next_seq     = 0            # next seq to send for the first time

        self.sent_times   = {}           # {seq: timestamp} for timeout detection
        self.ever_sent    = set()        # seqs transmitted at least once

        self.total_sent   = 0
        self.total_retrans = 0
        self.total_acks   = 0

        self.lock         = Lock()

        # Open file descriptor once for thread-safe reads
        # os.pread() is thread-safe and position-independent
        try:
            self.file_fd = os.open(filepath, os.O_RDONLY)
        except OSError as e:
            raise IOError(f"Failed to open file '{filepath}': {e}")

    def read_chunk(self, seq):
        """
        Read a specific chunk from file on-demand using position-independent read.
        Thread-safe: os.pread() doesn't modify file offset, safe for concurrent calls.

        Args:
            seq: sequence number of chunk to read

        Returns:
            bytes: chunk data (may be shorter than chunk_size for last chunk)
        """
        offset = seq * self.chunk_size

        try:
            # os.pread: atomic position-independent read, thread-safe
            chunk_data = os.pread(self.file_fd, self.chunk_size, offset)
            return chunk_data
        except OSError as e:
            # Log error but return empty bytes to avoid crashing transfer
            print(f"[SendWindow] Error reading chunk {seq}: {e}")
            return b""

    def get_next_to_send(self):
        """
        Return (seq, chunk) for the next packet to send, or None if nothing to send.

        Priority:
          1. Timed-out packets within window (retransmit)
          2. New packets within window (first send)
          3. None if window is full and no timeouts
        """
        with self.lock:
            # Priority 1: retransmit timed-out packets (only already-sent seqs)
            seq = None
            for s in range(self.window_base, min(self.next_seq, self.window_base + self.window_size)):
                if s >= self.total_chunks:
                    break
                if s not in self.sent_times:
                    seq = s
                    break

            # Priority 2: send new packet if window has room
            if seq is None:
                if (self.next_seq - self.window_base < self.window_size
                        and self.next_seq < self.total_chunks):
                    seq = self.next_seq
                    self.next_seq += 1

            if seq is None:
                return None

        # Disk I/O outside the lock — ack_recv_thread can acquire lock freely
        return (seq, self.read_chunk(seq))

    def mark_sent(self, seq):
        """Record that seq was just transmitted. Distinguishes first send vs retransmit."""
        with self.lock:
            if seq in self.ever_sent:
                self.total_retrans += 1
            else:
                self.total_sent += 1
                self.ever_sent.add(seq)
            self.sent_times[seq] = time.time()

    def receive_ack(self, ack_num):
        """
        Process a cumulative ACK. Marks seq 0..ack_num-1 as confirmed, slides window.
        Stale ACKs (ack_num <= window_base) are ignored.
        """
        with self.lock:
            if ack_num <= self.window_base:
                return
            for seq in range(self.window_base, ack_num):
                self.sent_times.pop(seq, None)
            self.window_base = ack_num
            self.total_acks += 1

    def check_timeouts(self):
        """
        Delete sent_times entries for packets that have exceeded timeout_ms.
        get_next_to_send() will pick them up as needing retransmission.
        """
        now = time.time()
        threshold = self.timeout_ms / 1000.0
        with self.lock:
            timed_out = [
                seq for seq, t in self.sent_times.items()
                if now - t > threshold
            ]
            for seq in timed_out:
                del self.sent_times[seq]

    def all_acked(self):
        """Return True when every chunk has been acknowledged."""
        with self.lock:
            return self.window_base >= self.total_chunks

    def get_stats(self):
        """Return transfer statistics for the final report."""
        with self.lock:
            return {
                "total_sent":    self.total_sent,
                "total_retrans": self.total_retrans,
                "total_acks":    self.total_acks,
            }

    def close(self):
        """
        Close the file descriptor. Should be called after transfer completes.
        Safe to call multiple times.
        """
        if hasattr(self, 'file_fd') and self.file_fd >= 0:
            try:
                os.close(self.file_fd)
                self.file_fd = -1
            except OSError as e:
                print(f"[SendWindow] Warning: Failed to close file descriptor: {e}")


class RecvBuffer:
    """
    Receiving-side buffer. Used by Client.

    Shared between Data Recv Thread and ACK Send Thread.
    All methods acquire self.lock before touching internal state.
    Tracks comprehensive statistics for project report.
    """

    def __init__(self, window_size=256):
        self.buffer       = {}    # {seq: bytes}
        self.expected_seq = 0     # cumulative ACK value = next seq we need
        self.total_chunks = None  # set when FIN is received
        self.window_size  = window_size
        self.lock         = Lock()

        # Statistics counters (thread-safe via lock)
        self.total_received    = 0  # Total DATA packets received (including duplicates)
        self.duplicate_count   = 0  # Packets received that were already in buffer
        self.out_of_order_count = 0  # Packets with seq > expected_seq
        self.checksum_errors   = 0  # Packets dropped due to checksum failure

    def receive_data(self, seq, data):
        """
        Store an incoming data chunk. Tracks statistics and discards duplicates.
        Advances expected_seq as far as consecutive chunks allow.

        Args:
            seq: sequence number of the packet
            data: payload bytes
        """
        with self.lock:
            self.total_received += 1

            # Discard packets outside receive window
            if seq >= self.expected_seq + self.window_size:
                return

            # Check for duplicate
            if seq in self.buffer:
                self.duplicate_count += 1
                return  # duplicate, discard

            # Check for out-of-order (arrived before earlier packets)
            if seq > self.expected_seq:
                self.out_of_order_count += 1

            self.buffer[seq] = data

            # Advance expected_seq over any consecutive chunks now in buffer
            while self.expected_seq in self.buffer:
                self.expected_seq += 1

    def get_cumulative_ack(self):
        """Return the cumulative ACK value to send back to Server."""
        with self.lock:
            return self.expected_seq

    def set_total_chunks(self, total):
        """Called when FIN is received and total chunk count becomes known."""
        with self.lock:
            self.total_chunks = total

    def is_complete(self):
        """Return True when all chunks have been received."""
        with self.lock:
            return (self.total_chunks is not None
                    and len(self.buffer) == self.total_chunks)

    def get_all_chunks(self):
        """Return the buffer dict to Module D for file assembly."""
        with self.lock:
            return dict(self.buffer)

    def record_checksum_error(self):
        """
        Record a packet that was dropped due to checksum failure.
        Called by receive thread when checksum validation fails.
        """
        with self.lock:
            self.checksum_errors += 1

    def get_stats(self):
        """
        Return transfer statistics for the final report.
        Thread-safe.

        Returns:
            dict with statistics counters
        """
        with self.lock:
            return {
                "total_received":     self.total_received,
                "duplicate_count":    self.duplicate_count,
                "out_of_order_count": self.out_of_order_count,
                "checksum_errors":    self.checksum_errors,
            }