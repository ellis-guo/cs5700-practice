"""
Module C: Reliability
Role: Manage the state of reliable transfer. Nothing else.

Does NOT send or receive packets. Does NOT touch the network.
Server uses SendWindow. Client uses RecvBuffer.
Both classes are thread-safe via internal Lock.
"""

import time
from threading import Lock


class SendWindow:
    """
    Sending-side sliding window. Used by Server.

    Shared between Send Thread and ACK Recv Thread.
    All methods acquire self.lock before touching internal state.
    """

    def __init__(self, chunks, window_size=16, timeout_ms=500):
        self.chunks       = chunks       # [(0, bytes), (1, bytes), ...]
        self.window_size  = window_size
        self.timeout_ms   = timeout_ms

        self.window_base  = 0            # left edge: smallest unacked seq
        self.next_seq     = 0            # next seq to send for the first time

        self.sent_times   = {}           # {seq: timestamp} for timeout detection
        self.acked        = {}           # {seq: True} for confirmed packets

        self.total_sent   = 0
        self.total_retrans = 0
        self.total_acks   = 0

        self.lock         = Lock()

    def get_next_to_send(self):
        """
        Return (seq, chunk) for the next packet to send, or None if nothing to send.

        Priority:
          1. Timed-out packets within window (retransmit)
          2. New packets within window (first send)
          3. None if window is full and no timeouts
        """
        with self.lock:
            # Scan window for packets needing (re)transmission
            for seq in range(self.window_base, self.window_base + self.window_size):
                if seq >= len(self.chunks):
                    break
                # Not in sent_times means: never sent, or timed out and deleted
                if seq not in self.sent_times and seq not in self.acked:
                    return (seq, self.chunks[seq][1])

            # Send new packet if window has room
            if (self.next_seq - self.window_base < self.window_size
                    and self.next_seq < len(self.chunks)):
                seq = self.next_seq
                self.next_seq += 1
                return (seq, self.chunks[seq][1])

            return None

    def mark_sent(self, seq):
        """Record that seq was just transmitted. Distinguishes first send vs retransmit."""
        with self.lock:
            if seq in self.sent_times:
                self.total_retrans += 1
            else:
                self.total_sent += 1
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
                self.acked[seq] = True
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
                if seq not in self.acked and now - t > threshold
            ]
            for seq in timed_out:
                del self.sent_times[seq]

    def all_acked(self):
        """Return True when every chunk has been acknowledged."""
        with self.lock:
            return self.window_base >= len(self.chunks)

    def get_stats(self):
        """Return transfer statistics for the final report."""
        with self.lock:
            return {
                "total_sent":    self.total_sent,
                "total_retrans": self.total_retrans,
                "total_acks":    self.total_acks,
            }


class RecvBuffer:
    """
    Receiving-side buffer. Used by Client.

    Shared between Data Recv Thread and ACK Send Thread.
    All methods acquire self.lock before touching internal state.
    """

    def __init__(self):
        self.buffer       = {}    # {seq: bytes}
        self.expected_seq = 0     # cumulative ACK value = next seq we need
        self.total_chunks = None  # set when FIN is received
        self.lock         = Lock()

    def receive_data(self, seq, data):
        """
        Store an incoming data chunk. Silently discard duplicates.
        Advances expected_seq as far as consecutive chunks allow.
        """
        with self.lock:
            if seq in self.buffer:
                return  # duplicate, discard
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