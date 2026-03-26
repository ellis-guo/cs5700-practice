# SRFT Phase 2 — Security Plan

## Overview

Add security to the existing SRFT (Selective Repeat File Transfer) protocol in three stages.
The transfer stack (raw UDP, sliding window, batch ACK) remains unchanged.

---

## Week 1: PSK Handshake (Authentication)

**Goal:** Verify client knows the pre-shared key before any file transfer begins.

**Mechanism: Challenge-Response**
1. Client sends `REQUEST` (filename)
2. Server generates a random 16-byte nonce, sends `CHALLENGE` packet
3. Client computes `HMAC-SHA-256(PSK, nonce)`, sends `AUTH` packet with the 32-byte result
4. Server independently computes the same HMAC and compares
   - Match → proceed to file transfer (send `START`)
   - No match / timeout → drop connection

**New packet types needed:**
| Type | Direction | Payload |
|------|-----------|---------|
| `CHALLENGE` | Server → Client | 16-byte nonce |
| `AUTH` | Client → Server | 32-byte HMAC digest |
| `AUTH_FAIL` | Server → Client | (empty, optional) |

**PSK management:** Both sides read PSK from a local config file or env var `SRFT_PSK`.
The PSK itself is never transmitted.

**Files to modify:**
- `constants.py` — add `CHALLENGE`, `AUTH`, `AUTH_FAIL` packet type constants
- `packet.py` — no structural change needed (payload carries auth data)
- `SRFT_UDPServer.py` — insert challenge-response phase between REQUEST and START
- `SRFT_UDPClient.py` — insert AUTH response phase between REQUEST and data receive loop

---

## Week 2: Data Encryption

**Goal:** Encrypt file chunks in transit so a passive observer cannot read the file.

**Mechanism: AES-256-GCM (AEAD)**
- Derives a session key from `HKDF(PSK, nonce)` using the same nonce from Week 1
- Each chunk encrypted independently: `AES-256-GCM(session_key, IV=seq_number, plaintext)`
- GCM authentication tag (16 bytes) appended to each chunk — provides both encryption and per-packet integrity
- Chunk size stays 1400 bytes (plaintext); packet grows by 16 bytes (tag)

**Files to modify:**
- `SRFT_UDPServer.py` — encrypt chunk before `build_packet`
- `SRFT_UDPClient.py` — decrypt chunk after `parse_packet`, before writing to file
- Add `crypto.py` — key derivation + AES-GCM encrypt/decrypt helpers

---

## Week 3: Integrity Verification (TBD)

To be decided — options:
- **Option A:** End-to-end HMAC-SHA-256 over the full file (simple, one final check)
- **Option B:** Per-packet HMAC (redundant if Week 2 uses GCM tags)
- **Option C:** Replace MD5 report hash with SHA-256

Decision deferred until Week 2 is complete.

---

## Week 4: AWS EC2 Testing

- Deploy server on EC2 t2.micro (Linux basic)
- Client runs locally or on a second EC2 instance
- Test under real WAN conditions (RTT ~30–150ms, possible packet loss)
- Tune `TIMEOUT_MS`, `WINDOW_SIZE` if needed for WAN performance
- Final report

---

## Current Baseline (Phase 1 result)

| Metric | Value |
|--------|-------|
| File size | 800 MB |
| Transfer time (loopback) | 3:11 |
| Retransmissions | 0 |
| Chunk size | 1400 bytes |
| Window size | 256 |
| Timeout | 300 ms |
| ACK strategy | Batch (16 pkts) + 20ms timeout |
