"""
constants.py
Shared constants for the SRFT project.

All modules import from here. Do not define these values anywhere else.

Usage:
    from constants import REQUEST, DATA, ACK, FIN, FIN_ACK
"""

# ---------------------------------------------------------------------------
# Packet type constants
# ---------------------------------------------------------------------------

REQUEST = 0   # Client -> Server: payload = filename
DATA    = 1   # Server -> Client: payload = file chunk
ACK     = 2   # Client -> Server: payload = empty
FIN     = 3   # Server -> Client: payload = empty
FIN_ACK = 4   # Client -> Server: payload = empty