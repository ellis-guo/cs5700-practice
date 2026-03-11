"""
Module D: FileHandler
Role: Split files and assemble files. Nothing else.

Does NOT touch the network.
Does NOT know about packets, sequences, or acknowledgements.
"""

import hashlib
import os


def split_file(filepath, chunk_size=1024):
    """
    Split a file into chunks for transmission.
    Returns (chunks_list, total_size, total_chunks).
    chunks_list format: [(0, bytes), (1, bytes), ...]
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    total_size = os.path.getsize(filepath)

    if total_size == 0:
        return [], 0, 0

    chunks_list = []
    seq = 0

    with open(filepath, 'rb') as f:
        while True:
            chunk_data = f.read(chunk_size)
            if not chunk_data:
                break
            chunks_list.append((seq, chunk_data))
            seq += 1

    total_chunks = len(chunks_list)

    print(f"[FileHandler] Split '{filepath}' into {total_chunks} chunks ({total_size} bytes)")

    return chunks_list, total_size, total_chunks


def assemble_file(chunks_dict, output_path):
    """
    Assemble chunks back into a complete file.
    If output_path already exists, appends (1), (2), etc.
    Raises ValueError if chunks are non-consecutive.
    """
    if not chunks_dict:
        raise ValueError("Cannot assemble file: no chunks received")

    seq_numbers   = sorted(chunks_dict.keys())
    expected_seqs = list(range(len(seq_numbers)))

    if seq_numbers != expected_seqs:
        missing = set(expected_seqs) - set(seq_numbers)
        raise ValueError(f"Cannot assemble file: missing chunks {missing}")

    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    # Handle filename conflict
    final_path = output_path
    if os.path.exists(output_path):
        base, ext = os.path.splitext(output_path)
        counter = 1
        while os.path.exists(final_path):
            final_path = f"{base}({counter}){ext}"
            counter += 1

    with open(final_path, 'wb') as f:
        for seq in seq_numbers:
            f.write(chunks_dict[seq])

    print(f"[FileHandler] Assembled {len(seq_numbers)} chunks into '{final_path}'")


def compute_md5(filepath):
    """
    Compute MD5 hash of a file. Returns 32-char hex string.
    Reads in 8KB blocks to handle large files.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    md5_hash = hashlib.md5()

    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            md5_hash.update(chunk)

    result = md5_hash.hexdigest()
    print(f"[FileHandler] MD5 of '{filepath}': {result}")
    return result


def find_file(filename, repository_dir="./server_files"):
    """
    Safely locate a file in the server repository.
    Raises ValueError on path traversal or dangerous characters.
    Raises FileNotFoundError if file does not exist.
    """
    # Block path traversal and dangerous characters
    if ".." in filename or filename.startswith("/") or filename.startswith("\\"):
        raise ValueError(f"Invalid filename '{filename}': path traversal not allowed")

    dangerous_chars = ['|', '&', ';', '$', '`', '\n', '\r']
    if any(c in filename for c in dangerous_chars):
        raise ValueError(f"Invalid filename '{filename}': contains dangerous characters")

    full_path = os.path.join(repository_dir, filename)

    # Verify resolved path stays inside repository (catches symlink attacks)
    if not os.path.realpath(full_path).startswith(os.path.realpath(repository_dir)):
        raise ValueError(f"Invalid filename '{filename}': resolved path outside repository")

    if not os.path.exists(full_path):
        raise FileNotFoundError(f"File not found: '{filename}' in {repository_dir}")

    if not os.path.isfile(full_path):
        raise ValueError(f"Invalid filename '{filename}': path is a directory")

    print(f"[FileHandler] Found file: {full_path}")
    return full_path