"""
Module D: FileHandler
Role: Split files and assemble files. Nothing else.

This module does NOT touch the network.
It does NOT know about packets, sequences, or acknowledgements.
It only interacts with the local file system.

Usage:
    Server side:
        from file_handler import find_file, split_file, compute_md5
        
    Client side:
        from file_handler import assemble_file, compute_md5
"""

import hashlib
import os


def split_file(filepath, chunk_size=1024):
    """
    Split a file into chunks for transmission.
    
    Used by: Server, before transfer begins.
    
    Args:
        filepath (str): Path to the file to split
        chunk_size (int): Size of each chunk in bytes (default: 1024)
    
    Returns:
        tuple: (chunks_list, total_size, total_chunks)
            - chunks_list: [(0, bytes), (1, bytes), (2, bytes), ...]
            - total_size: Total file size in bytes
            - total_chunks: Total number of chunks
    
    Raises:
        FileNotFoundError: If the file does not exist
        IOError: If the file cannot be read
    
    Example:
        chunks, size, count = split_file("./server_files/alice.txt", 1024)
        # Returns: [(0, b'...'), (1, b'...'), ...], 163841, 161
    """
    # Check if file exists
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    
    # Get total file size
    total_size = os.path.getsize(filepath)
    
    # Handle empty file
    if total_size == 0:
        return [], 0, 0
    
    chunks_list = []
    seq = 0
    
    # Read file in binary mode and split into chunks
    with open(filepath, 'rb') as f:
        while True:
            chunk_data = f.read(chunk_size)
            
            # End of file
            if not chunk_data:
                break
            
            # Store as (sequence_number, data_bytes) tuple
            chunks_list.append((seq, chunk_data))
            seq += 1
    
    total_chunks = len(chunks_list)
    
    print(f"[FileHandler] Split '{filepath}' into {total_chunks} chunks")
    print(f"[FileHandler] Total size: {total_size} bytes")
    print(f"[FileHandler] Chunk size: {chunk_size} bytes")
    print(f"[FileHandler] Last chunk size: {len(chunks_list[-1][1]) if chunks_list else 0} bytes")
    
    return chunks_list, total_size, total_chunks


def assemble_file(chunks_dict, output_path):
    """
    Assemble chunks back into a complete file.
    
    Used by: Client, after transfer is complete.
    
    Args:
        chunks_dict (dict): {seq: bytes} dictionary from RecvBuffer
        output_path (str): Path where the assembled file will be saved
                          If file exists, automatically adds (1), (2), etc.
    
    Raises:
        ValueError: If chunks are missing (non-consecutive sequence numbers)
        IOError: If the file cannot be written
    
    Example:
        chunks = {0: b'...', 1: b'...', 2: b'...'}
        assemble_file(chunks, "./client_downloads/alice.txt")
        # Creates: ./client_downloads/alice.txt
        # If exists: ./client_downloads/alice(1).txt
    """
    # Handle empty chunks
    if not chunks_dict:
        raise ValueError("Cannot assemble file: no chunks received")
    
    # Get all sequence numbers and sort them
    seq_numbers = sorted(chunks_dict.keys())
    
    # Check for completeness: seq should be 0, 1, 2, 3, ..., n-1
    expected_seq = list(range(len(seq_numbers)))
    if seq_numbers != expected_seq:
        missing = set(expected_seq) - set(seq_numbers)
        raise ValueError(
            f"Cannot assemble file: missing chunks {missing}. "
            f"Expected continuous sequence 0-{len(seq_numbers)-1}, "
            f"but got {seq_numbers}"
        )
    
    # Check if output directory exists, create if not
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        print(f"[FileHandler] Creating directory: {output_dir}")
        os.makedirs(output_dir, exist_ok=True)
    
    # Handle file name conflict: add (1), (2), (3)...
    final_output_path = output_path
    if os.path.exists(output_path):
        # Split filename into base and extension
        base, ext = os.path.splitext(output_path)
        
        counter = 1
        while os.path.exists(final_output_path):
            final_output_path = f"{base}({counter}){ext}"
            counter += 1
        
        print(f"[FileHandler] File exists, saving as: {final_output_path}")
    
    # Open output file and write chunks in order
    try:
        with open(final_output_path, 'wb') as f:
            for seq in seq_numbers:
                chunk_data = chunks_dict[seq]
                f.write(chunk_data)
        
        # Get final file size
        final_size = os.path.getsize(final_output_path)
        
        print(f"[FileHandler] Assembled {len(seq_numbers)} chunks into '{final_output_path}'")
        print(f"[FileHandler] Final file size: {final_size} bytes")
        
    except IOError as e:
        raise IOError(f"Failed to write assembled file: {e}")


def compute_md5(filepath):
    """
    Compute MD5 hash of a file for verification.
    
    Used by: Both Server and Client for integrity verification.
    
    Args:
        filepath (str): Path to the file
    
    Returns:
        str: MD5 hash as a 32-character hexadecimal string
    
    Raises:
        FileNotFoundError: If the file does not exist
        IOError: If the file cannot be read
    
    Example:
        md5 = compute_md5("./server_files/alice.txt")
        # Returns: "d41d8cd98f00b204e9800998ecf8427e"
    """
    # Check if file exists
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    
    # Create MD5 hash object
    md5_hash = hashlib.md5()
    
    # Read file in chunks to avoid loading large files into memory
    try:
        with open(filepath, 'rb') as f:
            # Read 8KB at a time
            while chunk := f.read(8192):
                md5_hash.update(chunk)
        
        result = md5_hash.hexdigest()
        
        print(f"[FileHandler] MD5 of '{filepath}': {result}")
        
        return result
        
    except IOError as e:
        raise IOError(f"Failed to read file for MD5 computation: {e}")


def find_file(filename, repository_dir="./server_files"):
    """
    Safely locate a file in the server's file repository.
    
    Used by: Server, after receiving REQUEST packet.
    
    Args:
        filename (str): Filename requested by client (e.g., "alice.txt")
        repository_dir (str): Server's file repository directory
    
    Returns:
        str: Full path to the file if found
    
    Raises:
        ValueError: If filename contains invalid/dangerous characters
        FileNotFoundError: If file does not exist in repository
    
    Example:
        path = find_file("alice.txt", "./server_files")
        # Returns: "./server_files/alice.txt"
        
    Security:
        - Blocks directory traversal: "..", "../", absolute paths
        - Blocks dangerous characters: |, &, ;, $, `, etc.
        - Verifies resolved path stays inside repository
    """
    # Security check 1: Prevent directory traversal attacks
    # Block: "../", "..\\", absolute paths
    if ".." in filename or filename.startswith("/") or filename.startswith("\\"):
        raise ValueError(
            f"Invalid filename '{filename}': "
            "path traversal not allowed (no '..' or absolute paths)"
        )
    
    # Security check 2: Block dangerous characters
    dangerous_chars = ['|', '&', ';', '$', '`', '\n', '\r']
    if any(char in filename for char in dangerous_chars):
        raise ValueError(
            f"Invalid filename '{filename}': "
            "contains dangerous characters"
        )
    
    # Construct full path
    full_path = os.path.join(repository_dir, filename)
    
    # Security check 3: Verify the resolved path is still inside repository
    # This catches symlink attacks
    real_repo = os.path.realpath(repository_dir)
    real_file = os.path.realpath(full_path)
    
    if not real_file.startswith(real_repo):
        raise ValueError(
            f"Invalid filename '{filename}': "
            "resolved path is outside repository"
        )
    
    # Check if file exists
    if not os.path.exists(full_path):
        raise FileNotFoundError(
            f"File not found: '{filename}' "
            f"(searched in {repository_dir})"
        )
    
    # Check if it's a file (not a directory)
    if not os.path.isfile(full_path):
        raise ValueError(
            f"Invalid filename '{filename}': "
            "path is a directory, not a file"
        )
    
    print(f"[FileHandler] Found file: {full_path}")
    
    return full_path