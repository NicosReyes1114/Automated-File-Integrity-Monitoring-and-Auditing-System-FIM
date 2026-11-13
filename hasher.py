
"""
Module: hasher.py

Description:
    Provides functionality for calculating SHA-256 hashes of files.

Responsibilities:
    - Calculate SHA-256 file hashes.

Dependencies:
    - hashlib

Author: Julian Nicos Reyes
Version: 1.0.0
"""

import hashlib


def calculate_file_hash(file_path: str) -> str:
    """
    Calculate the SHA-256 hash of a file.

    Args:
        file_path (str): Path to the target file.

    Returns:
        str: SHA-256 hash or an error status.

    Notes:
        The function reads the file in chunks to avoid loading
        the entire file into memory.
    """

    try:
        with open(file_path, "rb") as file:
            hash_obj = hashlib.sha256()

            # Process the file in chunks to limit memory usage.
            while True:
                chunk = file.read(4096)

                if not chunk:
                    break

                hash_obj.update(chunk)

        return hash_obj.hexdigest()

    except PermissionError:
        return "PERMISSION_DENIED"

    except FileNotFoundError:
        return "FILE_NOT_FOUND"

    except OSError:
        return "READ_ERROR"
