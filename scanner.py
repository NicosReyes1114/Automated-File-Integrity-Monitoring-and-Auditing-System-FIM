
"""
Module: scanner.py

Description:
    Provides functionality for scanning directories and file paths.

Responsibilities:
    - Recursively scan directories.
    - Calculate file hashes.
    - Retrieve file metadata.
    - Report whether directory traversal completed successfully.

Dependencies:
    - os
    - hasher

Author: Julian Nicos Reyes
Version: 1.0.0
"""

import os

from hasher import calculate_file_hash


def scan_directory(directory_path: str) -> tuple[dict, bool]:
    """
    Recursively scan a directory and calculate hashes for its files.

    Args:
        directory_path (str): Path to the directory being monitored.

    Returns:
        tuple[dict, bool]:
            - Dictionary mapping relative file paths to their records.
            - Boolean indicating whether directory traversal completed.
    """

    file_records = {}
    scan_complete = True

    def handle_scan_error(error: OSError) -> None:
        """
        Mark the scan as incomplete when a directory cannot be accessed.
        """

        nonlocal scan_complete
        scan_complete = False

        print(f"Scan warning: {error}")

    for root, directories, files in os.walk(
        directory_path,
        onerror=handle_scan_error
    ):

        for filename in files:
            file_path = os.path.join(root, filename)

            # Retrieve metadata before calculating the file hash.
            metadata = get_file_metadata(file_path)

            integrity_state = calculate_file_hash(file_path)

            if integrity_state in ["PERMISSION_DENIED", "FILE_NOT_FOUND", "READ_ERROR"]:
                file_state = integrity_state
                file_hash = None

            else:
                file_state = "OK"
                file_hash = integrity_state

            relative_path = os.path.relpath(
                file_path,
                directory_path
            )

            file_records[relative_path] = {
                "file_state": file_state,
                "file_hash": file_hash,
                "file_size": metadata.get("file_size"),
                "modified_time": metadata.get("modified_time")
            }

    return file_records, scan_complete


def get_file_metadata(
    file_path: str
) -> dict[str, int | float | str]:
    """
    Retrieve metadata for a file.

    Args:
        file_path (str): Path to the target file.

    Returns:
        dict: File size and modification timestamp,
              or an error status if metadata cannot be retrieved.
    """

    try:
        file_stats = os.stat(file_path)

        return {
            "file_size": file_stats.st_size,
            "modified_time": file_stats.st_mtime
        }

    except PermissionError:
        return {"status": "PERMISSION_DENIED"}

    except FileNotFoundError:
        return {"status": "FILE_NOT_FOUND"}
