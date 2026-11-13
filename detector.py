"""
Module: detector.py

Description:
    Provides functionality for detecting changes in monitored files.

Responsibilities:
    - Compare previously stored file states with the current scan.
    - Identify new, modified, missing, reappearing, and inaccessible files.
    - Avoid reporting missing files after incomplete scans.

Dependencies:
    None

Author: Julian Nicos Reyes
Version: 1.0.0
"""


def detect_changes(
    previous_baseline: dict,
    current_scan: dict,
    scan_complete: bool = True
) -> list[dict]:
    """
    Compare previously stored file states with the current scan.

    Args:
        previous_baseline (dict): Previously stored file records.
        current_scan (dict): File records from the latest directory scan.
        scan_complete (bool): Whether directory traversal completed.

    Returns:
        list[dict]: Detected file integrity events.
    """

    previous_paths = set(previous_baseline.keys())
    current_paths = set(current_scan.keys())

    new_paths = current_paths - previous_paths
    missing_paths = previous_paths - current_paths
    retained_paths = previous_paths & current_paths

    events = []

    # Detect newly discovered files.
    for path in sorted(new_paths):
        events.append({
            "file_path": path,
            "event_type": "NEW_FILE",
            "old_state": None,
            "old_hash": None,
            "new_state": current_scan[path]["file_state"],
            "new_hash": current_scan[path]["file_hash"]
        })

    # Only identify missing files when traversal was complete.
    if scan_complete:
        for path in sorted(missing_paths):
            old_record = previous_baseline[path]

            # Avoid repeatedly recording the same missing-file event.
            if old_record["file_state"] != "FILE_NOT_FOUND":
                events.append({
                    "file_path": path,
                    "event_type": "FILE_NOT_FOUND",
                    "old_state": old_record["file_state"],
                    "old_hash": old_record["file_hash"],
                    "new_state": None,
                    "new_hash": None
                })

    # Compare files discovered in both scans.
    for path in sorted(retained_paths):
        old_record = previous_baseline[path]
        new_record = current_scan[path]

        old_state = old_record["file_state"]
        new_state = new_record["file_state"]

        old_hash = old_record["file_hash"]
        new_hash = new_record["file_hash"]

        if old_state != new_state:

            if new_state == "FILE_NOT_FOUND":
                event_type = "FILE_NOT_FOUND"

            elif old_state == "FILE_NOT_FOUND" and new_state == "OK":
                event_type = "FILE_REAPPEARED"

            elif old_state == "OK" and new_state == "PERMISSION_DENIED":
                event_type = "ACCESS_LOST"

            elif old_state == "PERMISSION_DENIED" and new_state == "OK":
                event_type = "ACCESS_RESTORED"

            else:
                event_type = "FILE_STATE_CHANGED"

            events.append({
                "file_path": path,
                "event_type": event_type,
                "old_state": old_state,
                "old_hash": old_hash,
                "new_state": new_state,
                "new_hash": new_hash
            })

            # A restored or reappearing file is compared against the
            # last successful hash preserved in the baseline.
            if (
                new_state == "OK"
                and old_hash is not None
                and old_hash != new_hash
            ):
                events.append({
                    "file_path": path,
                    "event_type": "FILE_MODIFIED",
                    "old_state": old_state,
                    "old_hash": old_hash,
                    "new_state": new_state,
                    "new_hash": new_hash
                })

        # Compare hashes only when both versions were readable.
        elif old_state == "OK" and new_state == "OK":
            if old_hash != new_hash:
                events.append({
                    "file_path": path,
                    "event_type": "FILE_MODIFIED",
                    "old_state": old_state,
                    "old_hash": old_hash,
                    "new_state": new_state,
                    "new_hash": new_hash
                })

    return events