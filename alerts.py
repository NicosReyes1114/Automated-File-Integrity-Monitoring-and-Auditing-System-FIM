"""
Module: alerts.py

Description:
    Provides console presentation of detected file integrity events.

Responsibilities:
    - Format detected events for display.
    - Display detected events through the console.
    - Display scan summaries.
    - Provide a common notification interface.

Dependencies:
    None

Author: Julian Nicos Reyes
Version: 1.0.0
"""


def format_event(event: dict) -> str:
    """
    Format a detected event as a single line of text.

    Args:
        event (dict): Event record produced by detector.py.

    Returns:
        str: Human-readable event description.
    """

    message = f"[{event['event_type']}] {event['file_path']}"

    old_state = event.get("old_state")
    new_state = event.get("new_state")

    # Show state transitions; content changes keep the same state.
    if old_state != new_state:
        message += f" ({old_state or 'NONE'} -> {new_state or 'NONE'})"

    return message


def summarize_events(events: list[dict]) -> dict[str, int]:
    """
    Count detected events by event type.

    Args:
        events (list[dict]): Events produced by detector.py.

    Returns:
        dict[str, int]: Mapping of event types to their counts.
    """

    counts = {}

    for event in events:
        event_type = event["event_type"]
        counts[event_type] = counts.get(event_type, 0) + 1

    return counts


def notify_events(events: list[dict]) -> None:
    """
    Notify the user of detected events.

    This is the common notification interface. Console output is the
    only supported notification method at present.

    Args:
        events (list[dict]): Events produced by detector.py.
    """

    if not events:
        print("No integrity changes detected.")
        return

    print(f"\n{len(events)} integrity event(s) detected:")

    for event in events:
        print(format_event(event))


def display_scan_summary(
    files_scanned: int,
    events: list[dict],
    scan_complete: bool
) -> None:
    """
    Display a summary of a completed integrity scan.

    Args:
        files_scanned (int): Number of files observed in the scan.
        events (list[dict]): Events produced by detector.py.
        scan_complete (bool): Whether directory traversal completed.
    """

    print("\nScan summary:")
    print(f"Files scanned: {files_scanned}")
    print(f"Events detected: {len(events)}")

    for event_type, count in sorted(summarize_events(events).items()):
        print(f"  {event_type}: {count}")

    if not scan_complete:
        print(
            "Warning: Scan was incomplete. "
            "Missing-file detection was suppressed."
        )