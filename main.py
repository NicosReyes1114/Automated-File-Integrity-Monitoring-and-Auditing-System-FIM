"""
Module: main.py

Description:
    Main entry point for the Automated File Integrity Monitor.

Responsibilities:
    - Register and manage monitored directories.
    - Generate unique database paths.
    - Coordinate directory scans and integrity checks.
    - Provide access to baseline records and audit history.

Dependencies:
    - os
    - json
    - hashlib
    - database
    - scanner
    - detector
    - alerts

Author: Julian Nicos Reyes
Version: 1.0.0
"""

import os
import json
import hashlib
import sqlite3

from database import (
    initialize_database,
    get_baseline,
    process_scan,
    search_baseline,
    search_baseline_by_state,
    get_audit_history,
    search_audit_history as search_audit_records
)

from scanner import scan_directory
from detector import detect_changes
from alerts import notify_events, display_scan_summary


REGISTRY_PATH = "monitored_directories.json"
DATABASE_DIRECTORY = "databases"


def normalize_directory_path(directory_path: str) -> str:
    """
    Convert a directory path into a consistent registry key.

    Args:
        directory_path (str): Directory path to normalize.

    Returns:
        str: Normalized absolute directory path.
    """

    absolute_path = os.path.abspath(
        os.path.expanduser(directory_path)
    )

    return os.path.normcase(absolute_path)


def load_registry() -> dict:
    """
    Load registered monitored directories.

    Returns:
        dict: Registered directories and their database information.

    Raises:
        RuntimeError: If the registry contains invalid JSON.
    """

    if not os.path.exists(REGISTRY_PATH):
        return {}

    try:
        with open(REGISTRY_PATH, "r", encoding="utf-8") as file:
            registry = json.load(file)

    except json.JSONDecodeError as error:
        raise RuntimeError(
            "The registry file contains invalid JSON. "
            "It was not modified."
        ) from error

    if not isinstance(registry, dict):
        raise RuntimeError(
            "The registry file has an invalid structure."
        )

    return registry


def save_registry(registry: dict) -> None:
    """
    Save monitored directory information to the registry.

    Args:
        registry (dict): Registry information to save.
    """

    temporary_path = REGISTRY_PATH + ".tmp"

    with open(temporary_path, "w", encoding="utf-8") as file:
        json.dump(registry, file, indent=4)

    # Replace the registry only after the new file is written.
    os.replace(temporary_path, REGISTRY_PATH)


def generate_database_path(directory_path: str) -> str:
    """
    Generate a unique database path for a monitored directory.

    Args:
        directory_path (str): Path to the monitored directory.

    Returns:
        str: Generated database file path.
    """

    normalized_path = normalize_directory_path(directory_path)

    directory_name = os.path.basename(
        os.path.normpath(directory_path)
    )

    # Drive roots and filesystem roots may have no basename.
    if not directory_name:
        directory_name = "root"

    path_hash = hashlib.sha256(
        normalized_path.encode("utf-8")
    ).hexdigest()[:12]

    os.makedirs(DATABASE_DIRECTORY, exist_ok=True)

    database_name = f"{directory_name}_{path_hash}.db"

    return os.path.join(DATABASE_DIRECTORY, database_name)


def add_directory() -> None:
    """
    Register a directory for file integrity monitoring.
    """

    directory_path = input(
        "Enter directory path: "
    ).strip().strip('"')

    directory_path = os.path.abspath(
        os.path.expanduser(directory_path)
    )

    if not os.path.isdir(directory_path):
        print("Error: Directory does not exist.")
        return

    registry_key = normalize_directory_path(directory_path)
    registry = load_registry()

    # Reactivate an existing registration instead of creating another DB.
    if registry_key in registry:
        registry[registry_key]["active"] = True
        save_registry(registry)

        print("Directory already registered. Reactivated it.")
        return

    database_path = generate_database_path(directory_path)

    initialize_database(database_path)

    registry[registry_key] = {
        "directory_path": directory_path,
        "database_path": database_path,
        "baseline_initialized": False,
        "active": True
    }

    save_registry(registry)

    print(f"Directory registered: {directory_path}")
    print(f"Database created: {database_path}")


def list_directories() -> list[str]:
    """
    Display registered active monitored directories.

    Returns:
        list[str]: Registry keys for active directories.
    """

    registry = load_registry()

    active_directories = [
        key
        for key, information in registry.items()
        if information.get("active", True)
    ]

    if not active_directories:
        print("No active directories registered.")
        return []

    print("\nRegistered Directories:")

    for index, key in enumerate(active_directories, start=1):
        information = registry[key]

        print(f"\n{index}. {information['directory_path']}")
        print(f"   Database: {information['database_path']}")

    return active_directories


def select_directory() -> str | None:
    """
    Select an active monitored directory.

    Returns:
        str | None: Selected registry key, or None.
    """

    directories = list_directories()

    if not directories:
        return None

    try:
        selection = int(
            input("\nSelect directory number: ")
        )

        if 1 <= selection <= len(directories):
            return directories[selection - 1]

        print("Invalid selection.")

    except ValueError:
        print("Please enter a valid number.")

    return None


def run_scan(registry_key: str) -> None:
    """
    Perform an integrity scan on a selected directory.

    Args:
        registry_key (str): Registry key of the selected directory.
    """

    registry = load_registry()

    information = registry[registry_key]

    directory_path = information["directory_path"]
    database_path = information["database_path"]

    if not os.path.isdir(directory_path):
        print("Error: Monitored directory no longer exists.")
        return

    previous_baseline = get_baseline(database_path)

    current_scan, scan_complete = scan_directory(
        directory_path
    )

    if not information["baseline_initialized"]:

        # An incomplete initial scan must not create a partial baseline.
        if scan_complete:
            process_scan(database_path, current_scan, [])

            information["baseline_initialized"] = True
            save_registry(registry)

            print("Initial baseline established.")
            print(f"Files recorded: {len(current_scan)}")

        else:
            print(
                "Initial scan was incomplete. "
                "No baseline was saved."
            )

        return

    events = detect_changes(
        previous_baseline,
        current_scan,
        scan_complete
    )

    process_scan(
        database_path,
        current_scan,
        events
    )

    notify_events(events)

    display_scan_summary(
        len(current_scan),
        events,
        scan_complete
    )


def view_baseline(database_path: str) -> None:
    """
    Display all baseline records for a selected database.

    Args:
        database_path (str): Selected database path.
    """

    records = search_baseline(
        database_path,
        "",
        verbose=True
    )

    if not records:
        print("No baseline records found.")
        return

    for record in records:
        print(f"\nFile: {record['file_path']}")
        print(f"State: {record['file_state']}")
        print(f"Hash: {record['file_hash']}")
        print(f"Size: {record['file_size']}")
        print(f"Modified: {record['modified_time']}")
        print(f"Last scanned: {record['last_scanned']}")


def search_files(database_path: str) -> None:
    """
    Search baseline records by filename or partial path.

    Args:
        database_path (str): Selected database path.
    """

    search_term = input(
        "Enter filename or search term: "
    ).strip()

    results = search_baseline(
        database_path,
        search_term,
        verbose=True
    )

    if not results:
        print("No matching files found.")
        return

    for record in results:
        print(f"\nFile: {record['file_path']}")
        print(f"State: {record['file_state']}")
        print(f"Hash: {record['file_hash']}")
        print(f"Size: {record['file_size']}")
        print(f"Modified: {record['modified_time']}")


def view_audit_history(database_path: str) -> None:
    """
    Display all historical integrity events.

    Args:
        database_path (str): Selected database path.
    """

    history = get_audit_history(
        database_path,
        verbose=True
    )

    if not history:
        print("No audit events found.")
        return

    for event in history:
        print_event_record(event)


def print_event_record(event: dict) -> None:
    """
    Display a single audit-history event.

    Args:
        event (dict): Event record retrieved from the audit log.
    """

    print(f"\nEvent ID: {event['event_id']}")
    print(f"File: {event['file_path']}")
    print(f"Event: {event['event_type']}")
    print(f"Old state: {event['old_state']}")
    print(f"Old hash: {event['old_hash']}")
    print(f"New state: {event['new_state']}")
    print(f"New hash: {event['new_hash']}")
    print(f"Timestamp: {event['timestamp']}")


def search_audit_history(database_path: str) -> None:
    """
    Search historical integrity events by filename or partial path.

    Args:
        database_path (str): Selected database path.
    """

    search_term = input(
        "Enter filename or file path to search: "
    ).strip()

    results = search_audit_records(
        database_path,
        search_term,
        verbose=True
    )

    if not results:
        print("No matching audit events found.")
        return

    for event in results:
        print_event_record(event)


def deactivate_directory(registry_key: str) -> None:
    """
    Deactivate a monitored directory without deleting its database.

    Args:
        registry_key (str): Registry key of the directory to deactivate.
    """

    registry = load_registry()

    registry[registry_key]["active"] = False

    save_registry(registry)

    print("Directory deactivated.")
    print("Its database and audit history have been preserved.")
    print("You can reactivate it by adding the same directory again.")



def search_files_by_state(database_path: str) -> None:
    """
    Search baseline records by their integrity state.

    Args:
        database_path (str): Selected database path.
    """

    print("\nAvailable integrity states:")
    print("1. OK")
    print("2. PERMISSION_DENIED")
    print("3. FILE_NOT_FOUND")

    state_options = {
        "1": "OK",
        "2": "PERMISSION_DENIED",
        "3": "FILE_NOT_FOUND"
    }

    choice = input("\nSelect an integrity state: ").strip()

    if choice not in state_options:
        print("Invalid selection.")
        return

    file_state = state_options[choice]

    results = search_baseline_by_state(
        database_path,
        file_state,
        verbose=True
    )

    if not results:
        print("No matching files found.")
        return

    for record in results:
        print(f"\nFile: {record['file_path']}")
        print(f"State: {record['file_state']}")
        print(f"Hash: {record['file_hash']}")
        print(f"Size: {record['file_size']}")
        print(f"Modified: {record['modified_time']}")


def directory_menu(registry_key: str) -> None:
    """
    Display operations for an individually selected directory.

    Args:
        registry_key (str): Registry key of the selected directory.
    """

    registry = load_registry()
    information = registry[registry_key]

    directory_path = information["directory_path"]
    database_path = information["database_path"]

    while True:
        print("\n========== SELECTED DIRECTORY ==========")
        print(directory_path)

        print("\n1. Run integrity scan")
        print("2. View baseline records")
        print("3. Search baseline by filename or path")
        print("4. Search baseline by integrity state")
        print("5. View audit history")
        print("6. Search audit history by file path")
        print("7. Deactivate directory")
        print("8. Return to main menu")

        choice = input("\nSelect an option: ").strip()

        match choice:
            case "1":
                run_scan(registry_key)

            case "2":
                view_baseline(database_path)

            case "3":
                search_files(database_path)

            case "4":
                search_files_by_state(database_path)

            case "5":
                view_audit_history(database_path)

            case "6":
                search_audit_history(database_path)

            case "7":
                deactivate_directory(registry_key)
                break

            case "8":
                break

            case _:
                print("Invalid option.")


def main() -> None:
    """
    Display the main menu and manage monitored directories.
    """

    while True:
        print("\n========== FILE INTEGRITY MONITOR ==========")
        print("1. Add directory")
        print("2. Select monitored directory")
        print("3. List monitored directories")
        print("4. Exit")

        choice = input("\nSelect an option: ").strip()

        try:
            match choice:
                case "1":
                    add_directory()

                case "2":
                    registry_key = select_directory()

                    if registry_key is not None:
                        directory_menu(registry_key)

                case "3":
                    list_directories()

                case "4":
                    print("Exiting File Integrity Monitor.")
                    break

                case _:
                    print("Invalid option.")

        except (OSError, RuntimeError, sqlite3.Error) as error:
            print(f"Operation failed: {error}")


if __name__ == "__main__":
    main()