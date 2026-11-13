"""
Module: database.py

Description:
    Provides functionality for managing the FIM SQLite database.

Responsibilities:
    - Initialize database tables.
    - Store and retrieve the latest observed file states.
    - Search baseline records.
    - Record and retrieve historical audit events.
    - Process scan results and update the baseline.

Dependencies:
    - sqlite3

Author: Julian Nicos Reyes
Version: 1.0.0
"""

import sqlite3


def escape_like(search_term: str) -> str:
    """
    Escape SQL LIKE wildcards so they are matched as literal characters.

    Args:
        search_term (str): Text supplied by the user.

    Returns:
        str: Search text safe for use with ESCAPE '\\'.
    """

    return (
        search_term
        .replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )


def initialize_database(database_path: str) -> None:
    """
    Initialize the FIM database and create its required tables.

    Args:
        database_path (str): Path to the SQLite database file.
    """

    connection = sqlite3.connect(database_path)

    try:
        with connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS baseline (
                    file_path TEXT PRIMARY KEY,
                    file_state TEXT NOT NULL,
                    file_hash TEXT,
                    file_size INTEGER,
                    modified_time REAL,
                    last_scanned TEXT NOT NULL
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    old_state TEXT,
                    old_hash TEXT,
                    new_state TEXT,
                    new_hash TEXT,
                    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)

    finally:
        connection.close()


def get_baseline(database_path: str) -> dict:
    """
    Retrieve all previously observed file states.

    Args:
        database_path (str): Path to the SQLite database.

    Returns:
        dict: Mapping of file paths to their stored state and metadata.
    """

    connection = sqlite3.connect(database_path)

    try:
        cursor = connection.execute("""
            SELECT
                file_path,
                file_state,
                file_hash,
                file_size,
                modified_time,
                last_scanned
            FROM baseline
        """)

        rows = cursor.fetchall()
        baseline = {}

        for row in rows:
            (
                file_path,
                file_state,
                file_hash,
                file_size,
                modified_time,
                last_scanned
            ) = row

            baseline[file_path] = {
                "file_state": file_state,
                "file_hash": file_hash,
                "file_size": file_size,
                "modified_time": modified_time,
                "last_scanned": last_scanned
            }

        return baseline

    finally:
        connection.close()


def search_baseline(
    database_path: str,
    search_term: str,
    verbose: bool = False
) -> list[dict]:
    """
    Search baseline records using a partial file path or filename.

    Args:
        database_path (str): Path to the SQLite database.
        search_term (str): Text to search for in file paths.
        verbose (bool): Include file hashes when True.

    Returns:
        list[dict]: Matching baseline records.
    """

    connection = sqlite3.connect(database_path)

    try:
        if verbose:
            cursor = connection.execute("""
                SELECT
                    file_path,
                    file_state,
                    file_hash,
                    file_size,
                    modified_time,
                    last_scanned
                FROM baseline
                WHERE file_path LIKE ? ESCAPE '\\'
                ORDER BY file_path
            """, (f"%{escape_like(search_term)}%",))

        else:
            cursor = connection.execute("""
                SELECT
                    file_path,
                    file_state,
                    file_size,
                    modified_time,
                    last_scanned
                FROM baseline
                WHERE file_path LIKE ? ESCAPE '\\'
                ORDER BY file_path
            """, (f"%{escape_like(search_term)}%",))

        rows = cursor.fetchall()
        results = []

        for row in rows:
            if verbose:
                (
                    file_path,
                    file_state,
                    file_hash,
                    file_size,
                    modified_time,
                    last_scanned
                ) = row

                results.append({
                    "file_path": file_path,
                    "file_state": file_state,
                    "file_hash": file_hash,
                    "file_size": file_size,
                    "modified_time": modified_time,
                    "last_scanned": last_scanned
                })

            else:
                (
                    file_path,
                    file_state,
                    file_size,
                    modified_time,
                    last_scanned
                ) = row

                results.append({
                    "file_path": file_path,
                    "file_state": file_state,
                    "file_size": file_size,
                    "modified_time": modified_time,
                    "last_scanned": last_scanned
                })

        return results

    finally:
        connection.close()


def update_baseline(
    database_path: str,
    file_path: str,
    file_state: str,
    file_hash: str | None,
    file_size: int | None,
    modified_time: float | None
) -> None:
    """
    Insert or update a file's latest observed state.

    Args:
        database_path (str): Path to the SQLite database.
        file_path (str): File path relative to the monitored directory.
        file_state (str): File visibility status.
        file_hash (str | None): Last successfully calculated file hash.
        file_size (int | None): File size in bytes.
        modified_time (float | None): Last modification timestamp.
    """

    connection = sqlite3.connect(database_path)

    try:
        with connection:
            connection.execute("""
                INSERT INTO baseline (
                    file_path,
                    file_state,
                    file_hash,
                    file_size,
                    modified_time,
                    last_scanned
                )
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)

                ON CONFLICT(file_path) DO UPDATE SET
                    file_state = excluded.file_state,
                    file_hash = excluded.file_hash,
                    file_size = excluded.file_size,
                    modified_time = excluded.modified_time,
                    last_scanned = CURRENT_TIMESTAMP
            """, (
                file_path,
                file_state,
                file_hash,
                file_size,
                modified_time
            ))

    finally:
        connection.close()


def record_event(
    database_path: str,
    file_path: str,
    event_type: str,
    old_state: str | None,
    old_hash: str | None,
    new_state: str | None,
    new_hash: str | None
) -> None:
    """
    Record a detected file integrity event.

    Args:
        database_path (str): Path to the SQLite database.
        file_path (str): Path of the affected file.
        event_type (str): Type of detected event.
        old_state (str | None): Previously observed file state.
        old_hash (str | None): Previously known file hash.
        new_state (str | None): Newly observed file state.
        new_hash (str | None): Newly calculated file hash.
    """

    connection = sqlite3.connect(database_path)

    try:
        with connection:
            connection.execute("""
                INSERT INTO audit_log (
                    file_path,
                    event_type,
                    old_state,
                    old_hash,
                    new_state,
                    new_hash
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                file_path,
                event_type,
                old_state,
                old_hash,
                new_state,
                new_hash
            ))

    finally:
        connection.close()


def get_audit_history(
    database_path: str,
    verbose: bool = False
) -> list[dict]:
    """
    Retrieve all historical integrity events.

    Args:
        database_path (str): Path to the SQLite database.
        verbose (bool): Include old and new hashes when True.

    Returns:
        list[dict]: Historical events ordered newest first.
    """

    connection = sqlite3.connect(database_path)

    try:
        if verbose:
            selected_columns = """
                event_id,
                file_path,
                event_type,
                old_state,
                old_hash,
                new_state,
                new_hash,
                timestamp
            """
        else:
            selected_columns = """
                event_id,
                file_path,
                event_type,
                old_state,
                new_state,
                timestamp
            """

        cursor = connection.execute(f"""
            SELECT {selected_columns}
            FROM audit_log
            ORDER BY event_id DESC
        """)

        return build_event_list(cursor.fetchall(), verbose)

    finally:
        connection.close()


def search_audit_history(
    database_path: str,
    search_term: str,
    verbose: bool = False
) -> list[dict]:
    """
    Search historical integrity events using a partial file path.

    Args:
        database_path (str): Path to the SQLite database.
        search_term (str): Text to search for in file paths.
        verbose (bool): Include old and new hashes when True.

    Returns:
        list[dict]: Matching events ordered newest first.
    """

    connection = sqlite3.connect(database_path)

    try:
        if verbose:
            selected_columns = """
                event_id,
                file_path,
                event_type,
                old_state,
                old_hash,
                new_state,
                new_hash,
                timestamp
            """
        else:
            selected_columns = """
                event_id,
                file_path,
                event_type,
                old_state,
                new_state,
                timestamp
            """

        cursor = connection.execute(f"""
            SELECT {selected_columns}
            FROM audit_log
            WHERE file_path LIKE ? ESCAPE '\\'
            ORDER BY event_id DESC
        """, (f"%{escape_like(search_term)}%",))

        return build_event_list(cursor.fetchall(), verbose)

    finally:
        connection.close()


def build_event_list(rows: list[tuple], verbose: bool) -> list[dict]:
    """
    Convert audit_log rows into event dictionaries.

    Args:
        rows (list[tuple]): Rows selected from the audit_log table.
        verbose (bool): Rows include old and new hashes when True.

    Returns:
        list[dict]: Event dictionaries in the same order as the rows.
    """

    history = []

    for row in rows:
        if verbose:
            (
                event_id,
                path,
                event_type,
                old_state,
                old_hash,
                new_state,
                new_hash,
                timestamp
            ) = row

            history.append({
                "event_id": event_id,
                "file_path": path,
                "event_type": event_type,
                "old_state": old_state,
                "old_hash": old_hash,
                "new_state": new_state,
                "new_hash": new_hash,
                "timestamp": timestamp
            })

        else:
            (
                event_id,
                path,
                event_type,
                old_state,
                new_state,
                timestamp
            ) = row

            history.append({
                "event_id": event_id,
                "file_path": path,
                "event_type": event_type,
                "old_state": old_state,
                "new_state": new_state,
                "timestamp": timestamp
            })

    return history


def process_scan(
    database_path: str,
    current_scan: dict,
    events: list[dict]
) -> None:
    """
    Record detected events and update the latest file baseline.

    Args:
        database_path (str): Path to the FIM database.
        current_scan (dict): File records from the latest directory scan.
        events (list[dict]): Events detected by detector.py.
    """

    connection = sqlite3.connect(database_path)

    try:
        with connection:

            # Record all detected events.
            for event in events:
                connection.execute("""
                    INSERT INTO audit_log (
                        file_path,
                        event_type,
                        old_state,
                        old_hash,
                        new_state,
                        new_hash
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    event["file_path"],
                    event["event_type"],
                    event["old_state"],
                    event["old_hash"],
                    event["new_state"],
                    event["new_hash"]
                ))

            # Update records for files discovered in this scan.
            for file_path, record in current_scan.items():

                file_state = record["file_state"]
                file_hash = record["file_hash"]
                file_size = record["file_size"]
                modified_time = record["modified_time"]

                # Preserve the last successful values when access is lost.
                if file_state != "OK":
                    previous_record = connection.execute("""
                        SELECT file_hash, file_size, modified_time
                        FROM baseline
                        WHERE file_path = ?
                    """, (file_path,)).fetchone()

                    if previous_record is not None:
                        file_hash = previous_record[0]
                        file_size = previous_record[1]
                        modified_time = previous_record[2]

                connection.execute("""
                    INSERT INTO baseline (
                        file_path,
                        file_state,
                        file_hash,
                        file_size,
                        modified_time,
                        last_scanned
                    )
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)

                    ON CONFLICT(file_path) DO UPDATE SET
                        file_state = excluded.file_state,
                        file_hash = excluded.file_hash,
                        file_size = excluded.file_size,
                        modified_time = excluded.modified_time,
                        last_scanned = CURRENT_TIMESTAMP
                """, (
                    file_path,
                    file_state,
                    file_hash,
                    file_size,
                    modified_time
                ))

            # Update records for previously known files now absent from the scan.
            for event in events:
                if (
                    event["event_type"] == "FILE_NOT_FOUND"
                    and event["file_path"] not in current_scan
                ):
                    connection.execute("""
                        UPDATE baseline
                        SET file_state = 'FILE_NOT_FOUND',
                            last_scanned = CURRENT_TIMESTAMP
                        WHERE file_path = ?
                    """, (event["file_path"],))

    finally:
        connection.close()



def search_baseline_by_state(
    database_path: str,
    file_state: str,
    verbose: bool = False
) -> list[dict]:
    """
    Search baseline records by file integrity state.

    Args:
        database_path (str): Path to the SQLite database.
        file_state (str): Integrity state to search for.
        verbose (bool): Include file hashes when True.

    Returns:
        list[dict]: Matching baseline records.
    """

    connection = sqlite3.connect(database_path)

    try:
        if verbose:
            cursor = connection.execute("""
                SELECT
                    file_path,
                    file_state,
                    file_hash,
                    file_size,
                    modified_time,
                    last_scanned
                FROM baseline
                WHERE file_state = ?
                ORDER BY file_path
            """, (file_state,))

        else:
            cursor = connection.execute("""
                SELECT
                    file_path,
                    file_state,
                    file_size,
                    modified_time,
                    last_scanned
                FROM baseline
                WHERE file_state = ?
                ORDER BY file_path
            """, (file_state,))

        rows = cursor.fetchall()
        results = []

        if verbose:
            for row in rows:
                (
                    file_path,
                    state,
                    file_hash,
                    file_size,
                    modified_time,
                    last_scanned
                ) = row

                results.append({
                    "file_path": file_path,
                    "file_state": state,
                    "file_hash": file_hash,
                    "file_size": file_size,
                    "modified_time": modified_time,
                    "last_scanned": last_scanned
                })

        else:
            for row in rows:
                (
                    file_path,
                    state,
                    file_size,
                    modified_time,
                    last_scanned
                ) = row

                results.append({
                    "file_path": file_path,
                    "file_state": state,
                    "file_size": file_size,
                    "modified_time": modified_time,
                    "last_scanned": last_scanned
                })

        return results

    finally:
        connection.close()