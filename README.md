# Automated File Integrity Monitor

A command-line File Integrity Monitoring (FIM) tool written in Python.
It watches directories for changes by comparing SHA-256 file hashes against
a stored baseline, and records every detected change in an audit history.

The initial release focuses on reliable manual scanning and persistent
change auditing. The architecture is designed for extension: continuous
filesystem monitoring (`monitor.py`) and additional notification channels
are planned follow-up phases (see Roadmap).

## Features

- Register multiple directories for monitoring (each gets its own database)
- Recursive directory scanning with SHA-256 hashing (chunked, memory-safe)
- Detection of new, modified, deleted, reappeared, and inaccessible files
- Persistent baseline and full audit history in SQLite
- Search baseline and audit history by filename, path, or integrity state
- Safe handling of unreadable files, vanished files, and incomplete scans
- Interactive console menu — no configuration files or arguments needed

## Requirements

- Python 3.10 or newer (developed against Python 3.13)
- No third-party dependencies (standard library only)

## How It Works

1. **Add a directory** — the directory is registered and an initial scan
   establishes the baseline (file states + SHA-256 hashes) in a SQLite
   database dedicated to that directory.
2. **Run integrity scans** — each scan re-reads the directory and compares
   current file states and hashes against the baseline. Differences are
   reported as events and written to the audit log.
3. **Review** — inspect baseline records, search by name/path/state, and
   browse or search the full audit history at any time.

## Project Structure

| Module         | Responsibility                                              |
|----------------|-------------------------------------------------------------|
| `main.py`      | Entry point, menus, directory registry, scan coordination   |
| `scanner.py`   | Recursive directory traversal, metadata, hash calculation   |
| `hasher.py`    | SHA-256 file hashing with error statuses                    |
| `detector.py`  | Baseline-vs-scan comparison, event classification           |
| `database.py`  | SQLite storage: baseline, audit log, searches               |
| `alerts.py`    | Console presentation of events and scan summaries           |
| `monitor.py`   | Continuous filesystem monitoring (planned — not yet implemented) |

## Integrity States

| State               | Meaning                                   |
|---------------------|-------------------------------------------|
| `OK`                | File readable, hash calculated            |
| `PERMISSION_DENIED` | File exists but cannot be read            |
| `FILE_NOT_FOUND`    | File no longer present                    |
| `READ_ERROR`        | File could not be read for another reason |

## Event Types

| Event                | Triggered when                                   |
|----------------------|--------------------------------------------------|
| `NEW_FILE`           | File appears that was not in the baseline        |
| `FILE_MODIFIED`      | File content changed (hash mismatch)             |
| `FILE_NOT_FOUND`     | Baseline file is missing from a complete scan    |
| `FILE_REAPPEARED`    | Previously missing file is readable again        |
| `ACCESS_LOST`        | Readable file becomes unreadable                 |
| `ACCESS_RESTORED`    | Unreadable file becomes readable again           |
| `FILE_STATE_CHANGED` | Any other state transition                       |

Notes:
- Missing files are only reported after a **complete** directory traversal;
  an incomplete scan never produces false deletion events.
- A file that reappears or regains readability is additionally reported as
  `FILE_MODIFIED` if its content differs from the last known good hash.
- When a file becomes unreadable, its last successful hash and metadata are
  preserved in the baseline rather than overwritten.

## Usage

```bash
python main.py
```

```
========== FILE INTEGRITY MONITOR ==========
1. Add directory
2. Select monitored directory
3. List monitored directories
4. Exit
```

Selecting a directory opens its menu:

```
1. Run integrity scan
2. View baseline records
3. Search baseline by filename or path
4. Search baseline by integrity state
5. View audit history
6. Search audit history by file path
7. Deactivate directory
8. Return to main menu
```

Deactivating a directory preserves its database and audit history; adding
the same directory again reactivates it.

## Runtime Files

| Path                        | Purpose                                        |
|-----------------------------|------------------------------------------------|
| `monitored_directories.json`| Registry of monitored directories              |
| `databases/<name>_<hash>.db`| One SQLite database per monitored directory    |

## Database Schema

**baseline** — latest observed state of every file:

```sql
file_path TEXT PRIMARY KEY,
file_state TEXT NOT NULL,
file_hash TEXT,
file_size INTEGER,
modified_time REAL,
last_scanned TEXT NOT NULL
```

**audit_log** — historical integrity events (newest first on retrieval):

```sql
event_id INTEGER PRIMARY KEY AUTOINCREMENT,
file_path TEXT NOT NULL,
event_type TEXT NOT NULL,
old_state TEXT, old_hash TEXT,
new_state TEXT, new_hash TEXT,
timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
```

## Roadmap

Potentially planned extensions, in the intended implementation order:

- **Continuous monitoring (`monitor.py`)** — real-time filesystem event
  watching (using `watchdog`) that triggers targeted verification, with
  periodic full reconciliation scans as the integrity authority. Filesystem
  events act as triggers only; hash verification remains the definitive
  evidence of content changes.
- **Extended notifications (`alerts.py`)** — the console notification
  interface is designed so additional delivery channels can be added later,
  such as Discord (webhook or bot), email, or phone/push notifications.
  The specific channels are not yet decided.
- Other planned directions: Linux compatibility and daemon/service
  deployment, tamper-evident (hash-chained) audit logging, and more detailed
  permission/ACL monitoring.

## Limitations

- The tool detects and records changes; it does not determine whether a
  change was authorized, and it does not repair or restore files.
- The local SQLite database is not tamper-proof; a sufficiently privileged
  process can modify or delete it.
- Permission/ACL changes are only detected when they cause a read failure,
  not by inspecting permission bits.
- The initial baseline is trusted as-is; establish it from a directory you
  consider trustworthy.

## AI Usage Disclosure

This project was developed by a human author. AI tools were used in a
supporting role for:

- **Documentation** — drafting and structuring the README, standardizing in-code documentation, and project
  documentation.
- **Testing** — authoring a test suite to verify functionality

All architecture, application logic, and design decisions — including the
module structure, database schema, and detection rules — are the author's
own work
