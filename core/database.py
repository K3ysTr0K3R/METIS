import os
import sqlite3
import threading
import time
from datetime import datetime

DEFAULT_WORKSPACE = "default"
DEFAULT_DB_PATH = os.path.expanduser("~/.metis/metis.db")

_ALLOWED_HOST_FIELDS = {"name", "os", "info", "state"}

def _now():
    return int(time.time())


def _fmt_time(ts):
    if not ts:
        return "."
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
    except (ValueError, OSError):
        return str(ts)


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS workspaces (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    address      TEXT NOT NULL,
    name         TEXT DEFAULT '',
    os           TEXT DEFAULT '',
    info         TEXT DEFAULT '',
    state        TEXT DEFAULT 'unknown',
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    UNIQUE(workspace_id, address),
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS services (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id    INTEGER NOT NULL,
    port       INTEGER NOT NULL,
    proto      TEXT DEFAULT 'tcp',
    name       TEXT DEFAULT '',
    state      TEXT DEFAULT 'open',
    banner     TEXT DEFAULT '',
    info       TEXT DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(host_id, port, proto),
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vulns (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    host_id      INTEGER,
    name         TEXT NOT NULL,
    module       TEXT DEFAULT '',
    severity     TEXT DEFAULT 'unknown',
    refs         TEXT DEFAULT '',
    info         TEXT DEFAULT '',
    created_at   INTEGER NOT NULL,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS creds (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    host_id      INTEGER,
    username     TEXT DEFAULT '',
    secret       TEXT DEFAULT '',
    kind         TEXT DEFAULT 'password',
    info         TEXT DEFAULT '',
    created_at   INTEGER NOT NULL,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    host_id      INTEGER,
    kind         TEXT DEFAULT 'note',
    data         TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS loots (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    host_id      INTEGER,
    path         TEXT DEFAULT '',
    kind         TEXT DEFAULT '',
    data         BLOB,
    info         TEXT DEFAULT '',
    created_at   INTEGER NOT NULL,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS db_sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    sid          TEXT NOT NULL,
    host_id      INTEGER,
    kind         TEXT DEFAULT 'shell',
    info         TEXT DEFAULT '',
    opened_at    INTEGER NOT NULL,
    closed_at    INTEGER,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    host_id      INTEGER,
    kind         TEXT DEFAULT 'info',
    message      TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_hosts_ws    ON hosts(workspace_id);
CREATE INDEX IF NOT EXISTS idx_vulns_ws    ON vulns(workspace_id);
CREATE INDEX IF NOT EXISTS idx_events_ws   ON events(workspace_id);
CREATE INDEX IF NOT EXISTS idx_services_h  ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_vulns_dedup ON vulns(workspace_id, host_id, module, name);
"""


class Database:
    def __init__(self, path=None):
        self.path = path or DEFAULT_DB_PATH
        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, exist_ok=True)

        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._init_schema()

        self._active_name = None
        self._active_id = None

        stored = self._get_meta("active_workspace")
        if stored:
            row = self._conn.execute(
                "SELECT id FROM workspaces WHERE name=?", (stored,)
            ).fetchone()
            if row:
                self._active_name = stored
                self._active_id = row["id"]

    def _init_schema(self):
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def _get_meta(self, key):
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key=?", (key,)
            ).fetchone()
            return row["value"] if row else None

    def _set_meta(self, key, value):
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            self._conn.commit()

    def _ensure_workspace(self, name):
        now = _now()
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM workspaces WHERE name=?", (name,)
            ).fetchone()
            if row:
                return row["id"]
            cur = self._conn.execute(
                "INSERT INTO workspaces (name, created_at, updated_at) "
                "VALUES (?, ?, ?)",
                (name, now, now),
            )
            self._conn.commit()
            return cur.lastrowid

    def _row_to_dict(self, row):
        return dict(row) if row else None

    def _filter_host_fields(self, fields):
        return {k: v for k, v in fields.items() if k in _ALLOWED_HOST_FIELDS}

    def _require_workspace(self):
        if self._active_id is None:
            raise RuntimeError("no active workspace - run 'workspace <name>' first")

    def current_workspace(self):
        return self._active_name

    def current_workspace_id(self):
        return self._active_id

    def list_workspaces(self):
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, name, description, created_at, updated_at "
                "FROM workspaces ORDER BY name"
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def set_workspace(self, name):
        if not name:
            self._active_name = None
            self._active_id = None
            self._set_meta("active_workspace", "")
            return True
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM workspaces WHERE name=?", (name,)
            ).fetchone()
            if not row:
                return False
            self._active_name = name
            self._active_id = row["id"]
            self._set_meta("active_workspace", name)
        return True

    def create_workspace(self, name, description=""):
        if not name:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM workspaces WHERE name=?", (name,)
            ).fetchone()
            if row:
                return row["id"]
            now = _now()
            cur = self._conn.execute(
                "INSERT INTO workspaces (name, description, created_at, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (name, description, now, now),
            )
            self._conn.commit()
            return cur.lastrowid

    def delete_workspace(self, name):
        if name == DEFAULT_WORKSPACE:
            raise ValueError("cannot delete the default workspace")
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM workspaces WHERE name=?", (name,)
            ).fetchone()
            if not row:
                return False
            if self._active_name == name:
                self._active_name = None
                self._active_id = None
                self._set_meta("active_workspace", "")
            self._conn.execute(
                "DELETE FROM workspaces WHERE id=?", (row["id"],)
            )
            self._conn.commit()
            return True

    def reset_workspace(self, name):
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM workspaces WHERE name=?", (name,)
            ).fetchone()
            if not row:
                return False
            wsid = row["id"]
            self._conn.execute(
                "DELETE FROM services WHERE host_id IN "
                "(SELECT id FROM hosts WHERE workspace_id=?)",
                (wsid,),
            )
            for table in ("events", "db_sessions", "loots", "notes",
                          "creds", "vulns", "hosts"):
                self._conn.execute(
                    f"DELETE FROM {table} WHERE workspace_id=?", (wsid,)
                )
            self._conn.commit()
            return True

    def ensure_host(self, address, **fields):
        self._require_workspace()
        fields = self._filter_host_fields(fields)
        now = _now()
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM hosts WHERE workspace_id=? AND address=?",
                (self._active_id, address),
            ).fetchone()
            if row:
                if fields:
                    sets = ", ".join(f"{k}=?" for k in fields)
                    vals = list(fields.values()) + [now, row["id"]]
                    self._conn.execute(
                        f"UPDATE hosts SET {sets}, updated_at=? WHERE id=?",
                        vals,
                    )
                    self._conn.commit()
                return row["id"]
            cur = self._conn.execute(
                "INSERT INTO hosts "
                "(workspace_id, address, created_at, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (self._active_id, address, now, now),
            )
            host_id = cur.lastrowid
            if fields:
                sets = ", ".join(f"{k}=?" for k in fields)
                vals = list(fields.values()) + [host_id]
                self._conn.execute(
                    f"UPDATE hosts SET {sets} WHERE id=?", vals
                )
            self._conn.commit()
            return host_id

    def get_host(self, address):
        if self._active_id is None:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM hosts WHERE workspace_id=? AND address=?",
                (self._active_id, address),
            ).fetchone()
        return self._row_to_dict(row)

    def list_hosts(self):
        if self._active_id is None:
            return []
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM hosts WHERE workspace_id=? ORDER BY address",
                (self._active_id,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def delete_host(self, address):
        if self._active_id is None:
            return False
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM hosts WHERE workspace_id=? AND address=?",
                (self._active_id, address),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def add_service(self, host_address, port, proto="tcp", name="",
                    state="open", banner="", info=""):
        self._require_workspace()
        host_id = self.ensure_host(host_address)
        now = _now()
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM services WHERE host_id=? AND port=? AND proto=?",
                (host_id, port, proto),
            ).fetchone()
            if row:
                self._conn.execute(
                    "UPDATE services SET name=?, state=?, banner=?, info=?, "
                    "updated_at=? WHERE id=?",
                    (name, state, banner, info, now, row["id"]),
                )
                self._conn.commit()
                return row["id"]
            cur = self._conn.execute(
                "INSERT INTO services "
                "(host_id, port, proto, name, state, banner, info, "
                " created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (host_id, port, proto, name, state, banner, info, now, now),
            )
            self._conn.commit()
            return cur.lastrowid

    def list_services(self, host_address=None):
        if self._active_id is None:
            return []
        with self._lock:
            if host_address:
                rows = self._conn.execute(
                    "SELECT s.*, h.address AS address FROM services s "
                    "JOIN hosts h ON s.host_id = h.id "
                    "WHERE h.workspace_id=? AND h.address=? "
                    "ORDER BY h.address, s.port",
                    (self._active_id, host_address),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT s.*, h.address AS address FROM services s "
                    "JOIN hosts h ON s.host_id = h.id "
                    "WHERE h.workspace_id=? "
                    "ORDER BY h.address, s.port",
                    (self._active_id,),
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def delete_service(self, service_id):
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM services WHERE id=?", (service_id,)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def add_vuln(self, name, module="", host_address=None,
                 severity="unknown", refs="", info=""):
        self._require_workspace()
        host_id = None
        if host_address:
            host_id = self.ensure_host(host_address)
        now = _now()
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM vulns WHERE workspace_id=? AND "
                "((host_id IS NULL AND ? IS NULL) OR host_id=?) AND "
                "module=? AND name=?",
                (self._active_id, host_id, host_id, module, name),
            ).fetchone()
            if row:
                return row["id"]
            cur = self._conn.execute(
                "INSERT INTO vulns "
                "(workspace_id, host_id, name, module, severity, refs, info, "
                " created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (self._active_id, host_id, name, module, severity,
                 refs, info, now),
            )
            self._conn.commit()
            return cur.lastrowid

    def list_vulns(self, host_address=None):
        if self._active_id is None:
            return []
        with self._lock:
            if host_address:
                rows = self._conn.execute(
                    "SELECT v.*, h.address AS address FROM vulns v "
                    "LEFT JOIN hosts h ON v.host_id = h.id "
                    "WHERE v.workspace_id=? AND h.address=? "
                    "ORDER BY v.created_at DESC",
                    (self._active_id, host_address),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT v.*, h.address AS address FROM vulns v "
                    "LEFT JOIN hosts h ON v.host_id = h.id "
                    "WHERE v.workspace_id=? "
                    "ORDER BY v.created_at DESC",
                    (self._active_id,),
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def delete_vuln(self, vuln_id):
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM vulns WHERE id=?", (vuln_id,)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def add_cred(self, host_address, username, secret,
                 kind="password", info=""):
        self._require_workspace()
        host_id = None
        if host_address:
            host_id = self.ensure_host(host_address)
        now = _now()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO creds "
                "(workspace_id, host_id, username, secret, kind, info, "
                " created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (self._active_id, host_id, username, secret,
                 kind, info, now),
            )
            self._conn.commit()
            return cur.lastrowid

    def list_creds(self):
        if self._active_id is None:
            return []
        with self._lock:
            rows = self._conn.execute(
                "SELECT c.*, h.address AS address FROM creds c "
                "LEFT JOIN hosts h ON c.host_id = h.id "
                "WHERE c.workspace_id=? ORDER BY c.created_at DESC",
                (self._active_id,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def delete_cred(self, cred_id):
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM creds WHERE id=?", (cred_id,)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def add_note(self, data, host_address=None, kind="note"):
        self._require_workspace()
        host_id = None
        if host_address:
            host_id = self.ensure_host(host_address)
        now = _now()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO notes "
                "(workspace_id, host_id, kind, data, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (self._active_id, host_id, kind, data, now),
            )
            self._conn.commit()
            return cur.lastrowid

    def list_notes(self):
        if self._active_id is None:
            return []
        with self._lock:
            rows = self._conn.execute(
                "SELECT n.*, h.address AS address FROM notes n "
                "LEFT JOIN hosts h ON n.host_id = h.id "
                "WHERE n.workspace_id=? ORDER BY n.created_at DESC",
                (self._active_id,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def delete_note(self, note_id):
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM notes WHERE id=?", (note_id,)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def add_loot(self, data, path="", kind="", info="", host_address=None):
        self._require_workspace()
        host_id = None
        if host_address:
            host_id = self.ensure_host(host_address)
        if isinstance(data, str):
            data = data.encode()
        now = _now()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO loots "
                "(workspace_id, host_id, path, kind, data, info, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (self._active_id, host_id, path, kind, data, info, now),
            )
            self._conn.commit()
            return cur.lastrowid

    def list_loot(self):
        if self._active_id is None:
            return []
        with self._lock:
            rows = self._conn.execute(
                "SELECT l.id, l.workspace_id, l.host_id, l.path, l.kind, "
                "       l.info, l.created_at, length(l.data) AS size, "
                "       h.address AS address "
                "FROM loots l LEFT JOIN hosts h ON l.host_id = h.id "
                "WHERE l.workspace_id=? ORDER BY l.created_at DESC",
                (self._active_id,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def delete_loot(self, loot_id):
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM loots WHERE id=?", (loot_id,)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def add_session_record(self, sid, address=None, kind="shell", info=""):
        self._require_workspace()
        host_id = None
        if address:
            host_id = self.ensure_host(address, state="up")
        now = _now()
        with self._lock:
            self._conn.execute(
                "INSERT INTO db_sessions "
                "(workspace_id, sid, host_id, kind, info, opened_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (self._active_id, sid, host_id, kind, info, now),
            )
            self._conn.commit()

    def close_session_record(self, sid):
        now = _now()
        with self._lock:
            self._conn.execute(
                "UPDATE db_sessions SET closed_at=? "
                "WHERE sid=? AND closed_at IS NULL",
                (now, sid),
            )
            self._conn.commit()

    def list_sessions(self):
        if self._active_id is None:
            return []
        with self._lock:
            rows = self._conn.execute(
                "SELECT s.*, h.address AS address FROM db_sessions s "
                "LEFT JOIN hosts h ON s.host_id = h.id "
                "WHERE s.workspace_id=? ORDER BY s.opened_at DESC",
                (self._active_id,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def log_event(self, message, host_address=None, kind="info"):
        self._require_workspace()
        host_id = None
        if host_address:
            host_id = self.ensure_host(host_address)
        now = _now()
        with self._lock:
            self._conn.execute(
                "INSERT INTO events "
                "(workspace_id, host_id, kind, message, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (self._active_id, host_id, kind, message, now),
            )
            self._conn.commit()

    def list_events(self, limit=100):
        if self._active_id is None:
            return []
        with self._lock:
            rows = self._conn.execute(
                "SELECT e.*, h.address AS address FROM events e "
                "LEFT JOIN hosts h ON e.host_id = h.id "
                "WHERE e.workspace_id=? "
                "ORDER BY e.created_at DESC LIMIT ?",
                (self._active_id, limit),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def stats(self):
        if self._active_id is None:
            return {"hosts": 0, "services": 0, "vulns": 0, "creds": 0,
                    "notes": 0, "loot": 0, "sessions": 0, "events": 0}
        with self._lock:
            out = {}
            for name, sql in (
                ("hosts",    "SELECT COUNT(*) FROM hosts WHERE workspace_id=?"),
                ("services", "SELECT COUNT(*) FROM services s JOIN hosts h ON s.host_id=h.id WHERE h.workspace_id=?"),
                ("vulns",    "SELECT COUNT(*) FROM vulns WHERE workspace_id=?"),
                ("creds",    "SELECT COUNT(*) FROM creds WHERE workspace_id=?"),
                ("notes",    "SELECT COUNT(*) FROM notes WHERE workspace_id=?"),
                ("loot",     "SELECT COUNT(*) FROM loots WHERE workspace_id=?"),
                ("sessions", "SELECT COUNT(*) FROM db_sessions WHERE workspace_id=?"),
                ("events",   "SELECT COUNT(*) FROM events WHERE workspace_id=?"),
            ):
                out[name] = self._conn.execute(sql, (self._active_id,)).fetchone()[0]
        return out

    def size_bytes(self):
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0
