"""Export everything to one zip you store elsewhere, and import it back. Captures are not included."""
import json
import os
import shutil
import sqlite3
import tempfile
import zipfile
from pathlib import Path

from . import VERSION, db, util

MAX_DB = 2 * 1024 ** 3


def export(dest=None):
    dest = Path(dest or (util.DATA / "exports"))
    dest.mkdir(parents=True, exist_ok=True)
    stamp = util.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out = dest / f"noxy-export-{stamp}.zip"
    with tempfile.TemporaryDirectory() as td:
        snap = Path(td) / "noxy.db"
        src = db.connect()
        dst = sqlite3.connect(snap)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        con = sqlite3.connect(snap)
        n = con.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        con.close()
        manifest = {"app": "noxy", "version": VERSION, "created": util.iso(util.now_ts()), "sessions": n,
                    "db_sha256": util.sha256_file(snap), "note": "Text evidence only; captures stay in the VM."}
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("manifest.json", json.dumps(manifest, indent=2))
            z.write(snap, "noxy.db")
    digest = util.sha256_file(out)
    Path(str(out) + ".sha256").write_text(f"{digest}  {out.name}\n")
    os.chmod(out, 0o600)
    return {"path": str(out), "name": out.name, "sha256": digest, "sessions": n}


def validate(zpath):
    with zipfile.ZipFile(zpath) as z:
        names = sorted(i.filename for i in z.infolist() if not i.is_dir())
        if names != ["manifest.json", "noxy.db"]:
            raise ValueError(f"Not a noxy export (unexpected files: {', '.join(names)}).")
        info = z.getinfo("noxy.db")
        if info.file_size > MAX_DB:
            raise ValueError("Database in the export is unexpectedly large.")
        manifest = json.loads(z.read("manifest.json")[:65536])
        if manifest.get("app") != "noxy":
            raise ValueError("Manifest is not from noxy.")
    return manifest


def import_(zpath):
    manifest = validate(zpath)
    with tempfile.TemporaryDirectory() as td:
        with zipfile.ZipFile(zpath) as z:
            with z.open("noxy.db") as src, open(Path(td) / "noxy.db", "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
        cand = Path(td) / "noxy.db"
        if util.sha256_file(cand) != manifest.get("db_sha256"):
            raise ValueError("Database checksum does not match the manifest: the export is damaged.")
        with open(cand, "rb") as f:
            if f.read(16) != b"SQLite format 3\x00":
                raise ValueError("Not an SQLite database.")
        con = sqlite3.connect(f"file:{cand}?mode=ro", uri=True)
        try:
            if con.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("Database integrity check failed.")
            tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"sessions", "notes", "events", "net"} <= tables:
                raise ValueError("Database does not have noxy's tables.")
        finally:
            con.close()
        util.DATA.mkdir(parents=True, exist_ok=True)
        cur = db.path()
        kept = None
        if cur.exists():
            bdir = util.DATA / "backups"
            bdir.mkdir(exist_ok=True)
            kept = bdir / f"noxy-before-import-{util.utcnow().strftime('%Y%m%dT%H%M%SZ')}.db"
            src, dst = sqlite3.connect(cur), sqlite3.connect(kept)
            try:
                src.backup(dst)                          # consistent copy, including the WAL
            finally:
                dst.close()
                src.close()
            for ext in ("-wal", "-shm"):
                Path(str(cur) + ext).unlink(missing_ok=True)
        shutil.copy2(cand, cur)
        os.chmod(cur, 0o600)
    db.init()
    return {"sessions": manifest.get("sessions"), "previous": str(kept) if kept else None}
