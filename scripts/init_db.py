"""Create all tables (idempotent). Run after creating the database and app role."""
import _boot  # noqa
from pathlib import Path
from app.database.db import get_cursor

with get_cursor() as cur:
    cur.execute((Path(__file__).parent.parent / "app" / "database" / "schema.sql").read_text())
print("Schema created/verified in vulntrack_db.")
