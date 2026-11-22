"""PostgreSQL connection helper. Every query in the project uses %s parameters."""
import os
from contextlib import contextmanager

import psycopg2
import psycopg2.extras


def connect():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        port=os.environ.get("DB_PORT", "5432"),
        dbname=os.environ.get("DB_NAME", "vulntrack_db"),
        user=os.environ.get("DB_USER", "vulntrack_app"),
        password=os.environ.get("DB_PASSWORD", ""),
        connect_timeout=5,
    )


@contextmanager
def get_cursor():
    """One transaction per `with` block: commit on success, rollback on any error."""
    conn = connect()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
