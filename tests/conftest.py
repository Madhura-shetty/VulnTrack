import os, sys, types
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRET_KEY", "test-secret")
try:
    import psycopg2  # noqa
except ImportError:  # sandbox without a PostgreSQL driver: stub so non-DB tests can import the app
    pg = types.ModuleType("psycopg2"); pg.extras = types.ModuleType("psycopg2.extras"); pg.extras.RealDictCursor = object
    pg.errors = types.ModuleType("psycopg2.errors")
    for n in ("UniqueViolation", "ForeignKeyViolation"):
        setattr(pg.errors, n, type(n, (Exception,), {}))
    def _no_db(*a, **k): raise RuntimeError("no database in this environment")
    pg.connect = _no_db
    sys.modules.update({"psycopg2": pg, "psycopg2.extras": pg.extras, "psycopg2.errors": pg.errors})
