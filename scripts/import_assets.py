"""Import assets from a CSV (default data/sample_assets.csv). Validates each row; upserts on asset_code."""
import csv, sys
import _boot  # noqa
from app.database.db import get_cursor
from app.services.validators import validate_asset

path = sys.argv[1] if len(sys.argv) > 1 else "data/sample_assets.csv"
ok = bad = 0
with open(path, newline="", encoding="utf-8") as f, get_cursor() as cur:
    for n, row in enumerate(csv.DictReader(f), start=2):
        try:
            d = validate_asset(row)
        except ValueError as e:
            print(f"line {n}: skipped - {e}")
            bad += 1
            continue
        cur.execute("""INSERT INTO assets (asset_code,name,asset_type,owner,host,environment,criticality,status)
                       VALUES (%(asset_code)s,%(name)s,%(asset_type)s,%(owner)s,%(host)s,%(environment)s,%(criticality)s,%(status)s)
                       ON CONFLICT (asset_code) DO UPDATE SET name=EXCLUDED.name, asset_type=EXCLUDED.asset_type, owner=EXCLUDED.owner,
                       host=EXCLUDED.host, environment=EXCLUDED.environment, criticality=EXCLUDED.criticality,
                       status=EXCLUDED.status, updated_at=now()""", d)
        ok += 1
    cur.execute("INSERT INTO audit_logs (username, action, module, record_id) VALUES ('system','CSV_IMPORT','assets',%s)", (path,))
print(f"Imported/updated {ok} asset(s); {bad} row(s) skipped.")
