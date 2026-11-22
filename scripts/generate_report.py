"""Write CSV reports to ./reports/ (assets, vulnerabilities, risks)."""
import os
import _boot  # noqa
from app.database.db import get_cursor
from app.services.reports import REPORTS, build_csv

os.makedirs("reports", exist_ok=True)
with get_cursor() as cur:
    for name in REPORTS:
        with open(f"reports/{name}_report.csv", "w", newline="", encoding="utf-8") as f:
            f.write(build_csv(cur, name))
        print(f"reports/{name}_report.csv written")
