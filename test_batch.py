import time
import requests

BASE = "http://localhost:8090"
JOB_ID = "batch-test-100"

PACKAGES = [
    # npm (50 distinct)
    {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"},
    {"name": "express", "version": "4.18.2", "ecosystem": "npm"},
    {"name": "chalk", "version": "5.3.0", "ecosystem": "npm"},
    {"name": "axios", "version": "1.6.8", "ecosystem": "npm"},
    {"name": "react", "version": "18.2.0", "ecosystem": "npm"},
    {"name": "moment", "version": "2.29.4", "ecosystem": "npm"},
    {"name": "uuid", "version": "9.0.0", "ecosystem": "npm"},
    {"name": "dotenv", "version": "16.4.5", "ecosystem": "npm"},
    {"name": "commander", "version": "12.0.0", "ecosystem": "npm"},
    {"name": "yargs", "version": "17.7.2", "ecosystem": "npm"},
    {"name": "webpack", "version": "5.91.0", "ecosystem": "npm"},
    {"name": "typescript", "version": "5.4.3", "ecosystem": "npm"},
    {"name": "jest", "version": "29.7.0", "ecosystem": "npm"},
    {"name": "prettier", "version": "3.2.5", "ecosystem": "npm"},
    {"name": "nodemon", "version": "3.1.0", "ecosystem": "npm"},
    {"name": "cors", "version": "2.8.5", "ecosystem": "npm"},
    {"name": "body-parser", "version": "1.20.2", "ecosystem": "npm"},
    {"name": "mongoose", "version": "8.2.3", "ecosystem": "npm"},
    {"name": "sequelize", "version": "6.37.1", "ecosystem": "npm"},
    {"name": "socket.io", "version": "4.7.4", "ecosystem": "npm"},
    {"name": "multer", "version": "1.4.5-lts.1", "ecosystem": "npm"},
    {"name": "passport", "version": "0.7.0", "ecosystem": "npm"},
    {"name": "jsonwebtoken", "version": "9.0.2", "ecosystem": "npm"},
    {"name": "bcrypt", "version": "5.1.1", "ecosystem": "npm"},
    {"name": "morgan", "version": "1.10.0", "ecosystem": "npm"},
    {"name": "compression", "version": "1.7.4", "ecosystem": "npm"},
    {"name": "helmet", "version": "7.1.0", "ecosystem": "npm"},
    {"name": "winston", "version": "3.13.0", "ecosystem": "npm"},
    {"name": "ramda", "version": "0.29.1", "ecosystem": "npm"},
    {"name": "underscore", "version": "1.13.6", "ecosystem": "npm"},
    {"name": "rxjs", "version": "7.8.1", "ecosystem": "npm"},
    {"name": "immutable", "version": "4.3.5", "ecosystem": "npm"},
    {"name": "dayjs", "version": "1.11.10", "ecosystem": "npm"},
    {"name": "date-fns", "version": "3.6.0", "ecosystem": "npm"},
    {"name": "luxon", "version": "3.4.4", "ecosystem": "npm"},
    {"name": "classnames", "version": "2.5.1", "ecosystem": "npm"},
    {"name": "prop-types", "version": "15.8.1", "ecosystem": "npm"},
    {"name": "redux", "version": "5.0.1", "ecosystem": "npm"},
    {"name": "zustand", "version": "4.5.2", "ecosystem": "npm"},
    {"name": "graphql", "version": "16.8.1", "ecosystem": "npm"},
    {"name": "knex", "version": "3.1.0", "ecosystem": "npm"},
    {"name": "joi", "version": "17.12.2", "ecosystem": "npm"},
    {"name": "zod", "version": "3.22.4", "ecosystem": "npm"},
    {"name": "semver", "version": "7.6.0", "ecosystem": "npm"},
    {"name": "glob", "version": "10.3.12", "ecosystem": "npm"},
    {"name": "minimist", "version": "1.2.8", "ecosystem": "npm"},
    {"name": "cross-env", "version": "7.0.3", "ecosystem": "npm"},
    {"name": "husky", "version": "9.0.11", "ecosystem": "npm"},
    {"name": "lint-staged", "version": "15.2.2", "ecosystem": "npm"},
    {"name": "concurrently", "version": "8.2.2", "ecosystem": "npm"},
    # pypi (50 distinct)
    {"name": "requests", "version": "2.31.0", "ecosystem": "pypi"},
    {"name": "numpy", "version": "1.26.4", "ecosystem": "pypi"},
    {"name": "pandas", "version": "2.2.1", "ecosystem": "pypi"},
    {"name": "flask", "version": "3.0.2", "ecosystem": "pypi"},
    {"name": "click", "version": "8.1.7", "ecosystem": "pypi"},
    {"name": "pydantic", "version": "2.6.4", "ecosystem": "pypi"},
    {"name": "httpx", "version": "0.27.0", "ecosystem": "pypi"},
    {"name": "rich", "version": "13.7.1", "ecosystem": "pypi"},
    {"name": "fastapi", "version": "0.110.0", "ecosystem": "pypi"},
    {"name": "boto3", "version": "1.34.69", "ecosystem": "pypi"},
    {"name": "django", "version": "5.0.3", "ecosystem": "pypi"},
    {"name": "sqlalchemy", "version": "2.0.29", "ecosystem": "pypi"},
    {"name": "celery", "version": "5.3.6", "ecosystem": "pypi"},
    {"name": "redis", "version": "5.0.3", "ecosystem": "pypi"},
    {"name": "pillow", "version": "10.3.0", "ecosystem": "pypi"},
    {"name": "pytest", "version": "8.1.1", "ecosystem": "pypi"},
    {"name": "black", "version": "24.3.0", "ecosystem": "pypi"},
    {"name": "mypy", "version": "1.9.0", "ecosystem": "pypi"},
    {"name": "pylint", "version": "3.1.0", "ecosystem": "pypi"},
    {"name": "cryptography", "version": "42.0.5", "ecosystem": "pypi"},
    {"name": "paramiko", "version": "3.4.0", "ecosystem": "pypi"},
    {"name": "scrapy", "version": "2.11.1", "ecosystem": "pypi"},
    {"name": "beautifulsoup4", "version": "4.12.3", "ecosystem": "pypi"},
    {"name": "lxml", "version": "5.1.0", "ecosystem": "pypi"},
    {"name": "aiohttp", "version": "3.9.3", "ecosystem": "pypi"},
    {"name": "uvicorn", "version": "0.29.0", "ecosystem": "pypi"},
    {"name": "gunicorn", "version": "21.2.0", "ecosystem": "pypi"},
    {"name": "arrow", "version": "1.3.0", "ecosystem": "pypi"},
    {"name": "pendulum", "version": "3.0.0", "ecosystem": "pypi"},
    {"name": "pytz", "version": "2024.1", "ecosystem": "pypi"},
    {"name": "python-dateutil", "version": "2.9.0", "ecosystem": "pypi"},
    {"name": "six", "version": "1.16.0", "ecosystem": "pypi"},
    {"name": "attrs", "version": "23.2.0", "ecosystem": "pypi"},
    {"name": "marshmallow", "version": "3.21.1", "ecosystem": "pypi"},
    {"name": "tqdm", "version": "4.66.2", "ecosystem": "pypi"},
    {"name": "loguru", "version": "0.7.2", "ecosystem": "pypi"},
    {"name": "structlog", "version": "24.1.0", "ecosystem": "pypi"},
    {"name": "sentry-sdk", "version": "1.44.0", "ecosystem": "pypi"},
    {"name": "prometheus-client", "version": "0.20.0", "ecosystem": "pypi"},
    {"name": "psycopg2-binary", "version": "2.9.9", "ecosystem": "pypi"},
    {"name": "pymongo", "version": "4.6.3", "ecosystem": "pypi"},
    {"name": "motor", "version": "3.4.0", "ecosystem": "pypi"},
    {"name": "alembic", "version": "1.13.1", "ecosystem": "pypi"},
    {"name": "typer", "version": "0.12.1", "ecosystem": "pypi"},
    {"name": "jinja2", "version": "3.1.3", "ecosystem": "pypi"},
    {"name": "werkzeug", "version": "3.0.2", "ecosystem": "pypi"},
    {"name": "itsdangerous", "version": "2.1.2", "ecosystem": "pypi"},
    {"name": "python-dotenv", "version": "1.0.1", "ecosystem": "pypi"},
    {"name": "pyyaml", "version": "6.0.1", "ecosystem": "pypi"},
    {"name": "toml", "version": "0.10.2", "ecosystem": "pypi"},
]

print(f"Submitting job '{JOB_ID}' with {len(PACKAGES)} packages...")
r = requests.post(f"{BASE}/jobs/{JOB_ID}", json={"packages": PACKAGES})
print(f"  {r.status_code} {r.json()}")
r.raise_for_status()

start = time.time()
while True:
    r = requests.get(f"{BASE}/jobs/{JOB_ID}")
    data = r.json()
    done = data["done"]
    total = data["total"]
    status = data["status"]
    elapsed = time.time() - start
    print(f"  [{elapsed:5.1f}s] {done}/{total} done  (status={status})")

    if status == "done":
        break
    time.sleep(5)

print(f"\nFinished in {time.time() - start:.1f}s\n")
for pkg in sorted(data["packages"], key=lambda p: p["name"]):
    verdict = pkg.get("verdict") or pkg.get("error") or "?"
    prob = f'{pkg["probability"]:.3f}' if pkg.get("probability") is not None else "  -  "
    print(f"  {pkg['ecosystem']:5} {pkg['name']:25} {prob}  {verdict}")
