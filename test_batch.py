import time
import requests

BASE = "http://localhost:8090"
JOB_ID = "batch-test-050"

PACKAGES = [
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
    print(f"  {pkg['ecosystem']:5} {pkg['name']:20} {prob}  {verdict}")
