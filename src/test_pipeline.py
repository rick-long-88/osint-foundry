import sys
sys.path.insert(0, "/home/bigdaddy/osint-foundry/src")
from osint_foundry.collectors.runner import Pipeline
print("1. Pipeline import: OK")
report = Pipeline().run("example.com")
print("2. Pipeline run: OK")
print("   TARGET:", report.target)
print("   STATUS:", report.status)
print("   FINDINGS:", len(report.findings))
print("   SUMMARY:", report.summary)
for f in report.findings:
    print("   -", f.category, "|", f.summary[:80], "| conf:", f.confidence)
print("3. Findings printed: OK")
