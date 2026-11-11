
import sys
sys.path.insert(0, "/home/bigdaddy/osint-foundry/src")
from osint_foundry.model import Report, Finding
from osint_foundry.web.ui import build_ui_html

# Create a test report
report = Report(target='example.com')
report.status = 'success'
report.started_at = '2026-09-28T12:00:00'
report.collectors = ['osintpilot.com']
for i in range(5):
    report.findings.append(Finding(
        category='recon', 
        subtype='test', 
        target='example.com', 
        summary=f'Test finding {i}',
        source='test.com', 
        confidence=0.9
    ))

# Test build_ui_html
print("Testing build_ui_html...", file=sys.stderr)
try:
    html = build_ui_html(report)
    print(f"build_ui_html: OK, {len(html)} chars", file=sys.stderr)
    print(f"SUCCESS!", file=sys.stderr)
except Exception as e:
    print(f"build_ui_html ERROR: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc(file=sys.stderr)
