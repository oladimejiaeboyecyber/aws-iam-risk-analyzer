import json
import os
from datetime import datetime
from detector import run_detection


def generate_reports():
    findings = run_detection()

    # Make sure the reports/ folder exists
    os.makedirs('reports', exist_ok=True)

    # Count findings by severity for the summary
    counts = {}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # ---------- 1. JSON report (machine-readable) ----------
    json_output = {
        'generated_at': timestamp,
        'total_findings': len(findings),
        'summary_by_severity': counts,
        'findings': findings
    }
    with open('reports/risk-report.json', 'w') as f:
        json.dump(json_output, f, indent=2)

    # ---------- 2. Markdown report (human-readable) ----------
    lines = []
    lines.append('# AWS IAM Privilege Escalation Risk Report')
    lines.append(f'\n**Generated:** {timestamp}')
    lines.append(f'\n**Total findings:** {len(findings)}')

    # Severity summary line
    summary_parts = [f'{v} {k}' for k, v in counts.items()]
    lines.append(f'\n**Summary:** {", ".join(summary_parts)}')

    # Findings table
    lines.append('\n## Findings\n')
    lines.append('| Severity | Rule | Role |')
    lines.append('|----------|------|------|')
    for f in findings:
        lines.append(f"| {f['severity']} | {f['rule']} | {f['role']} |")

    # Detailed section
    lines.append('\n## Details\n')
    for f in findings:
        lines.append(f"### [{f['severity']}] {f['role']}")
        lines.append(f"- **Rule:** {f['rule']}")
        lines.append(f"- **Why:** {f['reason']}\n")

    with open('reports/risk-report.md', 'w') as f:
        f.write('\n'.join(lines))

    print(f"Reports generated:")
    print(f"  - reports/risk-report.json")
    print(f"  - reports/risk-report.md")
    print(f"\n{len(findings)} findings: {', '.join(summary_parts)}")


if __name__ == '__main__':
    generate_reports()