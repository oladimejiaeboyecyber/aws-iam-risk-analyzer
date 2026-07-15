# Project Progress Log — AWS IAM Risk Analyzer

## Day 1 — AWS Account & Environment Setup
- Created a personal AWS account (free tier).
- Set up a billing budget alert to avoid surprise charges.
- Enabled MFA on the root user; created a non-root IAM user (oladimeji_admin) with AdministratorAccess for daily use.
- Enabled CloudTrail (main-trail, multi-region) to log all account API activity.

## Day 2 — Manual IAM Privilege Escalation (Core Demo)
- Learned IAM fundamentals: trust policies (who can assume a role) vs permissions policies (what a role can do). Documented in notes/iam-fundamentals.md.
- Created admin-lambda-execution-role: an IAM role with AdministratorAccess, trusted by the Lambda service. Represents the "prize" — a powerful role that shouldn't be easily reachable.
- Created low-priv-ec2-role: an IAM role with only 3 permissions (iam:PassRole, lambda:CreateFunction, lambda:InvokeFunction), trusted by EC2. Represents the "foothold" — a weak identity an attacker might compromise first.
- Installed and configured AWS CLI; created an access key for oladimeji_admin.
- Edited low-priv-ec2-role's trust policy to also allow oladimeji_admin to assume it (shortcut to simulate compromising an EC2 instance without spinning one up).
- Used STS (aws sts assume-role) to obtain temporary credentials for low-priv-ec2-role and loaded them as PowerShell environment variables.
- Confirmed the low-priv role's limits: `aws iam list-users` returned AccessDenied (proof of no admin access).
- Wrote a Lambda function (lambda_function.py) that calls iam.list_users() — an admin-only action.
- As the low-priv role, created a Lambda (escalation-demo) and attached admin-lambda-execution-role to it — succeeded because of iam:PassRole. THIS is the escalation.
- Invoked the Lambda; it successfully listed IAM users while running as admin. Confirmed privilege escalation: low-priv identity → admin-level action.
- Cleaned up: dropped temporary credentials, returned terminal to oladimeji_admin.
- Set up GitHub repo, .gitignore (to protect credentials/artifacts), committed all work.

## Day 3 — Infrastructure as Code (Terraform)
- Installed Terraform via winget.
- Learned Infrastructure-as-Code concepts: provider (which cloud), resource (a thing to create), state (Terraform's record of what it built).
- Wrote infra/provider.tf (targets AWS, us-east-1) and infra/iam_roles.tf.
- Defined low-priv-ec2-role-tf in code: trusted by EC2, with an inline policy granting iam:PassRole, lambda:CreateFunction, lambda:InvokeFunction (the "foothold").
- Defined admin-lambda-execution-role-tf in code: trusted by Lambda, with AWS-managed AdministratorAccess attached (the "prize").
- Learned the difference between inline policies (custom, written by me) vs managed policies (AWS pre-built, attached by ARN).
- Ran terraform init / plan / apply to build the full vulnerable lab from code. Verified roles appeared in AWS console.
- Configured .gitignore to exclude Terraform state (terraform.tfstate), the .terraform/ provider folder, and credentials — while committing the .tf source files.
- Result: the entire privilege-escalation lab can now be rebuilt or destroyed with a single command, and is version-controlled on GitHub.
## Day 4 — The Analyzer: Collector (Stage 1)
- Installed Python 3.12 and set up an isolated virtual environment (venv); installed boto3.
- Learned the analyzer's 5 stages: Collect -> Model -> Detect -> Score -> Report.
- Built analyzer/collector.py using boto3: connects to AWS and pulls every IAM role, its trust policy, inline policies, and attached managed policies.
- Successfully enumerated all roles in the account (including hand-made, Terraform-created, and AWS service roles).
- Known limitation (documented for future work): current collector doesn't paginate, so it would only see the first 100 roles in a large account. Real-scale tools also need parallel calls and rate-limit backoff (as tools like PMapper/Cartography do). Fine for this lab's ~8 roles.
## Day 4 (cont.) — Detection Engine (Stage 3, all 4 rules)
- Built analyzer/detector.py, which imports the collector and analyzes every role.
- Wrote a helper (extract_actions) to normalize AWS's inconsistent policy format (single vs list, string vs array).
- Rule 1 — PassRole + Lambda: flags roles with both iam:PassRole and lambda:CreateFunction.
- Rule 2 — Self-Permission Modification: flags roles that can edit their own permissions (iam:AttachRolePolicy, PutRolePolicy, CreatePolicyVersion, AttachUserPolicy, PutUserPolicy).
- Rule 3 — Wildcard Admin: flags inline policies granting Action:* on Resource:* (effective admin).
- Rule 4 — Permissive Trust Policy: flags trust policies allowing Principal "*" (anyone can assume the role). This rule inspects the TRUST policy (who can assume) vs Rules 1-3 which inspect permissions (what it can do).
- Structured run_detection to loop over a list of check functions, so adding rules is trivial.
- Deleted the console-made self-modify-role; recreated it plus wildcard and open-trust test roles entirely in Terraform. The lab now provisions one deliberately-vulnerable role per rule, all as code.
- Verified: all 4 rules flag exactly their intended roles (5 findings), and safe roles (S3 read-only, AWS service roles) are correctly NOT flagged (no false positives).
- Known design note: Rules 1-3 inspect inline policies; roles with admin via attached managed policies aren't caught by the wildcard rule (documented as a future enhancement).
## Day 4 (cont.) — Scoring, Reporting & Packaging

### Risk Scoring (Stage 4)
- Added a severity map to the detector (CRITICAL / HIGH / MEDIUM) based on impact + exploitability, mirroring CVSS-style reasoning.
- Rule 4 (permissive trust) = CRITICAL (anyone can assume, no foothold needed); Rules 2 & 3 = HIGH; Rule 1 = MEDIUM (requires foothold + multi-step escalation).
- Findings are now sorted most-severe-first, with a summary line (e.g. "1 CRITICAL, 2 HIGH, 2 MEDIUM").

### Report Generation (Stage 5)
- Built analyzer/report.py: runs the full pipeline (collector -> detector) and writes two outputs:
  - reports/risk-report.json (machine-readable)
  - reports/risk-report.md (human-readable, with summary, findings table, and detailed reasons)

### Packaging & Documentation
- Created requirements.txt (pip freeze) so the project is reproducible.
- Wrote a full README: problem statement, architecture (collect -> detect -> report), the 4 detection rules, setup/run instructions, sample-report screenshot, and a "what I learned" section.
- Captured a screenshot of the rendered risk report (reports/sample-report.png) as visual proof of function.
- Verified repo hygiene: only source code, Terraform config, docs, and sample reports are tracked — no state files, credentials, or build artifacts.

### Current State
- Full working pipeline: enumerates all IAM roles, detects 4 categories of privilege-escalation risk, scores by severity, and outputs a prioritized report.
