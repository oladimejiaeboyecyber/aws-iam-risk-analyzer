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