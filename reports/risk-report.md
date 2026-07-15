# AWS IAM Privilege Escalation Risk Report

**Generated:** 2026-07-15 14:47:31

**Total findings:** 5

**Summary:** 1 CRITICAL, 2 HIGH, 2 MEDIUM

## Findings

| Severity | Rule | Role |
|----------|------|------|
| CRITICAL | Overly Permissive Trust Policy | open-trust-role-tf |
| HIGH | Self-Permission Modification | self-modify-role-tf |
| HIGH | Wildcard Admin (inline */*) | wildcard-admin-role-tf |
| MEDIUM | PassRole + Lambda Privilege Escalation | low-priv-ec2-role |
| MEDIUM | PassRole + Lambda Privilege Escalation | low-priv-ec2-role-tf |

## Details

### [CRITICAL] open-trust-role-tf
- **Rule:** Overly Permissive Trust Policy
- **Why:** Trust policy allows Principal "*", meaning ANY AWS account or user can assume this role.

### [HIGH] self-modify-role-tf
- **Rule:** Self-Permission Modification
- **Why:** Role can modify permissions using ['iam:AttachRolePolicy', 'iam:PutRolePolicy'], allowing it to grant itself additional privileges (including admin).

### [HIGH] wildcard-admin-role-tf
- **Rule:** Wildcard Admin (inline */*)
- **Why:** Role has an inline policy allowing all actions (*) on all resources (*), which is effectively full admin access.

### [MEDIUM] low-priv-ec2-role
- **Rule:** PassRole + Lambda Privilege Escalation
- **Why:** Role can create a Lambda function and pass a role to it, allowing escalation by attaching a privileged role to attacker-controlled code.

### [MEDIUM] low-priv-ec2-role-tf
- **Rule:** PassRole + Lambda Privilege Escalation
- **Why:** Role can create a Lambda function and pass a role to it, allowing escalation by attaching a privileged role to attacker-controlled code.
