from collector import collect_roles
# Severity ranking per rule (mirrors CVSS-style reasoning: impact + exploitability)
SEVERITY = {
    'Overly Permissive Trust Policy': 'CRITICAL',
    'Wildcard Admin (inline */*)': 'HIGH',
    'Self-Permission Modification': 'HIGH',
    'PassRole + Lambda Privilege Escalation': 'MEDIUM'
}

# Numeric order so we can sort most-severe-first
SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

def extract_actions(policy_document):
    """Pull every 'Action' out of a policy document into a flat list."""
    actions = []
    statements = policy_document.get('Statement', [])

    # A policy can have one statement (dict) or many (list) - normalize to a list
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get('Effect') != 'Allow':
            continue
        action = statement.get('Action', [])
        # Action can be a single string or a list - normalize to a list
        if isinstance(action, str):
            action = [action]
        actions.extend(action)

    return actions


def check_passrole_lambda(role):
    """Rule 1: flag roles that can create a Lambda AND pass a role to it."""
    all_actions = []

    # Gather actions from every inline policy on this role
    for policy in role['inline_policies']:
        all_actions.extend(extract_actions(policy['document']))

    has_passrole = 'iam:PassRole' in all_actions
    has_create_lambda = 'lambda:CreateFunction' in all_actions

    if has_passrole and has_create_lambda:
        return {
            'rule': 'PassRole + Lambda Privilege Escalation',
            'role': role['name'],
            'reason': 'Role can create a Lambda function and pass a role to it, '
                      'allowing escalation by attaching a privileged role to attacker-controlled code.'
        }
    return None
def check_self_permission_modification(role):
    """Rule 2: flag roles that can modify their own permissions."""
    # These permissions let a role rewrite/attach policies - i.e. grant itself more power
    dangerous_actions = [
        'iam:AttachRolePolicy',
        'iam:PutRolePolicy',
        'iam:CreatePolicyVersion',
        'iam:AttachUserPolicy',
        'iam:PutUserPolicy'
    ]

    all_actions = []
    for policy in role['inline_policies']:
        all_actions.extend(extract_actions(policy['document']))

    # Find which dangerous actions this role has (if any)
    found = [action for action in dangerous_actions if action in all_actions]

    if found:
        return {
            'rule': 'Self-Permission Modification',
            'role': role['name'],
            'reason': f'Role can modify permissions using {found}, '
                      f'allowing it to grant itself additional privileges (including admin).'
        }
    return None
def check_wildcard_admin(role):
    """Rule 3: flag roles with an inline policy granting Action:* on Resource:*."""
    for policy in role['inline_policies']:
        statements = policy['document'].get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue

            action = statement.get('Action', [])
            resource = statement.get('Resource', [])
            if isinstance(action, str):
                action = [action]
            if isinstance(resource, str):
                resource = [resource]

            if '*' in action and '*' in resource:
                return {
                    'rule': 'Wildcard Admin (inline */*)',
                    'role': role['name'],
                    'reason': 'Role has an inline policy allowing all actions (*) on all '
                              'resources (*), which is effectively full admin access.'
                }
    return None


def check_permissive_trust_policy(role):
    """Rule 4: flag roles whose TRUST policy allows Principal '*' (anyone can assume)."""
    trust = role['trust_policy']
    statements = trust.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get('Effect') != 'Allow':
            continue

        principal = statement.get('Principal', {})

        # Principal can be "*" directly, or {"AWS": "*"}, or {"AWS": ["*", ...]}
        flagged = False
        if principal == '*':
            flagged = True
        elif isinstance(principal, dict):
            for value in principal.values():
                if value == '*' or (isinstance(value, list) and '*' in value):
                    flagged = True

        if flagged:
            return {
                'rule': 'Overly Permissive Trust Policy',
                'role': role['name'],
                'reason': 'Trust policy allows Principal "*", meaning ANY AWS account or user '
                          'can assume this role.'
            }
    return None
def run_detection():
    roles = collect_roles()
    findings = []

    for role in roles:
        for check in [
            check_passrole_lambda,
            check_self_permission_modification,
            check_wildcard_admin,
            check_permissive_trust_policy
        ]:
            result = check(role)
            if result:
                # Tag each finding with its severity
                result['severity'] = SEVERITY.get(result['rule'], 'LOW')
                findings.append(result)

    # Sort most severe first
    findings.sort(key=lambda f: SEVERITY_ORDER[f['severity']])
    return findings


if __name__ == '__main__':
    findings = run_detection()

    # Count by severity for a summary line
    counts = {}
    for f in findings:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1
    summary = ', '.join(f"{v} {k}" for k, v in counts.items())

    print(f"Detection complete. {len(findings)} finding(s): {summary}\n")
    for f in findings:
        print(f"[{f['severity']}] {f['rule']}")
        print(f"    Role: {f['role']}")
        print(f"    Why:  {f['reason']}\n")