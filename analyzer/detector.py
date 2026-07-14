from collector import collect_roles


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

def run_detection():
    roles = collect_roles()
    findings = []

    for role in roles:
        for check in [check_passrole_lambda, check_self_permission_modification]:
            result = check(role)
            if result:
                findings.append(result)

    return findings


if __name__ == '__main__':
    findings = run_detection()
    print(f"Detection complete. {len(findings)} finding(s):\n")
    for f in findings:
        print(f"[!] {f['rule']}")
        print(f"    Role: {f['role']}")
        print(f"    Why:  {f['reason']}\n")