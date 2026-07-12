import boto3

def collect_roles():
    """Connect to AWS and pull back every IAM role plus its policies."""
    iam = boto3.client('iam')

    collected = []

    # Get every role in the account
    roles = iam.list_roles()['Roles']

    for role in roles:
        role_name = role['RoleName']

        role_data = {
            'name': role_name,
            'trust_policy': role['AssumeRolePolicyDocument'],
            'inline_policies': [],
            'attached_policies': []
        }

        # Get inline policies (custom policies written directly into the role)
        inline_names = iam.list_role_policies(RoleName=role_name)['PolicyNames']
        for policy_name in inline_names:
            policy_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            role_data['inline_policies'].append({
                'name': policy_name,
                'document': policy_doc['PolicyDocument']
            })

        # Get attached managed policies (AWS-managed, attached by reference)
        attached = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
        for policy in attached:
            role_data['attached_policies'].append({
                'name': policy['PolicyName'],
                'arn': policy['PolicyArn']
            })

        collected.append(role_data)

    return collected


if __name__ == '__main__':
    roles = collect_roles()
    print(f"Found {len(roles)} roles:\n")
    for r in roles:
        print(f"- {r['name']}")
        print(f"    inline policies: {[p['name'] for p in r['inline_policies']]}")
        print(f"    attached policies: {[p['name'] for p in r['attached_policies']]}")