# IAM Fundamentals — Trust Policies vs Permission Policies

## What is a trust policy?
A trust policy is attached to a role and defines who is allowed to assume that role.
In the ec2-s3-readonly-role, the trust policy's Principal is set to ec2.amazonaws.com,
meaning EC2 instances are allowed to assume this role. Once an EC2 instance assumes
the role, it inherits whatever permissions are attached to the role — in this case,
AmazonS3ReadOnlyAccess. The trust policy controls WHO can become the role;
it does not control WHAT the role can do.
## Why scope Principal to a specific service instead of "*"?
The Principal field controls who is allowed to assume a role. Scoping it to
ec2.amazonaws.com means only EC2 instances in this account can assume the role.
If Principal were set to "*" instead, literally anyone — any AWS account, any
service, any random person on the internet — could assume the role and inherit
its permissions. Since this role has AmazonS3ReadOnlyAccess attached, a wildcard
Principal would mean anyone in the world could read every S3 bucket the role
has access to. A wildcard Principal on a role with real permissions attached
is a high-risk misconfiguration in a security audit.
## Trust policy vs permissions policy — what's the difference?
AmazonS3ReadOnlyAccess is a permissions policy, not a trust policy. I know this
because it defines WHAT actions are allowed (reading S3 buckets) rather than
WHO is allowed to assume the role. The sequence matters: the trust policy is
evaluated first (does EC2 have permission to assume this role?), and only after
that assumption succeeds does the permissions policy (AmazonS3ReadOnlyAccess)
determine what the assumed role can actually do. Trust policy = who can become
this identity. Permissions policy = what that identity can do once assumed.
## What I learned from the empty Principal mistake
While editing the trust policy, I accidentally added a second statement with
Principal: {} using the "Add new statement" button. An empty Principal is
different from a wildcard "*" — a wildcard means "anyone" (too permissive,
high risk), while an empty Principal means "no one" (invalid, not a security
risk, just a broken policy that AWS would likely reject). This helped me
understand that Principal isn't optional or a placeholder — it has to name
exactly who is trusted, and getting it wrong in either direction (too open
or empty/broken) causes a real problem, just different kinds.