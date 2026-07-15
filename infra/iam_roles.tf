# The low-privilege role (the "foothold")
resource "aws_iam_role" "low_priv_ec2_role" {
  name = "low-priv-ec2-role-tf"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

# The dangerous inline policy attached to that role
resource "aws_iam_role_policy" "low_priv_escalation_policy" {
  name = "low-priv-escalation-policy-tf"
  role = aws_iam_role.low_priv_ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:PassRole",
          "lambda:CreateFunction",
          "lambda:InvokeFunction"
        ]
        Resource = "*"
      }
    ]
  })
}
# The high-privilege role (the "prize")
resource "aws_iam_role" "admin_lambda_execution_role" {
  name = "admin-lambda-execution-role-tf"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

# Attach AdministratorAccess to the admin role
resource "aws_iam_role_policy_attachment" "admin_policy_attach" {
  role       = aws_iam_role.admin_lambda_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
# ---------- Rule 2 test role: self-permission modification ----------
resource "aws_iam_role" "self_modify_role" {
  name = "self-modify-role-tf"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "self_modify_policy" {
  name = "self-modify-policy-tf"
  role = aws_iam_role.self_modify_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:AttachRolePolicy", "iam:PutRolePolicy"]
        Resource = "*"
      }
    ]
  })
}

# ---------- Rule 3 test role: wildcard admin (inline */*) ----------
resource "aws_iam_role" "wildcard_admin_role" {
  name = "wildcard-admin-role-tf"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "wildcard_admin_policy" {
  name = "wildcard-admin-policy-tf"
  role = aws_iam_role.wildcard_admin_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# ---------- Rule 4 test role: overly permissive trust policy ----------
resource "aws_iam_role" "open_trust_role" {
  name = "open-trust-role-tf"

  # NOTE: Principal "*" means ANYONE can assume this role - the vulnerability
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "open_trust_policy" {
  name = "open-trust-policy-tf"
  role = aws_iam_role.open_trust_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = "*"
      }
    ]
  })
}