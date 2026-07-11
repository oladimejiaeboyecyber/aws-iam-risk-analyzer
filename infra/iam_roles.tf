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