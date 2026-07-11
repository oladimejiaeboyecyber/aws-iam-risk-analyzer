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