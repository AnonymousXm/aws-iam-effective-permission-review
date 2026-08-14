# Least-privilege IAM remediation pattern.
#
# The role name and Lambda ARN are supplied as variables so this module
# can be reused across isolated test environments without hard-coded
# identifiers.

variable "entry_role_name" {
  type = string
}

variable "lambda_function_arn_pattern" {
  type = string
}

# Scope the role to the Lambda operations required by the application.
# Avoid broad role-passing permissions unless a separately tested workflow
# requires them; if PassRole is necessary, scope it to the exact role ARN
# and intended AWS service.

resource "aws_iam_role_policy" "least_privilege_entry" {
  name = "least-privilege-entry"
  role = var.entry_role_name

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "ScopedLambdaOperations"
        Effect = "Allow"

        Action = [
          "lambda:GetFunction",
          "lambda:InvokeFunction",
          "lambda:DeleteFunction"
        ]

        Resource = var.lambda_function_arn_pattern
      }
    ]
  })
}
