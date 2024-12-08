output "trust_anchor_arns" {
  value = {
    for k, v in aws_rolesanywhere_trust_anchor.this :
    k => v.arn
  }
}

output "role_arns" {
  value = { for k, v in aws_iam_role.this : k => v.arn }
}

output "profile_arns" {
  value = {
    for k, v in aws_rolesanywhere_profile.this :
    k => v.arn
  }
}

output "certificate_files" {
  value = { for k, v in local_file.this : k => abspath(v.filename) }
}

output "key_files" {
  value = { for k, v in local_sensitive_file.this : k => abspath(v.filename) }
}

output "region" {
  value = var.region
}
