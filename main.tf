provider "aws" {
  region = var.region
}

locals {
  acmpca_permission_actions = [
    "IssueCertificate",
    "GetCertificate",
    "ListPermissions",
  ]
}

resource "aws_s3_bucket" "this" {
  force_destroy = true
}

data "aws_caller_identity" "this" {}

data "aws_iam_policy_document" "s3" {
  statement {
    actions = [
      "s3:GetBucketAcl",
      "s3:GetBucketLocation",
      "s3:PutObject",
      "s3:PutObjectAcl",
    ]

    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*",
    ]

    principals {
      identifiers = ["acm-pca.amazonaws.com"]
      type        = "Service"
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.this.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.s3.json
}

data "aws_partition" "this" {}

resource "aws_acmpca_certificate_authority" "root" {
  type                            = "ROOT"
  permanent_deletion_time_in_days = 7

  certificate_authority_configuration {
    key_algorithm     = "RSA_4096"
    signing_algorithm = "SHA512WITHRSA"

    subject {
      common_name = "Root"
    }
  }

  revocation_configuration {
    crl_configuration {
      enabled            = true
      expiration_in_days = 1
      s3_bucket_name     = aws_s3_bucket.this.id
      s3_object_acl      = "BUCKET_OWNER_FULL_CONTROL"
    }
  }

  depends_on = [aws_s3_bucket_policy.this]
}

resource "aws_acmpca_certificate" "root" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.root.arn
  certificate_signing_request = aws_acmpca_certificate_authority.root.certificate_signing_request
  signing_algorithm           = "SHA512WITHRSA"

  validity {
    type  = "YEARS"
    value = 15
  }

  template_arn = "arn:${data.aws_partition.this.partition}:acm-pca:::template/RootCACertificate/V1"
}

resource "aws_acmpca_certificate_authority_certificate" "root" {
  certificate               = aws_acmpca_certificate.root.certificate
  certificate_authority_arn = aws_acmpca_certificate_authority.root.arn
}

resource "aws_acmpca_permission" "root" {
  certificate_authority_arn = aws_acmpca_certificate_authority.root.arn
  actions                   = local.acmpca_permission_actions
  principal                 = "acm.amazonaws.com"
}

resource "aws_acmpca_certificate_authority" "intermediate" {
  permanent_deletion_time_in_days = 7

  certificate_authority_configuration {
    key_algorithm     = "RSA_4096"
    signing_algorithm = "SHA512WITHRSA"

    subject {
      common_name = "AWS IAM Roles Anywhere"
    }
  }

  revocation_configuration {
    crl_configuration {
      enabled            = true
      expiration_in_days = 1
      s3_bucket_name     = aws_s3_bucket.this.id
      s3_object_acl      = "BUCKET_OWNER_FULL_CONTROL"
    }
  }

  depends_on = [aws_s3_bucket_policy.this]
}

resource "aws_acmpca_certificate" "intermediate" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.root.arn
  certificate_signing_request = aws_acmpca_certificate_authority.intermediate.certificate_signing_request
  signing_algorithm           = "SHA512WITHRSA"

  validity {
    type  = "YEARS"
    value = 10
  }

  template_arn = "arn:${data.aws_partition.this.partition}:acm-pca:::template/SubordinateCACertificate_PathLen1/V1"
}

resource "aws_acmpca_certificate_authority_certificate" "intermediate" {
  certificate               = aws_acmpca_certificate.intermediate.certificate
  certificate_authority_arn = aws_acmpca_certificate_authority.intermediate.arn

  certificate_chain = aws_acmpca_certificate.intermediate.certificate_chain
}

resource "aws_acmpca_permission" "intermediate" {
  certificate_authority_arn = aws_acmpca_certificate_authority.intermediate.arn
  actions                   = local.acmpca_permission_actions
  principal                 = "acm.amazonaws.com"
}

resource "aws_acmpca_certificate_authority" "signing" {
  for_each = var.iam_role

  permanent_deletion_time_in_days = 7

  certificate_authority_configuration {
    key_algorithm     = "RSA_4096"
    signing_algorithm = "SHA512WITHRSA"

    subject {
      common_name = each.value.name
    }
  }

  revocation_configuration {
    crl_configuration {
      enabled            = true
      expiration_in_days = 1
      s3_bucket_name     = aws_s3_bucket.this.id
      s3_object_acl      = "BUCKET_OWNER_FULL_CONTROL"
    }
  }

  depends_on = [aws_s3_bucket_policy.this]
}

resource "aws_acmpca_certificate" "signing" {
  for_each = aws_acmpca_certificate_authority.signing

  certificate_authority_arn   = aws_acmpca_certificate_authority.intermediate.arn
  certificate_signing_request = each.value.certificate_signing_request
  signing_algorithm           = "SHA512WITHRSA"

  validity {
    type  = "YEARS"
    value = 5
  }

  template_arn = "arn:${data.aws_partition.this.partition}:acm-pca:::template/SubordinateCACertificate_PathLen0/V1"
}

resource "aws_acmpca_certificate_authority_certificate" "signing" {
  for_each = aws_acmpca_certificate.signing

  certificate               = each.value.certificate
  certificate_authority_arn = aws_acmpca_certificate_authority.signing[each.key].arn

  certificate_chain = each.value.certificate_chain
}

resource "aws_acmpca_permission" "signing" {
  for_each = aws_acmpca_certificate_authority.signing

  certificate_authority_arn = each.value.arn
  actions = [
    "IssueCertificate",
    "GetCertificate",
    "ListPermissions",
  ]
  principal = "acm.amazonaws.com"
}

resource "aws_rolesanywhere_trust_anchor" "this" {
  for_each = aws_acmpca_certificate_authority.signing

  name = each.value.certificate_authority_configuration.0.subject.0.common_name

  enabled = true

  source {
    source_type = "AWS_ACM_PCA"

    source_data {
      acm_pca_arn = each.value.arn
    }
  }

  depends_on = [aws_acmpca_certificate_authority_certificate.signing]
}

data "aws_iam_policy_document" "trust" {
  for_each = aws_rolesanywhere_trust_anchor.this

  statement {
    sid = each.value.name

    actions = [
      "sts:AssumeRole",
      "sts:TagSession",
      "sts:SetSourceIdentity",
    ]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [each.value.arn]
    }

    principals {
      type        = "Service"
      identifiers = ["rolesanywhere.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "profile" {
  count = length(var.ip_addresses)

  statement {
    actions = ["*"]

    resources = ["*"]

    condition {
      test     = "IpAddress"
      variable = "aws:SourceIp"
      values   = var.ip_addresses
    }
  }
}

resource "aws_iam_role" "this" {
  for_each = data.aws_iam_policy_document.trust

  assume_role_policy = each.value.json

  path        = "/RolesAnywhere/"
  name_prefix = "${each.value.statement.0.sid}-"
}

resource "aws_iam_role_policy_attachment" "this" {
  for_each = aws_iam_role.this

  role       = each.value.id
  policy_arn = "arn:aws:iam::aws:policy/${var.iam_role[each.key].managed_policy}"
}

resource "aws_iam_role_policy_attachments_exclusive" "this" {
  for_each = aws_iam_role_policy_attachment.this

  role_name   = each.value.role
  policy_arns = [each.value.policy_arn]
}

resource "aws_rolesanywhere_profile" "this" {
  for_each = aws_iam_role.this

  name      = each.value.name
  role_arns = [each.value.arn]

  enabled        = true
  session_policy = length(var.ip_addresses) > 0 ? data.aws_iam_policy_document.profile.0.json : null
}

resource "tls_private_key" "this" {
  for_each = aws_rolesanywhere_profile.this

  algorithm = "RSA"
}

resource "tls_cert_request" "this" {
  for_each = tls_private_key.this

  private_key_pem = each.value.private_key_pem

  subject {
    common_name = split("-", aws_rolesanywhere_profile.this[each.key].name).0
  }
}

resource "aws_acmpca_certificate" "this" {
  for_each = tls_cert_request.this

  certificate_authority_arn   = aws_acmpca_certificate_authority.signing[each.key].arn
  certificate_signing_request = each.value.cert_request_pem
  signing_algorithm           = "SHA512WITHRSA"

  validity {
    type  = "YEARS"
    value = 1
  }
}

resource "local_sensitive_file" "this" {
  for_each = tls_private_key.this

  filename = "${path.module}/${each.key}.pem"

  content         = each.value.private_key_pem
  file_permission = "0600"
}

resource "local_file" "this" {
  for_each = aws_acmpca_certificate.this

  filename = "${path.module}/${each.key}.crt"

  content         = join("\n", [each.value.certificate, each.value.certificate_chain])
  file_permission = "0600"
}
