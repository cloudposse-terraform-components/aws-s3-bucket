variable "account_map_enabled" {
  type        = bool
  description = <<-EOT
    Enable the account map component lookup. When disabled, use the `account_map` variable to provide static account mapping.
    EOT
  default     = true
}

variable "account_map" {
  type = object({
    full_account_map              = map(string)
    audit_account_account_name    = optional(string, "")
    root_account_account_name     = optional(string, "")
    identity_account_account_name = optional(string, "")
    aws_partition                 = optional(string, "aws")
    iam_role_arn_templates        = optional(map(string), {})
  })
  description = <<-EOT
    Static account map to use when `account_map_enabled` is `false`. Map of account names (tenant-stage format) to account IDs.
    Optional attributes support component-specific functionality (e.g., audit_account_account_name for cloudtrail).
    EOT
  default = {
    full_account_map              = {}
    audit_account_account_name    = ""
    root_account_account_name     = ""
    identity_account_account_name = ""
    aws_partition                 = "aws"
    iam_role_arn_templates        = {}
  }
}

provider "aws" {
  region = var.region

  # Profile is deprecated in favor of terraform_role_arn. When profiles are not in use, terraform_profile_name is null.
  profile = module.iam_roles.terraform_profile_name

  dynamic "assume_role" {
    # module.iam_roles.terraform_role_arn may be null, in which case do not assume a role.
    for_each = compact([module.iam_roles.terraform_role_arn])
    content {
      role_arn = assume_role.value
    }
  }
}

module "iam_roles" {
  source  = "../account-map/modules/iam-roles"
  context = module.this.context
}
