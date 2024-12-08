variable "region" {
  type     = string
  nullable = false
  default  = "us-east-2"
}

variable "iam_role" {
  type = map(
    object(
      {
        name           = string
        managed_policy = string
      }
    )
  )
  nullable = false
  default = {
    admin = {
      name           = "Administrator",
      managed_policy = "AdministratorAccess",
    },
    power_user = {
      name           = "PowerUser",
      managed_policy = "PowerUserAccess",
    },
    read_only = {
      name           = "ReadOnly",
      managed_policy = "ReadOnlyAccess",
    },
  }
}

variable "ip_addresses" {
  type        = list(string)
  nullable    = false
  default     = []
  description = "List of IPv4 addresses allowed to use the Roles Anywhere profiles"
}
