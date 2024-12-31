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

variable "cidr_blocks" {
  type        = list(string)
  nullable    = false
  default     = ["0.0.0.0/0"]
  description = "List of IPv4 CIDR blocks allowed as source addresses to use the Roles Anywhere profiles"

  validation {
    condition     = alltrue([for cidr_block in var.cidr_blocks : can(cidrhost(cidr_block, 0))])
    error_message = "The value of cidr_blocks variable must be a list of valid IPv4 CIDR blocks."
  }
}
