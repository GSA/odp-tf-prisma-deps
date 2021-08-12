variable account_id {
  type        = string
  description = "The AWS Account Id where prisma cloud monitor is hosted"
}
variable external_id {
  type        = string
  description = "External ID of the entity that is allowed to assume this role"
}

variable "is_read_only" {
  type        = bool
  description = "If true, use READ ONLY iam policy, otherwise, grant READ and WRITE policy"
  default     = true
}