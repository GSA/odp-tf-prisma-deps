variable account_id {
  type        = string
  description = "The AWS Account Id where prisma cloud monitor is hosted"
  default     = "188619942792"
}
variable external_id {
  type        = string
  description = "External ID of the entity that is allowed to assume this role"
  default     = "622cbd5e-f964-4187-918f-33aed90f49ac"
}

variable "is_read_only" {
  type        = bool
  description = "If true, use READ ONLY iam policy, otherwise, grant READ and WRITE policy"
  default     = true
}
