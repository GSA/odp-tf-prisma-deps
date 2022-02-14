variable "prisma_secrets_name" {
  type        = string
  description = "The AWS Account Id where prisma cloud is located"
}

variable "is_read_only" {
  type        = bool
  description = "If true, use READ ONLY iam policy, otherwise, grant READ and WRITE policy"
  default     = true
}
