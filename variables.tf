variable account_id {
  type        = string
  description = "The AWS Account Id where prisma cloud monitor is hosted"
  default     = "188619942792"
}

variable external_id {
  type        = string
  description = "External ID of the entity that is allowed to assume this role"
}

/* variable "is_read_only" {
  type        = bool
  description = "If true, use READ ONLY iam policy, otherwise, grant READ and WRITE policy"
  default     = true
} */

variable prisma_cloud_role_name {
  type        = string
  description = "Provide a role ARN anme (Example: PrismaCloudAwsOrgMonitoringRole). Maximum 64 characters allowed"
  default     = "PrismaCloudAwsOrgMonitoringRole"
}
