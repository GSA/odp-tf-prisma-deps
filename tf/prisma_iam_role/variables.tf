variable "prisma_cloud_role_name" {
  type = string
  description = "Provide an role ARN name (Example: PrismaCloudReadOnlyRole)"
  default = "PrismaCloudReadOnlyRole"
}

variable "external_id" {
  type = string
  description = "Provide an ExternalID (Example: Xoih821ddwf)"
  default = "Xoih821ddwf"
}

variable "is_read_only" {
  type = bool
  description = "If true, use READ ONLY iam policy, otherwise, grant READ and WRITE policy"
  default = false
}
