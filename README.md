This terraform module allow you to create IAM Role for Prisma Tenant to assume.

## How to use this module?
```
module "prisma_dev_integration_roles" {
  source = "github.com/GSA/odp-tf-prisma-deps?ref=v1.0.1"
  prisma_secrets_name  = "prisma-cloud-enterprise/integration-secrets"
  is_read_only = true
}
```
## What are these variables?
1. <ins>prisma_secrets_name:</ins> - It is the name of the secrets in the AWS Secrets manager, which should contain the following secret key/value pairs:
   1. *prisma_aws_account_id*: *AWS account where prisma cloud enterprise is hosted**
   2. *prisma_external_id*: External ID supplied by Prisma Team
   3. *prisma_role_name*: Name of the role. For example: prisma-cloud-read-only-role-dev
2. <ins>is_read_only</ins>: Flag to specify if the role should provide read-only permissions

