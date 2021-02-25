It's a terraform module that allows you to create IAM Role for Prisma Tenant to assume and access the AWS resources to monitor.

### How to use this module?
```
module "prisma_dev_integration_roles" {
  source = "github.com/GSA/odp-tf-prisma-deps#dev_br"
  prisma_secrets_name  = "prisma-cloud-enterprise/integration-secrets"
  is_read_only = true
}
```
### What are these variables?
1. <ins>prisma_secrets_name:</ins> - It is the name of the secrets in the AWS Secrets manager, which should contain the following secret key/value pairs:
   - *prisma_aws_account_id*: AWS account where prisma cloud enterprise is hosted
   - *prisma_external_id*: External ID supplied by Prisma Team
   - *prisma_role_name*: Name of the role. For example: prisma-cloud-read-only-role-dev
2. <ins>is_read_only</ins>: Flag to specify if the role should provide read-only permissions