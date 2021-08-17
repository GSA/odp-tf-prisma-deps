It's a terraform module that allows you to create IAM Role for Prisma Tenant to assume and access the AWS resources to monitor.

### How to use this module?
```
module prisma_role {
  source = "github.com/GSA/odp-tf-prisma-deps.git//terraform"
  external_id = "qaz-123-xsw-321-cde-456-rfv-654"
  account_id  = "123456789012"
}
```
### What are these variables?
 - *account_id*: AWS account where prisma cloud enterprise is hosted
 - *external_id*: External ID supplied by Prisma Team
