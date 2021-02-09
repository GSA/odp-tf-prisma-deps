provider "aws" {
  profile   = "gsa_ociso_dev"
  region    = "us-east-1"
}

module "prisma_iam_role" {
  source = "./prisma_iam_role"
}
