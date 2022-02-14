provider "aws" {
  region = "us-east-1"
}

module "under_test" {
  source = "../terraform"

  # Any arguments the module requires
}