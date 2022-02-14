provider "aws" {
  region = "us-east-1"
}

module "under_test" {
  source = "../"

  # Any arguments the module requires
}