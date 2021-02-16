#!/bin/bash

which terraform

terraform init

workspace_name="dev"
terraform workspace new ${workspace_name}
terraform workspace select ${workspace_name}

#terraform plan
#terraform apply
#terraform destroy