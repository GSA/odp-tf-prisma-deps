resource "aws_iam_policy" "prisma_cloud_iam_read_only_policy" {
  name = "${terraform.workspace}-prisma-cloud-iam-read-only-policy"
  path = "/"
  description = ""
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "apigateway:GET",
        "cloudwatch:ListTagsForResource",
        "cognito-identity:ListTagsForResource",
        "cognito-idp:ListTagsForResource",
        "ds:ListTagsForResource",
        "dynamodb:ListTagsOfResource",
        "ecr:DescribeImages",
        "ecr:GetLifecyclePolicy",
        "ecr:ListTagsForResource",
        "eks:ListTagsForResource",
        "es:ListTags",
        "elasticbeanstalk:ListTagsForResource",
        "elasticfilesystem:DescribeTags",
        "elasticache:ListTagsForResource",
        "glacier:GetVaultLock",
        "glacier:ListTagsForVault",
        "glue:GetConnections",
        "glue:GetSecurityConfigurations",
        "logs:GetLogEvents",
        "mq:listBrokers",
        "mq:describeBroker",
        "ram:GetResourceShares",
        "sns:ListTagsForResource",
        "sns:ListPlatformApplications",
        "ssm:GetParameters",
        "ssm:ListTagsForResource",
        "sqs:SendMessage",
        "elasticmapreduce:ListSecurityConfigurations",
        "elasticmapreduce:GetBlockPublicAccessConfiguration",
        "sns:listSubscriptions",
        "wafv2:ListResourcesForWebACL",
        "wafv2:ListWebACLs",
        "wafv2:ListTagsForResource",
        "wafv2:GetWebACL",
        "wafv2:GetLoggingConfiguration",
        "waf:GetWebACL",
        "waf:ListTagsForResource",
        "waf:GetLoggingConfiguration",
        "waf-regional:ListResourcesForWebACL",
        "waf-regional:ListTagsForResource"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}


resource "aws_iam_policy" "prisma_cloud_iam_read_only_policy_elastic_beanstalk" {
  name = "${terraform.workspace}-prisma-cloud-iam-read-only-policy-elastic-beanstalk"
  path = "/"
  description = ""
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequiredForAwsElasticbeanstalkConfigurationSettingsApiIngestion",
      "Action": [
        "s3:GetObject"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::elasticbeanstalk-*/*"
    }
  ]
}
EOF
}


resource "aws_iam_policy" "prisma_cloud_iam_read_only_policy_compute" {
  name = "${terraform.workspace}-prisma-cloud-iam-read-only-policy-compute"
  path = "/"
  description = ""
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:DescribeImages",
        "ecr:DescribeImageScanFindings",
        "ecr:GetAuthorizationToken",
        "ecr:GetDownloadUrlForLayer",
        "ecr:GetLifecyclePolicy",
        "ecr:GetLifecyclePolicyPreview",
        "ecr:ListImages",
        "ecr:ListTagsForResource",
        "kms:Decrypt",
        "lambda:GetFunction"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}


resource "aws_iam_policy" "prisma_cloud_iam_remediation_policy" {
  name = "${terraform.workspace}-prisma-cloud-iam-remediation-policy"
  path = "/"
  description = ""
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "cloudtrail:StartLogging",
        "cloudtrail:UpdateTrail",
        "ec2:ModifyImageAttribute",
        "ec2:ModifySnapshotAttribute",
        "ec2:ModifySubnetAttribute",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:RevokeSecurityGroupIngress",
        "eks:UpdateClusterConfig",
        "elasticache:ModifyReplicationGroup",
        "elasticloadbalancing:ModifyLoadBalancerAttributes",
        "iam:UpdateAccountPasswordPolicy",
        "kms:EnableKeyRotation",
        "rds:ModifyDBInstance",
        "rds:ModifyDBSnapshotAttribute",
        "rds:ModifyEventSubscription",
        "redshift:ModifyCluster",
        "s3:PutBucketAcl",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutBucketVersioning"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}


resource "aws_iam_policy" "prisma_cloud_iam_remediation_policy_compute" {
  name = "${terraform.workspace}-prisma-cloud-iam-remediation-policy-compute"
  path = "/"
  description = ""
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CreateSecurityGroup",
        "ec2:CreateTags",
        "lambda:GetLayerVersion",
        "lambda:PublishLayerVersion",
        "lambda:UpdateFunctionConfiguration",
        "ssm:CreateAssociation"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}


resource "aws_iam_role" "prisma_cloud_iam_role" {
  name = "${terraform.workspace}-${var.prisma_cloud_role_name}"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::188619942792:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "${var.external_id}"
        }
      }
    }
  ]
}
EOF
}


resource "aws_iam_role_policy_attachment" "prisma_cloud_iam_role_use_prisma_cloud_iam_read_only_policy" {
  role       = aws_iam_role.prisma_cloud_iam_role.name
  policy_arn = aws_iam_policy.prisma_cloud_iam_read_only_policy.arn
}

resource "aws_iam_role_policy_attachment" "prisma_cloud_iam_role_use_prisma_cloud_iam_read_only_policy_elastic_beanstalk" {
  role       = aws_iam_role.prisma_cloud_iam_role.name
  policy_arn = aws_iam_policy.prisma_cloud_iam_read_only_policy_elastic_beanstalk.arn
}

resource "aws_iam_role_policy_attachment" "prisma_cloud_iam_role_use_prisma_cloud_iam_read_only_policy_compute" {
  role       = aws_iam_role.prisma_cloud_iam_role.name
  policy_arn = aws_iam_policy.prisma_cloud_iam_read_only_policy_compute.arn
}

resource "aws_iam_role_policy_attachment" "prisma_cloud_iam_role_use_prisma_cloud_iam_remediation_policy" {
  count = var.is_read_only ? 0 : 1
  role       = aws_iam_role.prisma_cloud_iam_role.name
  policy_arn = aws_iam_policy.prisma_cloud_iam_remediation_policy.arn
}

resource "aws_iam_role_policy_attachment" "prisma_cloud_iam_role_use_prisma_cloud_iam_remediation_policy_compute" {
  count = var.is_read_only ? 0 : 1
  role       = aws_iam_role.prisma_cloud_iam_role.name
  policy_arn = aws_iam_policy.prisma_cloud_iam_remediation_policy_compute.arn
}