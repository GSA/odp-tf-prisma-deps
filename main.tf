locals  {
  role_name = "PrismaCloudAwsOrgMonitoringRole"
}

resource "aws_iam_policy" "prisma_cloud_iam_read_only_policy" {
  name        = "prisma-cloud-iam-read-only-policy"
  path        = "/"
  description = ""
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
                    "account:GetAlternateContact",
                    "apigateway:GET",
                    "acm-pca:ListTags",
                    "acm-pca:GetPolicy",
                    "acm-pca:ListCertificateAuthorities",
                    "airflow:GetEnvironment",
                    "airflow:ListEnvironments",
                    "appstream:DescribeStacks",
                    "appstream:DescribeUsageReportSubscriptions",
                    "appstream:DescribeImages",
                    "appstream:DescribeFleets",
                    "appstream:ListTagsForResource",
                    "apprunner:DescribeAutoScalingConfiguration",
                    "apprunner:ListAutoScalingConfigurations",
                    "apprunner:ListTagsForResource",
                    "apprunner:ListServices",
                    "apprunner:DescribeCustomDomains",
                    "apprunner:DescribeService",
                    "appflow:DescribeFlow",
                    "appflow:ListFlows",
                    "amplify:ListApps",
                    "backup:ListBackupVaults",
                    "backup:ListTags",
                    "backup:GetBackupVaultAccessPolicy",
                    "cloudwatch:ListTagsForResource",
                    "cognito-identity:ListTagsForResource",
                    "cognito-identity:DescribeIdentityPool",
                    "cognito-idp:ListTagsForResource",
                    "codeartifact:ListDomains",
                    "codeartifact:DescribeDomain",
                    "codeartifact:GetDomainPermissionsPolicy",
                    "codeartifact:ListTagsForResource",
                    "codeartifact:ListRepositories",
                    "codeartifact:DescribeRepository",
                    "codeartifact:GetRepositoryPermissionsPolicy",
                    "connect:ListInstances",
                    "connect:ListInstanceStorageConfigs",
                    "connect:ListInstanceAttributes",
                    "devops-guru:DescribeServiceIntegration",
                    "ds:ListTagsForResource",
                    "dynamodb:ListTagsOfResource",
                    "ec2:GetEbsEncryptionByDefault",
                    "ec2:SearchTransitGatewayRoutes",
                    "ecr:DescribeImages",
                    "ecr:GetRegistryScanningConfiguration",
                    "ecr:GetLifecyclePolicy",
                    "ecr:ListTagsForResource",
                    "ecr-public:ListTagsForResource",
                    "eks:ListTagsForResource",
                    "eks:ListFargateProfiles",
                    "eks:DescribeFargateProfile",
                    "elasticbeanstalk:ListTagsForResource",
                    "elasticfilesystem:DescribeTags",
                    "elasticfilesystem:DescribeFileSystemPolicy",
                    "elasticache:ListTagsForResource",
                    "es:ListTags",
                    "glacier:GetVaultLock",
                    "glacier:ListTagsForVault",
                    "glue:GetConnections",
                    "glue:GetSecurityConfigurations",
                    "grafana:DescribeWorkspace",
                    "grafana:DescribeWorkspaceAuthentication",
                    "grafana:ListWorkspaces",
                    "kafka:ListClusters",
                    "kinesisanalytics:ListTagsForResource",
                    "kinesisanalytics:DescribeApplication",
                    "lambda:GetFunctionUrlConfig",
                    "lex:GetBot",
                    "lex:GetBots",
                    "lex:GetBotVersions",
                    "lex:ListTagsForResource",
                    "lex:ListBotVersions",
                    "lex:ListBots",
                    "lex:DescribeBotVersion",
                    "lex:DescribeBot",
                    "lakeformation:GetDataLakeSettings",
                    "logs:GetLogEvents",
                    "macie2:GetClassificationExportConfiguration",
                    "macie2:GetMacieSession",
                    "macie2:GetRevealConfiguration",
                    "macie2:GetFindingsPublicationConfiguration",
                    "memorydb:DescribeParameters",
                    "memorydb:DescribeParameterGroups",
                    "memorydb:ListTags",
                    "memorydb:DescribeClusters",
                    "mq:listBrokers",
                    "mq:describeBroker",
                    "mediastore:ListTagsForResource",
                    "mediastore:GetCorsPolicy",
                    "mobiletargeting:GetEmailChannel",
                    "mobiletargeting:GetSmsChannel",
                    "mobiletargeting:GetApps",
                    "ram:GetResourceShares",
                    "ssm:GetDocument",
                    "ssm:GetParameters",
                    "ssm:ListTagsForResource",
                    "transcribe:ListLanguageModels",
                    "transcribe:ListTagsForResource",
                    "elasticmapreduce:ListSecurityConfigurations",
                    "elasticmapreduce:GetBlockPublicAccessConfiguration",
                    "sns:listSubscriptions",
                    "sns:ListTagsForResource",
                    "sns:ListPlatformApplications",
                    "wafv2:ListResourcesForWebACL",
                    "wafv2:ListWebACLs",
                    "wafv2:ListTagsForResource",
                    "wafv2:GetWebACL",
                    "wafv2:GetLoggingConfiguration",
                    "waf:GetWebACL",
                    "waf:ListTagsForResource",
                    "waf:GetLoggingConfiguration",
                    "waf-regional:GetLoggingConfiguration",
                    "waf-regional:ListResourcesForWebACL",
                    "waf-regional:ListTagsForResource",
                    "codebuild:BatchGetProjects",
                    "s3:DescribeJob",
                    "s3:ListJobs",
                    "s3:GetJobTagging",
                    "ssm:GetInventory",
                    "shield:GetSubscriptionState",
                    "states:DescribeStateMachine",
                    "states:ListTagsForResource",
                    "storagegateway:DescribeSMBFileShares",
                    "storagegateway:DescribeSMBSettings",
                    "translate:GetTerminology",
                    "qldb:ListLedgers",
                    "qldb:DescribeLedger",
                    "qldb:ListTagsForResource"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}


resource "aws_iam_policy" "prisma_cloud_iam_read_only_policy_elastic_beanstalk" {
  name        = "prisma-cloud-iam-read-only-policy-elastic-beanstalk"
  path        = "/"
  description = ""
  policy      = <<EOF
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
  name        = "prisma-cloud-iam-read-only-policy-compute"
  path        = "/"
  description = ""
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:BatchGetImage",
                    "ecr:GetAuthorizationToken",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:GetLifecyclePolicyPreview",
                    "secretsmanager:GetSecretValue",
                    "lambda:GetLayerVersion",
                    "ssm:GetParameter",
                    "securityhub:BatchImportFindings",
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


resource "aws_iam_policy" "PrismaCloud-ReadOnly-Compute-Policy-EKS-Audit" {
  name        = "prisma-cloud-iam-read-only-policy-eks-audit"
  path        = "/"
  description = ""
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
                {
                  "Action": [
                    "logs:StartQuery",
                    "logs:GetQueryResults"
                  ],
                  "Effect": "Allow",
                  "Resource": "*"
                }
              ]
            }
EOF
}

resource "aws_iam_policy" "PrismaCloud-ReadOnly-Policy-Bridgecrew" {
  name        = "prisma-cloud-iam-read-only-policy-bridgecrew"
  path        = "/"
  description = ""
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
                {
                  "Action": [
                    "logs:StartQuery",
                    "logs:GetQueryResults"
                  ],
                  "Effect": "Allow",
                  "Resource": "*"
                }
              ]
            }
EOF
}




resource "aws_iam_policy" "prisma_cloud_iam_remediation_policy" {
  name        = "prisma-cloud-iam-remediation-policy"
  path        = "/"
  description = ""
  policy      = <<EOF
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
  name        = "prisma-cloud-iam-remediation-policy-compute"
  path        = "/"
  description = ""
  policy      = <<EOF
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
  name               = local.role_name
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${var.account_id}:root"
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

resource "aws_iam_role_policy_attachment" "prisma_cloud_iam_role_use_aws_managed_security_audit_policy" {
  role       = aws_iam_role.prisma_cloud_iam_role.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
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
  count      = var.is_read_only ? 0 : 1
  role       = aws_iam_role.prisma_cloud_iam_role.name
  policy_arn = aws_iam_policy.prisma_cloud_iam_remediation_policy.arn
}

resource "aws_iam_role_policy_attachment" "prisma_cloud_iam_role_use_prisma_cloud_iam_remediation_policy_compute" {
  count      = var.is_read_only ? 0 : 1
  role       = aws_iam_role.prisma_cloud_iam_role.name
  policy_arn = aws_iam_policy.prisma_cloud_iam_remediation_policy_compute.arn
}

output "prisma_role_arn" {
  value = aws_iam_role.prisma_cloud_iam_role.arn
}