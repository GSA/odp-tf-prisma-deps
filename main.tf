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
	"access-analyzer:GetAnalyzer",
        "access-analyzer:ListAnalyzers",
        "account:GetAlternateContact",
        "account:GetContactInformation",
        "acm-pca:GetPolicy",
        "acm-pca:ListCertificateAuthorities",
        "acm-pca:ListTags",
        "airflow:GetEnvironment",
        "airflow:ListEnvironments",
        "amplify:ListApps",
        "apigateway:GET",
        "appflow:DescribeFlow",
        "appflow:ListFlows",
        "apprunner:DescribeAutoScalingConfiguration",
        "apprunner:DescribeCustomDomains",
        "apprunner:DescribeService",
        "apprunner:ListAutoScalingConfigurations",
        "apprunner:ListServices",
        "apprunner:ListTagsForResource",
        "appstream:DescribeFleets",
        "appstream:DescribeImages",
        "appstream:DescribeStacks",
        "appstream:DescribeUsageReportSubscriptions",
        "appstream:ListTagsForResource",
        "appsync:GetGraphqlApi",
        "aps:DescribeLoggingConfiguration",
        "aps:ListWorkspaces"
        "auditmanager:GetAssessment",
        "auditmanager:GetControl",
        "backup:GetBackupPlan",
        "backup:GetBackupVaultAccessPolicy",
        "backup:ListBackupPlans",
        "backup:ListBackupVaults",
        "backup:ListProtectedResources",
        "backup:ListTags",
        "batch:DescribeJobQueues",
        "budgets:ViewBudget",
        "ce:GetCostAndUsage",
        "chime:GetVoiceConnectorLoggingConfiguration",
        "cloud9:ListTagsForResource",
        "cloudhsm:DescribeClusters",
        "cloudsearch:ListTags",
        "cloudwatch:ListTagsForResource",
        "codeartifact:DescribeDomain",
        "codeartifact:DescribeRepository",
        "codeartifact:GetDomainPermissionsPolicy",
        "codeartifact:GetRepositoryPermissionsPolicy",
        "codeartifact:ListDomains",
        "codeartifact:ListRepositories",
        "codeartifact:ListTagsForResource",
        "codebuild:BatchGetProjects",
        "codebuild:ListSourceCredentials",
        "codecommit:GetApprovalRuleTemplate",
        "codepipeline:ListTagsForResource",
        "codepipeline:ListWebhooks",
        "cognito-identity:DescribeIdentityPool",
        "cognito-identity:ListTagsForResource",
        "cognito-idp:ListResourcesForWebACL",
        "cognito-idp:ListTagsForResource",
        "comprehendmedical:ListEntitiesDetectionV2Jobs",
        "connect:ListInstanceAttributes",
        "connect:ListInstances",
        "connect:ListInstanceStorageConfigs",
        "databrew:DescribeJob",
        "detective:ListDatasourcePackages",
        "devops-guru:DescribeServiceIntegration",
        "drs:DescribeJobs",
        "drs:DescribeSourceServers",
        "drs:GetReplicationConfiguration",
        "ds:ListTagsForResource",
        "dynamodb:ListTagsOfResource",
        "ec2:GetEbsEncryptionByDefault",
        "ec2:GetLaunchTemplateData",
        "ec2:SearchTransitGatewayRoutes",
        "ecr-public:ListTagsForResource",
        "ecr:DescribeImages",
        "ecr:DescribePullThroughCacheRules",
        "ecr:GetLifecyclePolicy",
        "ecr:GetRegistryScanningConfiguration",
        "ecr:ListTagsForResource",
        "eks:DescribeFargateProfile",
        "eks:ListFargateProfiles",
        "eks:ListTagsForResource",
        "elasticache:ListTagsForResource",
        "elasticbeanstalk:ListTagsForResource",
        "elasticfilesystem:DescribeFileSystemPolicy",
        "elasticfilesystem:DescribeTags",
        "elasticmapreduce:GetBlockPublicAccessConfiguration",
        "elasticmapreduce:ListSecurityConfigurations",
        "es:ListTags",
        "fms:GetAdminAccount",
        "fms:GetPolicy",
        "forecast:DescribeAutoPredictor",
        "forecast:DescribeDataset",
        "forecast:DescribePredictor",
        "forecast:ListPredictors",
        "forecast:ListTagsForResource",
        "glacier:GetVaultLock",
        "glacier:ListTagsForVault",
        "glue:GetConnection",
        "glue:GetConnections",
        "glue:GetCrawler",
        "glue:GetSchema",
        "glue:GetSecurityConfigurations",
        "glue:ListCrawlers",
        "glue:ListSchemas",
        "grafana:DescribeWorkspace",
        "grafana:DescribeWorkspaceAuthentication",
        "grafana:ListWorkspaces",
        "guardduty:DescribeOrganizationConfiguration",
        "imagebuilder:GetComponent",
        "imagebuilder:GetImagePipeline",
        "imagebuilder:GetImageRecipe",
        "imagebuilder:GetInfrastructureConfiguration",
        "imagebuilder:ListComponents",
        "imagebuilder:ListImagePipelines",
        "imagebuilder:ListImageRecipes",
        "imagebuilder:ListInfrastructureConfigurations",
        "iotanalytics:ListDatastores",
        "iotanalytics:ListTagsForResource",
        "iotfleetwise:ListSignalCatalogs",
        "kafka:ListClusters",
        "kinesisanalytics:DescribeApplication",
        "kinesisanalytics:ListTagsForResource",
        "lakeformation:GetDataLakeSettings",
        "lambda:GetFunctionUrlConfig",
        "lex:DescribeBot",
        "lex:DescribeBotVersion",
        "lex:GetBot",
        "lex:GetBots",
        "lex:GetBotVersions",
        "lex:ListBots",
        "lex:ListBotVersions",
        "lex:ListTagsForResource",
        "logs:GetLogEvents",
        "macie2:GetClassificationExportConfiguration",
        "macie2:GetFindingsPublicationConfiguration",
        "macie2:GetMacieSession",
        "macie2:GetRevealConfiguration",
        "macie2:ListOrganizationAdminAccounts",
        "mediastore:GetCorsPolicy",
        "mediastore:ListTagsForResource",
        "memorydb:DescribeClusters",
        "memorydb:DescribeParameterGroups",
        "memorydb:DescribeParameters",
        "memorydb:ListTags",
        "mgn:DescribeLaunchConfigurationTemplates",
        "mobiletargeting:GetApps",
        "mobiletargeting:GetEmailChannel",
        "mobiletargeting:GetSmsChannel",
        "mq:describeBroker",
        "mq:listBrokers",
        "opsworks:DescribeUserProfiles",
        "polly:DescribeVoices",
        "polly:ListSpeechSynthesisTasks",
        "qldb:DescribeLedger",
        "qldb:ListLedgers",
        "qldb:ListTagsForResource",
        "ram:GetResourceShares",
        "resiliencehub:ListApps",
        "s3:DescribeJob",
        "s3:GetJobTagging",
        "s3:ListJobs",
        "servicecatalog:ListApplications",
        "servicecatalog:ListAttributeGroups",
        "servicecatalog:ListPortfolios",
        "servicediscovery:ListNamespaces",
        "shield:GetSubscriptionState",
        "sns:ListPlatformApplications",
        "sns:listSubscriptions",
        "sns:ListTagsForResource",
        "ssm:GetDocument",
        "ssm:GetInventory",
        "ssm:GetInventorySchema",
        "ssm:GetParameters",
        "ssm:ListTagsForResource",
        "states:DescribeStateMachine",
        "states:ListTagsForResource",
        "storagegateway:DescribeChapCredentials",
        "storagegateway:DescribeSMBFileShares",
        "storagegateway:DescribeSMBSettings",
        "support:DescribeCases",
        "swf:ListDomains",
        "transcribe:ListLanguageModels",
        "transcribe:ListTagsForResource",
        "translate:GetTerminology",
        "waf-regional:GetIPSet",
        "waf-regional:GetLoggingConfiguration",
        "waf-regional:ListIPSets",
        "waf-regional:ListResourcesForWebACL",
        "waf-regional:ListTagsForResource",
        "waf:GetIPSet",
        "waf:GetLoggingConfiguration",
        "waf:GetWebACL",
        "waf:ListIPSets",
        "waf:ListTagsForResource",
        "wafv2:GetIPSet",
        "wafv2:GetLoggingConfiguration",
        "wafv2:GetRuleGroup",
        "wafv2:GetWebACL",
        "wafv2:ListResourcesForWebACL",
        "wafv2:ListTagsForResource",
        "wafv2:ListWebACLs",
        "wellarchitected:GetWorkload",
        "wellarchitected:ListWorkloads"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_policy" "prisma-cloud-iam-read-only-policy-2" {
  name        = "prisma-cloud-iam-read-only-policy-2"
  path        = "/"
  description = ""
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PrismaCloudConfig2",
      "Action": [
        "acm:DescribeCertificate",
        "acm:ListCertificates",
        "acm:ListTagsForCertificate",
        "appconfig:ListApplications",
        "appconfig:ListConfigurationProfiles",
        "appconfig:ListEnvironments",
        "application-autoscaling:DescribeScalingPolicies",
        "appmesh:DescribeMesh",
        "appmesh:DescribeVirtualGateway",
        "appmesh:ListMeshes",
        "appmesh:ListTagsForResource",
        "appmesh:ListVirtualGateways",
        "appstream:DescribeImageBuilders",
        "appsync:ListGraphqlApis",
        "athena:GetWorkGroup",
        "athena:ListWorkGroups",
        "auditmanager:ListAssessments",
        "auditmanager:ListControls",
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:DescribeLaunchConfigurations",
        "batch:DescribeComputeEnvironments",
        "batch:DescribeJobDefinitions",
        "bedrock:GetAgent",
        "bedrock:GetCustomModel",
        "bedrock:GetFoundationModel",
        "bedrock:GetKnowledgeBase",
        "bedrock:GetModelCustomizationJob",
        "bedrock:GetModelInvocationLoggingConfiguration",
        "bedrock:GetProvisionedModelThroughput",
        "bedrock:ListAgents",
        "bedrock:ListCustomModels",
        "bedrock:ListFoundationModels",
        "bedrock:ListKnowledgeBases",
        "bedrock:ListModelCustomizationJobs",
        "bedrock:ListProvisionedModelThroughputs",
        "bedrock:ListTagsForResource",
        "chime:ListVoiceConnectors",
        "cloud9:DescribeEnvironmentMemberships",
        "cloud9:DescribeEnvironments",
        "cloud9:ListEnvironments",
        "cloudformation:DescribeStackResources",
        "cloudformation:DescribeStacks",
        "cloudformation:GetStackPolicy",
        "cloudformation:GetTemplate",
        "cloudformation:ListStackResources",
        "cloudformation:ListStacks",
        "cloudfront:GetDistributionConfig",
        "cloudfront:GetResponseHeadersPolicy",
        "cloudfront:ListDistributionsByWebACLId",
        "cloudfront:ListOriginAccessControls",
        "cloudfront:ListResponseHeadersPolicies",
        "cloudfront:ListTagsForResource",
        "cloudsearch:DescribeDomains",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:ListTags",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:DescribeInsightRules",
        "codebuild:ListProjects",
        "codecommit:GetRepository",
        "codecommit:ListApprovalRuleTemplates",
        "codecommit:ListRepositories",
        "codedeploy:BatchGetDeploymentTargets",
        "codedeploy:ListDeploymentTargets",
        "codedeploy:ListDeployments",
        "codepipeline:GetPipeline",
        "codepipeline:ListPipelines",
        "cognito-identity:ListIdentityPools",
        "cognito-idp:DescribeUserPoolClient",
        "cognito-idp:ListUserPoolClients",
        "cognito-idp:ListUserPools",
        "cognito-sync:ListIdentityPoolUsage",
        "comprehend:DescribeFlywheel",
        "comprehend:ListDocumentClassifierSummaries",
        "comprehend:ListEntitiesDetectionJobs",
        "comprehend:ListFlywheels",
        "comprehend:ListKeyPhrasesDetectionJobs",
        "comprehend:ListPiiEntitiesDetectionJobs",
        "comprehend:ListSentimentDetectionJobs",
        "comprehend:ListTagsForResource",
        "comprehend:ListTargetedSentimentDetectionJobs",
        "config:DescribeConfigRules",
        "config:DescribeConfigurationAggregators",
        "config:DescribeConfigurationRecorderStatus",
        "config:DescribeDeliveryChannels",
        "config:GetComplianceDetailsByConfigRule",
        "config:ListTagsForResource",
        "controltower:GetLandingZone",
        "controltower:ListLandingZones",
        "controltower:ListTagsForResource",
        "datapipeline:DescribePipelines",
        "datapipeline:GetPipelineDefinition",
        "datapipeline:ListPipelines",
        "datasync:DescribeAgent",
        "datasync:DescribeLocationEfs",
        "datasync:DescribeLocationFsxLustre",
        "datasync:DescribeLocationFsxOntap",
        "datasync:DescribeLocationFsxOpenZfs",
        "datasync:DescribeLocationFsxWindows",
        "datasync:DescribeLocationHdfs",
        "datasync:DescribeLocationNfs",
        "datasync:DescribeLocationObjectStorage"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_policy" "prisma-cloud-iam-read-only-policy-3" {
  name        = "prisma-cloud-iam-read-only-policy-3"
  path        = "/"
  description = ""
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PrismaCloudConfig3",
      "Action": [
        "datasync:DescribeLocationS3",
        "datasync:DescribeLocationSmb",
        "datasync:DescribeTask",
        "datasync:DescribeTaskExecution",
        "datasync:ListAgents",
        "datasync:ListLocations",
        "datasync:ListTagsForResource",
        "datasync:ListTaskExecutions",
        "datasync:ListTasks",
        "datazone:GetDataSource",
        "datazone:GetDomain",
        "datazone:ListDataSources",
        "datazone:ListDomains",
        "datazone:ListProjects",
        "dax:DescribeClusters",
        "dax:DescribeParameterGroups",
        "dax:DescribeParameters",
        "dax:ListTags",
        "detective:ListGraphs",
        "devicefarm:ListProjects",
        "directconnect:DescribeConnections",
        "directconnect:DescribeDirectConnectGateways",
        "directconnect:DescribeVirtualInterfaces",
        "dlm:GetLifecyclePolicies",
        "dlm:GetLifecyclePolicy",
        "dms:DescribeCertificates",
        "dms:DescribeEndpoints",
        "dms:DescribeReplicationInstances",
        "dms:DescribeReplicationTasks",
        "dms:ListTagsForResource",
        "drs:DescribeSourceNetworks",
        "ds:DescribeDirectories",
        "dynamodb:DescribeContinuousBackups",
        "dynamodb:DescribeTable",
        "dynamodb:GetResourcePolicy",
        "dynamodb:ListTables",
        "ec2:DescribeAccountAttributes",
        "ec2:DescribeAddresses",
        "ec2:DescribeClientVpnAuthorizationRules",
        "ec2:DescribeClientVpnEndpoints",
        "ec2:DescribeCustomerGateways",
        "ec2:DescribeDhcpOptions",
        "ec2:DescribeEgressOnlyInternetGateways",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeImages",
        "ec2:DescribeInstanceAttribute",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeIpams",
        "ec2:DescribeKeyPairs",
        "ec2:DescribeManagedPrefixLists",
        "ec2:DescribeNatGateways",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeNetworkInsightsAnalyses",
        "ec2:DescribeNetworkInterfaceAttribute",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeRegions",
        "ec2:DescribeReservedInstances",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshotAttribute",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeTags",
        "ec2:DescribeTrafficMirrorSessions",
        "ec2:DescribeTransitGatewayAttachments",
        "ec2:DescribeTransitGatewayRouteTables",
        "ec2:DescribeTransitGatewayVpcAttachments",
        "ec2:DescribeTransitGateways",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcEndpointConnectionNotifications",
        "ec2:DescribeVpcEndpointServiceConfigurations",
        "ec2:DescribeVpcEndpointServicePermissions",
        "ec2:DescribeVpcEndpointServices",
        "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeVpcs",
        "ec2:DescribeVpnConnections",
        "ec2:DescribeVpnGateways",
        "ec2:GetManagedPrefixListEntries",
        "ecr-public:DescribeRegistries",
        "ecr-public:DescribeRepositories",
        "ecr-public:GetRegistryCatalogData",
        "ecr-public:GetRepositoryCatalogData",
        "ecr-public:GetRepositoryPolicy",
        "ecr:DescribeRepositories",
        "ecr:GetRepositoryPolicy",
        "ecs:DescribeClusters",
        "ecs:DescribeContainerInstances",
        "ecs:DescribeServices",
        "ecs:DescribeTaskDefinition",
        "ecs:DescribeTasks",
        "ecs:ListClusters",
        "ecs:ListContainerInstances",
        "ecs:ListServices",
        "ecs:ListTagsForResource",
        "ecs:ListTaskDefinitions",
        "ecs:ListTasks",
        "eks:DescribeCluster",
        "eks:DescribeNodegroup",
        "eks:ListClusters",
        "eks:ListNodegroups",
        "elasticache:DescribeCacheClusters",
        "elasticache:DescribeCacheEngineVersions",
        "elasticache:DescribeCacheSubnetGroups",
        "elasticache:DescribeReplicationGroups",
        "elasticache:DescribeReservedCacheNodes",
        "elasticache:DescribeSnapshots",
        "elasticache:DescribeUsers",
        "elasticfilesystem:DescribeAccessPoints",
        "elasticfilesystem:DescribeBackupPolicy",
        "elasticfilesystem:DescribeFileSystems",
        "elasticfilesystem:DescribeMountTargetSecurityGroups",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "elasticloadbalancing:DescribeLoadBalancerPolicies",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeRules",
        "elasticloadbalancing:DescribeSSLPolicies",
        "elasticloadbalancing:DescribeTags",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "elasticmapreduce:DescribeCluster",
        "elasticmapreduce:DescribeSecurityConfiguration",
        "elasticmapreduce:DescribeStudio",
        "elasticmapreduce:ListClusters",
        "elasticmapreduce:ListInstances",
        "elasticmapreduce:ListStudios",
        "elastictranscoder:ListPipelines",
        "emr-serverless:GetApplication",
        "emr-serverless:ListApplications",
        "es:DescribeElasticsearchDomains",
        "es:ListDomainNames",
        "events:DescribeArchive",
        "events:DescribeConnection",
        "events:ListApiDestinations",
        "events:ListArchives",
        "events:ListConnections",
        "events:ListEventBuses",
        "events:ListRules",
        "events:ListTagsForResource",
        "events:ListTargetsByRule",
        "firehose:DescribeDeliveryStream"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_policy" "prisma-cloud-iam-read-only-policy-4" {
  name        = "prisma-cloud-iam-read-only-policy-4"
  path        = "/"
  description = ""
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PrismaCloudConfig4",
      "Action": [
        "firehose:ListDeliveryStreams",
        "firehose:ListTagsForDeliveryStream",
        "fis:GetExperiment",
        "fis:GetExperimentTemplate",
        "fis:ListExperimentTemplates",
        "fis:ListExperiments",
        "fms:ListComplianceStatus",
        "fms:ListPolicies",
        "forecast:ListDatasets",
        "fsx:DescribeBackups",
        "fsx:DescribeFileSystems",
        "glacier:GetVaultAccessPolicy",
        "glacier:ListVaults",
        "globalaccelerator:DescribeAcceleratorAttributes",
        "globalaccelerator:ListAccelerators",
        "globalaccelerator:ListTagsForResource",
        "glue:GetDataCatalogEncryptionSettings",
        "glue:GetDatabases",
        "glue:GetJobs",
        "glue:GetResourcePolicies",
        "glue:GetTriggers",
        "greengrass:ListCoreDefinitions",
        "guardduty:GetDetector",
        "guardduty:GetFindings",
        "guardduty:GetMasterAccount",
        "guardduty:ListDetectors",
        "guardduty:ListFindings",
        "iam:GenerateCredentialReport",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:GetAccountAuthorizationDetails",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:GetCredentialReport",
        "iam:GetGroupPolicy",
        "iam:GetOpenIDConnectProvider",
        "iam:GetPolicyVersion",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:GetSAMLProvider",
        "iam:GetServiceLastAccessedDetails",
        "iam:GetUserPolicy",
        "iam:ListAccessKeys",
        "iam:ListAttachedGroupPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListEntitiesForPolicy",
        "iam:ListGroupPolicies",
        "iam:ListGroups",
        "iam:ListGroupsForUser",
        "iam:ListInstanceProfilesForRole",
        "iam:ListMFADeviceTags",
        "iam:ListMFADevices",
        "iam:ListOpenIDConnectProviders",
        "iam:ListPolicies",
        "iam:ListPolicyTags",
        "iam:ListPolicyVersions",
        "iam:ListRolePolicies",
        "iam:ListRoleTags",
        "iam:ListRoles",
        "iam:ListSAMLProviderTags",
        "iam:ListSAMLProviders",
        "iam:ListSSHPublicKeys",
        "iam:ListServerCertificateTags",
        "iam:ListServerCertificates",
        "iam:ListUserPolicies",
        "iam:ListUserTags",
        "iam:ListUsers",
        "iam:ListVirtualMFADevices",
        "inspector2:ListAccountPermissions",
        "inspector2:ListCoverage",
        "inspector2:ListFilters",
        "inspector2:ListFindings",
        "inspector:DescribeAssessmentTemplates",
        "inspector:DescribeFindings",
        "inspector:DescribeRulesPackages",
        "inspector:ListAssessmentRunAgents",
        "inspector:ListAssessmentRuns",
        "inspector:ListAssessmentTemplates",
        "inspector:ListFindings",
        "inspector:ListRulesPackages",
        "iot:DescribeAccountAuditConfiguration",
        "iot:DescribeDomainConfiguration",
        "iot:ListDomainConfigurations",
        "iot:ListTagsForResource",
        "iotanalytics:ListChannels",
        "iotevents:ListInputs",
        "ivs:GetChannel",
        "ivs:ListChannels",
        "kafka:DescribeVpcConnection",
        "kafka:ListVpcConnections",
        "kendra:DescribeIndex",
        "kinesis:DescribeStream",
        "kinesis:ListStreams",
        "kinesis:ListTagsForStream",
        "kinesisanalytics:ListApplications",
        "kinesisvideo:DescribeNotificationConfiguration",
        "kinesisvideo:ListStreams",
        "kinesisvideo:ListTagsForStream",
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListAliases",
        "kms:ListGrants",
        "kms:ListKeyPolicies",
        "kms:ListKeys",
        "kms:ListResourceTags",
        "lakeformation:DescribeLakeFormationIdentityCenterConfiguration",
        "lakeformation:DescribeResource",
        "lakeformation:GetLFTag",
        "lakeformation:ListLFTags",
        "lakeformation:ListPermissions",
        "lakeformation:ListResources",
        "lambda:GetLayerVersionPolicy",
        "lambda:GetPolicy",
        "lambda:ListCodeSigningConfigs",
        "lambda:ListFunctions",
        "lambda:ListLayerVersions",
        "lambda:ListLayers",
        "lambda:ListTags",
        "lightsail:GetBuckets",
        "lightsail:GetDisks",
        "lightsail:GetInstances",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:DescribeMetricFilters",
        "logs:DescribeSubscriptionFilters",
        "logs:GetLogDelivery",
        "logs:ListLogDeliveries",
        "logs:ListTagsLogGroup",
        "lookoutequipment:ListDatasets",
        "lookoutmetrics:ListAnomalyDetectors",
        "lookoutvision:ListProjects",
        "macie2:ListClassificationJobs",
        "managedblockchain:ListNetworks",
        "mediastore:GetContainerPolicy",
        "mediastore:GetCorsPolicy",
        "mediastore:ListContainers",
        "memorydb:DescribeSnapshots",
        "memorydb:DescribeSubnetGroups",
        "mgh:DescribeHomeRegionControls"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_policy" "prisma-cloud-iam-read-only-policy-5" {
  name        = "prisma-cloud-iam-read-only-policy-5"
  path        = "/"
  description = ""
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PrismaCloudConfig5",
      "Action": [
        "mgn:DescribeReplicationConfigurationTemplates",
        "mgn:DescribeSourceServers",
        "network-firewall:DescribeFirewall",
        "network-firewall:DescribeFirewallPolicy",
        "network-firewall:DescribeLoggingConfiguration",
        "network-firewall:DescribeResourcePolicy",
        "network-firewall:ListFirewallPolicies",
        "network-firewall:ListFirewalls",
        "network-firewall:ListRuleGroups",
        "networkmanager:DescribeGlobalNetworks",
        "networkmanager:GetCoreNetwork",
        "networkmanager:GetSites",
        "networkmanager:ListCoreNetworks",
        "organizations:DescribeAccount",
        "organizations:DescribeOrganization",
        "quicksight:DescribeAccountSettings",
        "quicksight:DescribeIpRestriction",
        "quicksight:ListDataSets",
        "quicksight:ListDataSources",
        "quicksight:ListTagsForResource",
        "ram:ListPrincipals",
        "ram:ListResources",
        "rbin:GetRule",
        "rbin:ListRules",
        "rbin:ListTagsForResource",
        "rds:DescribeDBClusterParameterGroups",
        "rds:DescribeDBClusterParameters",
        "rds:DescribeDBClusterSnapshotAttributes",
        "rds:DescribeDBClusterSnapshots",
        "rds:DescribeDBClusters",
        "rds:DescribeDBInstances",
        "rds:DescribeDBParameterGroups",
        "rds:DescribeDBParameters",
        "rds:DescribeDBSnapshotAttributes",
        "rds:DescribeDBSnapshots",
        "rds:DescribeEventSubscriptions",
        "rds:DescribeOptionGroups",
        "rds:ListTagsForResource",
        "redshift-serverless:ListWorkgroups",
        "redshift:DescribeClusterParameters",
        "redshift:DescribeClusters",
        "redshift:DescribeLoggingStatus",
        "route53:GetDNSSEC",
        "route53:GetHealthCheck",
        "route53:ListHealthChecks",
        "route53:ListHostedZones",
        "route53:ListQueryLoggingConfigs",
        "route53:ListResourceRecordSets",
        "route53:ListTagsForResource",
        "route53domains:GetDomainDetail",
        "route53domains:ListDomains",
        "route53domains:ListTagsForDomain",
        "route53resolver:ListResolverEndpoints",
        "route53resolver:ListResolverQueryLogConfigAssociations",
        "route53resolver:ListResolverQueryLogConfigs",
        "route53resolver:ListTagsForResource",
        "s3:GetAccelerateConfiguration",
        "s3:GetAccessPoint",
        "s3:GetAccessPointPolicy",
        "s3:GetAccessPointPolicyStatus",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:GetBucketCORS",
        "s3:GetBucketLocation",
        "s3:GetBucketLogging",
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetBucketOwnershipControls",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketTagging",
        "s3:GetBucketVersioning",
        "s3:GetBucketWebsite",
        "s3:GetEncryptionConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:GetReplicationConfiguration",
        "s3:ListAccessPoints",
        "s3:ListAllMyBuckets",
        "s3:ListMultiRegionAccessPoints",
        "sagemaker:DescribeCodeRepository",
        "sagemaker:DescribeDomain",
        "sagemaker:DescribeEndpoint",
        "sagemaker:DescribeEndpointConfig",
        "sagemaker:DescribeLabelingJob",
        "sagemaker:DescribeModel",
        "sagemaker:DescribeNotebookInstance",
        "sagemaker:DescribeNotebookInstanceLifecycleConfig",
        "sagemaker:DescribeProcessingJob",
        "sagemaker:DescribeTrainingJob",
        "sagemaker:DescribeUserProfile",
        "sagemaker:ListCodeRepositories",
        "sagemaker:ListDomains",
        "sagemaker:ListEndpointConfigs",
        "sagemaker:ListEndpoints",
        "sagemaker:ListLabelingJobs",
        "sagemaker:ListModels",
        "sagemaker:ListNotebookInstanceLifecycleConfigs",
        "sagemaker:ListNotebookInstances",
        "sagemaker:ListProcessingJobs",
        "sagemaker:ListTags",
        "sagemaker:ListTrainingJobs",
        "sagemaker:ListUserProfiles",
        "secretsmanager:DescribeSecret",
        "secretsmanager:GetResourcePolicy",
        "secretsmanager:ListSecrets",
        "securityhub:DescribeHub",
        "securityhub:DescribeStandards",
        "securityhub:GetEnabledStandards",
        "securityhub:ListEnabledProductsForImport",
        "serverlessrepo:GetApplicationPolicy",
        "serverlessrepo:ListApplications",
        "servicecatalog:DescribePortfolioShares",
        "servicecatalog:ListPrincipalsForPortfolio",
        "servicecatalog:SearchProducts",
        "servicecatalog:SearchProductsAsAdmin",
        "ses:DescribeConfigurationSet",
        "ses:DescribeReceiptRuleSet",
        "ses:GetIdentityDkimAttributes",
        "ses:GetIdentityPolicies",
        "ses:GetIdentityVerificationAttributes",
        "ses:ListConfigurationSets",
        "ses:ListIdentities",
        "ses:ListIdentityPolicies",
        "ses:ListReceiptRuleSets",
        "shield:DescribeDRTAccess",
        "shield:ListProtectionGroups",
        "shield:ListProtections",
        "shield:ListResourcesInProtectionGroup",
        "shield:ListTagsForResource",
        "signer:DescribeSigningJob",
        "signer:ListSigningJobs",
        "sns:GetDataProtectionPolicy",
        "sns:GetTopicAttributes",
        "sns:ListTopics",
        "sqs:GetQueueAttributes",
        "sqs:ListQueueTags",
        "sqs:ListQueues",
        "ssm:DescribeActivations",
        "ssm:DescribeAssociation",
        "ssm:DescribeDocument",
        "ssm:DescribeDocumentPermission",
        "ssm:DescribeInstanceInformation",
        "ssm:DescribeParameters",
        "ssm:DescribePatchBaselines",
        "ssm:DescribeSessions",
        "ssm:GetPatchBaseline",
        "ssm:GetServiceSetting",
        "ssm:ListAssociations",
        "ssm:ListDocuments",
        "ssm:ListInventoryEntries",
        "ssm:ListResourceComplianceSummaries",
        "sso:DescribeApplication",
        "sso:DescribePermissionSet",
        "sso:ListAccountAssignments",
        "sso:ListAccountsForProvisionedPermissionSet",
        "sso:ListInstances",
        "sso:ListPermissionSets"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_policy" "prisma-cloud-iam-read-only-policy-6" {
  name        = "prisma-cloud-iam-read-only-policy-6"
  path        = "/"
  description = ""
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PrismaCloudConfig6",
      "Action": [
        "states:ListActivities",
        "states:ListStateMachines",
        "storagegateway:DescribeCachediSCSIVolumes",
        "storagegateway:DescribeGatewayInformation",
        "storagegateway:DescribeNFSFileShares",
        "storagegateway:DescribeTapes",
        "storagegateway:ListFileShares",
        "storagegateway:ListGateways",
        "storagegateway:ListTapes",
        "storagegateway:ListVolumes",
        "tag:DescribeReportCreation",
        "tag:GetComplianceSummary",
        "transcribe:GetTranscriptionJob",
        "transcribe:ListLanguageModels",
        "transcribe:ListTagsForResource",
        "transcribe:ListTranscriptionJobs",
        "transfer:DescribeAccess",
        "transfer:DescribeSecurityPolicy",
        "transfer:DescribeServer",
        "transfer:DescribeUser",
        "transfer:ListAccesses",
        "transfer:ListServers",
        "transfer:ListUsers",
        "translate:ListTerminologies",
        "waf-regional:GetWebACL",
        "waf-regional:ListWebACLs",
        "waf:ListWebACLs",
        "wafv2:ListIPSets",
        "wafv2:ListRuleGroups",
        "workspaces:DescribeIpGroups",
        "workspaces:DescribeTags",
        "workspaces:DescribeWorkspaceBundles",
        "workspaces:DescribeWorkspaceDirectories",
        "workspaces:DescribeWorkspaces",
        "xray:GetEncryptionConfig"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_policy" "prisma_cloud_iam_read_only_policy_all" {
  name        = "prisma-cloud-iam-read-only-policy-all"
  path        = "/"
  description = ""
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequiredForAwsElasticbeanstalkConfigurationSettingsApiIngestion",
      "Action": [
        "airflow:GetEnvironment",
        "amplify:ListApps",
        "appflow:DescribeFlow",
        "appstream:DescribeStacks",
        "appstream:DescribeUsageReportSubscriptions",
        "appstream:DescribeImages",
        "appstream:DescribeFleets",
        "appstream:ListTagsForResource",
        "appsync:GetGraphqlApi",
        "aps:DescribeLoggingConfiguration",
        "aps:ListWorkspaces",
        "backup:ListBackupPlans",
        "backup:GetBackupPlan",
        "ce:GetCostAndUsage",
        "chime:GetVoiceConnectorLoggingConfiguration",
        "cloud9:ListTagsForResource",
        "cloudhsm:DescribeClusters",
        "codeartifact:ListTagsForResource",
        "codeartifact:DescribeRepository",
        "codeartifact:DescribeDomain",
        "codeartifact:ListDomains",
        "codepipeline:ListTagsForResource",
        "cognito-idp:ListResourcesForWebACL",
        "comprehendmedical:ListEntitiesDetectionV2Jobs",
        "connect:ListInstanceAttributes",
        "connect:ListInstanceStorageConfigs",
        "databrew:DescribeJob",
        "databrew:ListJobs",
        "devops-guru:DescribeServiceIntegration",
        "ecr:GetRegistryPolicy",
        "ecr:DescribeRegistry",
        "ecr:DescribePullThroughCacheRules",
        "fms:GetPolicy",
        "fms:GetAdminAccount",
        "forecast:DescribePredictor",
        "forecast:DescribeDataset",
        "forecast:DescribeAutoPredictor",
        "forecast:ListTagsForResource",
        "forecast:ListPredictors",
        "glue:GetConnection",
        "grafana:DescribeWorkspace",
        "grafana:DescribeWorkspaceAuthentication",
        "identitystore:ListGroupMemberships",
        "identitystore:ListUsers",
        "identitystore:ListGroups",
        "iotanalytics:ListTagsForResource",
        "iotanalytics:ListDatastores",
        "iotfleetwise:ListSignalCatalogs",
        "kendra:ListTagsForResource",
        "kinesisanalytics:ListTagsForResource",
        "kinesisanalytics:DescribeApplication",
        "lakeformation:GetDataLakeSettings",
        "lambda:GetFunctionUrlConfig",
        "lex:ListBotVersions",
        "lex:GetBot",
        "lex:GetBots",
        "lex:GetBotVersions",
        "lex:DescribeBotVersion",
        "lex:ListTagsForResource",
        "macie2:GetClassificationExportConfiguration",
        "macie2:GetMacieSession",
        "macie2:GetRevealConfiguration",
        "macie2:GetFindingsPublicationConfiguration",
        "macie2:ListOrganizationAdminAccounts",
        "mediastore:ListTagsForResource",
        "memorydb:DescribeParameters",
        "memorydb:DescribeParameterGroups",
        "memorydb:ListTags",
        "mobiletargeting:GetEmailChannel",
        "mobiletargeting:GetSmsChannel",
        "mobiletargeting:GetApps",
        "opsworks:DescribeUserProfiles",
        "polly:DescribeVoices",
        "qldb:ListTagsForResource",
        "resiliencehub:ListApps",
        "servicecatalog:ListPortfolios",
        "servicecatalog:ListApplications",
        "servicecatalog:ListAttributeGroups",
        "servicediscovery:ListNamespaces",
        "states:ListTagsForResource",
        "storagegateway:DescribeSMBSettings",
        "storagegateway:DescribeSMBFileShares",
        "support:DescribeCases",
        "swf:ListDomains",
        "translate:GetTerminology"        
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

resource "aws_iam_role_policy_attachment" "prisma_cloud_iam_role_use_prisma_cloud_iam_read_only_policy_all" {
  role       = aws_iam_role.prisma_cloud_iam_role.name
  policy_arn = aws_iam_policy.prisma_cloud_iam_read_only_policy_all.arn
}

output "prisma_role_arn" {
  value = aws_iam_role.prisma_cloud_iam_role.arn
}
