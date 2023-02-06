

const InputJSON ={
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Amidelete",
            "Effect": "Allow",
            "Action": "ec2:DeregisterImage",
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalTag/UserName": [
                        "Rithwik@syscloudtech.com",
                        "adhithya@syscloudtech.com"
                    ]
                },
                
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                
            }
        },
        {
            "Sid": "ApplicationAutoscalingReadAccess",
            "Effect": "Allow",
            "Action": [
                "application-autoscaling:DescribeScalableTargets",
                "application-autoscaling:DescribeScalingActivities",
                "application-autoscaling:DescribeScalingPolicies",
                "application-autoscaling:DescribeScheduledActions",
                "application-autoscaling:RegisterScalableTarget"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "ASGForSpecificASGBasics",
            "Effect": "Allow",
            "Action": [
                "autoscaling:AttachInstances",
                "autoscaling:AttachLoadBalancers",
                "autoscaling:CancelInstanceRefresh",
                "autoscaling:DescribeAccountLimits",
                "autoscaling:DescribeAutoScalingGroups",
                "autoscaling:DescribeLoadBalancers",
                "autoscaling:DescribeMetricCollectionTypes",
                "autoscaling:DescribePolicies",
                "autoscaling:DescribeTags",
                "autoscaling:DescribeWarmPool",
                "autoscaling:ExecutePolicy",
                "autoscaling:PutScalingPolicy",
                "autoscaling:PutScheduledUpdateGroupAction",
                "autoscaling:PutWarmPool",
                "autoscaling:ResumeProcesses",
                "autoscaling:SetDesiredCapacity",
                "autoscaling:SetInstanceProtection",
                "autoscaling:TerminateInstanceInAutoScalingGroup",
                "autoscaling:UpdateAutoScalingGroup"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:ResourceTag/Project": [
                        "Backup",
                        "microservices"
                    ]
                },
                
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                
            }
        },
        {
            "Sid": "AutoscalingReadAccess",
            "Effect": "Allow",
            "Action": [
                "autoscaling:Describe*"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "CloudFormationRead",
            "Effect": "Allow",
            "Action": [
                "cloudformation:Describe*",
                "cloudformation:List*"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "CloudFormationWriteAccess",
            "Effect": "Allow",
            "Action": [
                "cloudformation:Get*",
                "cloudformation:UpdateStack"
            ],
            "Resource": [
                "arn:aws:cloudformation:*:*:stack/BK*/*",
                "arn:aws:cloudformation:*:*:stack/Pseudo*/*",
                "arn:aws:cloudformation:*:*:stackset/BK*:*",
                "arn:aws:cloudformation:*:*:stackset/Pseudo*:*"
            ]
        },
        {
            "Sid": "CloudShellFUllAcces",
            "Effect": "Allow",
            "Action": "cloudshell:*",
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalTag/UserName": [
                        "Vikas@syscloudtech.com",
                        "nitish@syscloudtech.com",
                        "navdeep@syscloudtech.com"
                    ],
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                
                }
            }
        },
        {
            "Sid": "CloudwatchSpecificReadAccess",
            "Effect": "Allow",
            "Action": [
                "cloudwatch:DescribeAlarmHistory",
                "cloudwatch:DescribeAlarms",
                "cloudwatch:EnableAlarmActions",
                "cloudwatch:Get*",
                "cloudwatch:PutDashboard",
                "cloudwatch:PutMetricAlarm",
                "cloudwatch:SetAlarmState"
            ],
            "Resource": [
                "*"
            ],
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "CodeBuildReadAccess",
            "Effect": "Allow",
            "Action": [
                "codebuild:ListBuilds",
                "codebuild:ListBuildsForProject",
                "codebuild:ListProjects",
                "codebuild:ListReports",
                "codebuild:ListRepositories"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "CodebuildWriteAccess",
            "Effect": "Allow",
            "Action": [
                "codebuild:BatchGetBuilds",
                "codebuild:BatchGetProjects",
                "codebuild:CreateProject",
                "codebuild:RetryBuild",
                "codebuild:StartBuild",
                "codebuild:StopBuild",
                "codebuild:UpdateProject"
            ],
            "Resource": [
                "arn:aws:codebuild:*:*:project/AWScliUsage",
                "arn:aws:codebuild:*:*:project/ToGetAppspec"
            ]
        },
        {
            "Sid": "CodeCommitForSpecificRead",
            "Effect": "Allow",
            "Action": [
                "codecommit:BatchGetPullRequests",
                "codecommit:CreateBranch",
                "codecommit:CreateCommit",
                "codecommit:CreatePullRequest",
                "codecommit:Get*",
                "codecommit:GitPull",
                "codecommit:GitPush",
                "codecommit:ListBranches",
                "codecommit:ListPullRequests",
                "codecommit:PutFile"
            ],
            "Resource": [
                "arn:aws:codecommit:us-east-1:538782569624:CloudBackupCode",
                "arn:aws:codecommit:us-east-1:538782569624:LustreAPI",
                "arn:aws:codecommit:us-east-1:538782569624:UnifiedBackup",
                "arn:aws:codecommit:us-east-1:538782569624:lustre-mount-js",
                "arn:aws:codecommit:us-east-1:724493240358:Automation",
                "arn:aws:codecommit:us-east-1:724493240358:CloudBackupCode",
                "arn:aws:codecommit:us-east-1:724493240358:CloudMover*",
                "arn:aws:codecommit:us-east-1:724493240358:LustreAPI",
                "arn:aws:codecommit:us-east-1:724493240358:TERRAFORM-AUTOMATION",
                "arn:aws:codecommit:us-east-1:724493240358:UnifiedBackup"
            ]
        },
        {
            "Sid": "CodeCommitList",
            "Effect": "Allow",
            "Action": [
                "codecommit:List*"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "CodedeployReadAccess",
            "Effect": "Allow",
            "Action": [
                "codedeploy:BatchGet*",
                "codedeploy:Get*",
                "codedeploy:List*"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "CodePipelineReadAccess",
            "Effect": "Allow",
            "Action": [
                "codepipeline:GetActionType",
                "codepipeline:GetActionType",
                "codepipeline:List*"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "CodePipelineReadSpecificAccess",
            "Effect": "Allow",
            "Action": [
                "codepipeline:DisableStageTransition",
                "codepipeline:EnableStageTransition",
                "codepipeline:Get*",
                "codepipeline:GetPipeline",
                "codepipeline:ListPipelineExecutions",
                "codepipeline:PutApprovalResult",
                "codepipeline:RetryStageExecution",
                "codepipeline:StartPipelineExecution",
                "codepipeline:StopPipelineExecution",
                "codepipeline:UpdatePipeline"
            ],
            "Resource": [
                "arn:aws:codepipeline:*:538782569624:U*",
                "arn:aws:codepipeline:*:724493240358:U*",
                "arn:aws:codepipeline:*:724493240358:cloudmover*",
                "arn:aws:codepipeline:us-east-1:*:BK_*",
                "arn:aws:codepipeline:us-east-1:*:Network*",
                "arn:aws:codepipeline:us-east-1:*:network*"
            ]
        },
        {
            "Sid": "Dynamodb1",
            "Effect": "Allow",
            "Action": [
                "dynamodb:DescribeLimits",
                "dynamodb:DescribeReservedCapacity",
                "dynamodb:DescribeReservedCapacityOfferings",
                "dynamodb:ListBackups",
                "dynamodb:ListContributorInsights",
                "dynamodb:ListExports",
                "dynamodb:ListGlobalTables",
                "dynamodb:ListImports",
                "dynamodb:ListStreams",
                "dynamodb:ListTables"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "dynamodbread",
            "Effect": "Allow",
            "Action": [
                "dynamodb:BatchGetItem",
                "dynamodb:Describe*",
                "dynamodb:GetItem",
                "dynamodb:List*",
                "dynamodb:PartiQLSelect",
                "dynamodb:Query",
                "dynamodb:Scan"
            ],
            "Resource": "arn:aws:dynamodb:us-east-1:*:table/unifiedBackup_Nodes_Cache"
        },
        {
            "Sid": "EC2CreateVolumes",
            "Effect": "Allow",
            "Action": "ec2:CreateVolume",
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalTag/UserName": [
                        "Ankit@syscloudtech.com",
                        "adhithyan@syscloudtech.com"
                    ],
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "EC2ForGeneralEC2Basics",
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "ec2:Get*",
                "ec2:ModifyInstanceAttribute",
                "ec2:RebootInstances",
                "ec2:Search*",
                "ec2:StartInstances",
                "ec2:StopInstances"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:ResourceTag/Project": [
                        "Backup",
                        "backup"
                    ],
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
                },
            
        },
        {
            "Sid": "EC2ForSpecificEC2Connect",
            "Effect": "Allow",
            "Action": "ec2-instance-connect:*",
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:ResourceTag/Project": "Backup"
                },
            }
        },
        {
            "Sid": "EC2ForSpecificImageManagement",
            "Effect": "Allow",
            "Action": [
                "ec2:CopyImage",
                "ec2:CreateImage",
                "ec2:DescribeImages",
                "ec2:ModifyImageAttribute",
                "ec2:ResetImageAttribute"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "EC2ForSpecificVolumeManagement",
            "Effect": "Allow",
            "Action": [
                "ec2:AttachVolume",
                "ec2:CreateVolume",
                "ec2:DeleteVolume",
                "ec2:DescribeVolumeStatus",
                "ec2:DescribeVolumes",
                "ec2:DetachVolume",
                "ec2:ModifyVolume",
                "ec2:RebootInstances"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:ResourceTag/Project": "Backup"
                }
            }
        },
        {
            "Sid": "Ec2ReadAccess",
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "ec2:List*"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "EC2TaggingPermission",
            "Effect": "Allow",
            "Action": [
                "ec2:CreateTags",
                "ec2:DeleteTags",
                "ec2:DescribeAvailabilityZones",
                "ec2:DescribeScheduledInstanceAvailability",
                "ec2:ModifyAvailabilityZoneGroup"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "ecsreadaccess",
            "Effect": "Allow",
            "Action": [
                "ecs:DescribeClusters",
                "ecs:DescribeTaskDefinition",
                "ecs:ListAccountSettings",
                "ecs:ListClusters",
                "ecs:ListServices",
                "ecs:ListTasks",
                "ecs:ListTaskDefinitionFamilies",
                "ecs:ListTaskDefinitions"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "ecsSpecificAccess",
            "Effect": "Allow",
            "Action": [
                "ecs:Describe*",
                "ecs:List*",
                "ecs:Update*"
            ],
            "Resource": [
                "arn:aws:ecs:*:*:cluster/unified*",
                "arn:aws:ecs:*:*:service/unified*",
                "arn:aws:ecs:*:*:service/unified*/*",
                "arn:aws:ecs:*:*:task/unified*/*",
                "arn:aws:ecs:us-east-1:*:cluster/Secretsmanager",
                "arn:aws:ecs:*:*:*/CLOUDMOVER*",
                "arn:aws:ecs:*:*:*/CLOUDMOVER*/*",
                "arn:aws:ecs:us-east-1:*:*/network-drive-api",
                "arn:aws:ecs:us-east-1:724493240358:cluster/IncrementalQueuePopulation",
                "arn:aws:ecs:us-east-1:*:cluster/JobManager",
                "arn:aws:ecs:us-east-1:*:service/IncrementalQueuePopulation/IncrementalQueuePopulation",
                "arn:aws:ecs:us-east-1:*:service/JobManager/JobManager",
                "arn:aws:ecs:us-east-1:*:service/Secretsmanager/Secretsmanager",
                "arn:aws:ecs:us-east-1:*:service/network-drive-api*/network-drive-api*"
            ]
        },
        {
            "Sid": "elasticsearchREadAccess",
            "Effect": "Allow",
            "Action": [
                "es:List*"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "ElasticSearchSpecificAccess",
            "Effect": "Allow",
            "Action": [
                "es:DescribeDomain",
                "es:DescribeDomains",
                "es:DescribeElasticsearchDomains"
            ],
            "Resource": [
                "arn:aws:es:*:*:domain/CloudOps",
                "arn:aws:es:*:*:domain/cloudops*"
            ]
        },
        {
            "Sid": "ELBRead",
            "Effect": "Allow",
            "Action": "elasticloadbalancing:Describe*",
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "EventsReadAccess",
            "Effect": "Allow",
            "Action": [
                "events:List*"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "FSxForSpecificDescribe",
            "Effect": "Allow",
            "Action": [
                "fsx:Describe*"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:ResourceTag/Platform": [
                        "O365",
                        "Google"
                    ],
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "FsxReadAccess",
            "Effect": "Allow",
            "Action": [
                "fsx:DescribeFileSystems",
                "fsx:List*"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "IAMListRoles",
            "Effect": "Allow",
            "Action": [
                "iam:ListRoles",
                "iam:PassRole"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "LambdaInvokeAccess",
            "Effect": "Allow",
            "Action": [
                "lambda:Get*",
                "lambda:InvokeAsync",
                "lambda:InvokeFunction"
            ],
            "Resource": [
                "arn:aws:lambda:us-east-1:538782569624:function:deleteDocumentsDataFromDynamoDB",
                "arn:aws:lambda:us-east-1:724493240358:function:Alpha-*",
                "arn:aws:lambda:us-east-1:724493240358:function:CodeDeployCF",
                "arn:aws:lambda:us-east-1:724493240358:function:RestoreExportEtaAlert",
                "arn:aws:lambda:us-east-1:724493240358:function:SetMinMaxtoZeroASG",
                "arn:aws:lambda:us-east-1:724493240358:function:UpdateLustreIDInBOD-Sls",
                "arn:aws:lambda:us-east-1:724493240358:function:createnewfunctions",
                "arn:aws:lambda:us-east-1:724493240358:function:deleteDocumentsDataFromDynamoDB",
                "arn:aws:lambda:us-east-1:724493240358:function:restoreASGMinMax"
            ]
        },
        {
            "Sid": "LambdaReadAccess",
            "Effect": "Allow",
            "Action": [
                "lambda:GetAccountSettings",
                "lambda:List*"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "LOgsReadAccess",
            "Effect": "Allow",
            "Action": [
                "logs:Describe*",
                "logs:Get*",
                "logs:FilterLogEvents"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "OpenSearchReadAccess",
            "Effect": "Allow",
            "Action": [
                "es:Describe*",
                "es:Get*",
                "es:List*"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "OPenSearchUpgradeaccess",
            "Effect": "Allow",
            "Action": [
                "es:UpdateDomainConfig",
                "es:UpdateElasticsearchDomainConfig",
                "es:UpgradeDomain",
                "es:UpgradeElasticsearchDomain"
            ],
            "Resource": "arn:aws:es:us-east-1:*:domain/cloudops-new"
        },
        {
            "Sid": "route53specificaccess",
            "Effect": "Allow",
            "Action": [
                "route53:CreateHostedZone",
                "route53:GetHostedZoneCount",
                "route53:List*",
                "route53:ListHostedZonesByVPC"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalTag/UserName": "Burma@syscloudtech.com",
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "Route53SpecificAccess",
            "Effect": "Allow",
            "Action": [
                "route53:AssociateVPCWithHostedZone",
                "route53:DeleteHostedZone",
                "route53:DisassociateVPCFromHostedZone",
                "route53:EnableHostedZoneDNSSEC",
                "route53:GetHostedZone",
                "route53:ListTrafficPolicyInstancesByHostedZone",
                "route53:UpdateHostedZoneComment"
            ],
            "Resource": "arn:aws:route53:::hostedzone/Z10299918JYBFLJCLFE5",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalTag/UserName": "Burma@syscloudtech.com"
                }
            }
        },
        {
            "Sid": "S3GlacierReadAccess",
            "Effect": "Allow",
            "Action": [
                "glacier:GetDataRetrievalPolicy",
                "glacier:ListProvisionedCapacity",
                "glacier:ListVaults"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalTag/UserName": [
                        "Ankit@syscloudtech.com",
                        "Mukund@syscloudtech.com",
                        "Burma@syscloudtech.com",
                        "Vikas@syscloudtech.com",
                        "adhithyan@syscloudtech.com",
                        "navdeep@syscloudtech.com",
                        "roshan@syscloudtech.com",
                        "santhosh@syscloudtech.com",
                        "Rithwik@syscloudtech.com"
                    ],
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "s3GlaciervaultsreadAccess",
            "Effect": "Allow",
            "Action": [
                "glacier:DescribeJob",
                "glacier:DescribeVault",
                "glacier:GetJobOutput",
                "glacier:GetVaultAccessPolicy",
                "glacier:GetVaultLock",
                "glacier:GetVaultNotifications",
                "glacier:ListJobs",
                "glacier:ListMultipartUploads",
                "glacier:ListParts",
                "glacier:ListTagsForVault"
            ],
            "Resource": [
                "arn:aws:glacier:us-east-1:538782569624:vaults/*",
                "arn:aws:glacier:us-east-1:724493240358:vaults/*"
            ],
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalTag/UserName": [
                        "Ankit@syscloudtech.com",
                        "Mukund@syscloudtech.com"
                    ],
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "s3listbucketaccess",
            "Effect": "Allow",
            "Action": "s3:List*",
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "S3ReadWriteAccess",
            "Effect": "Allow",
            "Action": [
                "s3:GetBucketAcl",
                "s3:GetBucketCORS",
                "s3:GetBucketLocation",
                "s3:GetBucketLogging",
                "s3:GetBucketNotification",
                "s3:GetBucketObjectLockConfiguration",
                "s3:GetBucketOwnershipControls",
                "s3:GetBucketPolicy",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketRequestPayment",
                "s3:GetBucketTagging",
                "s3:GetBucketVersioning",
                "s3:GetBucketWebsite",
                "s3:ListBucket",
                "s3:ListBucketMultipartUploads",
                "s3:ListBucketVersions",
                "s3:PutBucketAcl",
                "s3:PutBucketCORS",
                "s3:PutBucketLogging",
                "s3:PutBucketNotification",
                "s3:PutBucketObjectLockConfiguration",
                "s3:PutBucketOwnershipControls",
                "s3:PutBucketPolicy",
                "s3:PutBucketPublicAccessBlock",
                "s3:PutBucketRequestPayment",
                "s3:PutBucketTagging",
                "s3:PutBucketVersioning"
            ],
            "Resource": [
                "arn:aws:s3:::awscli-files*",
                "arn:aws:s3:::syscloud-downloads",
                "arn:aws:s3:::syscloud-downloads/export/"
            ]
        },
        {
            "Sid": "SNSREADACCESS",
            "Effect": "Allow",
            "Action": [
                "sns:Get*",
                "sns:List*"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "SQSReadAccess",
            "Effect": "Allow",
            "Action": [
                "sqs:GetQueueAttributes",
                "sqs:GetQueueUrl",
                "sqs:ListDeadLetterSourceQueues",
                "sqs:ListQueueTags",
                "sqs:ListQueues",
                "sqs:ReceiveMessage"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "SSMForSpecificEC2Connect",
            "Effect": "Allow",
            "Action": [
                "ssm:DescribeInstanceInformation",
                "ssm:GetConnectionStatus",
                "ssm:StartSession",
                "ssm:TerminateSession"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:ResourceTag/Project": [
                        "Backup",
                        "microservices"
                    ]
                }
            }
        },
        {
            "Sid": "SSMForSpecificEC2Connect1",
            "Effect": "Allow",
            "Action": [
                "ssm:DescribeInstanceInformation",
                "ssm:GetConnectionStatus",
                "ssm:StartSession",
                "ssm:TerminateSession"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:ResourceTag/Name": [
                        "Unified*",
                        "cloud*"
                    ]
                }
            }
        },
        {
            "Sid": "SSMForSpecificEC2Connect3",
            "Effect": "Allow",
            "Action": [
                "ssm:DescribeInstanceInformation",
                "ssm:GetConnectionStatus",
                "ssm:StartSession",
                "ssm:TerminateSession"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:ResourceTag/Key": "Deployment*",
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "SSMParaMeterStoreAccess",
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameter",
                "ssm:GetParameterHistory",
                "ssm:GetParameters",
                "ssm:GetParametersByPath",
                "ssm:LabelParameterVersion",
                "ssm:PutParameter",
                "ssm:UnlabelParameterVersion"
            ],
            "Resource": [
                "arn:aws:ecs:*:538782569624:cluster/BK_*",
                "arn:aws:ecs:*:538782569624:cluster/IncrementalQueuePopulation",
                "arn:aws:ecs:*:538782569624:cluster/JobManager",
                "arn:aws:ecs:*:538782569624:cluster/Secretsmanager",
                "arn:aws:ecs:*:538782569624:cluster/network-drive-api",
                "arn:aws:ecs:*:724493240358:cluster/BK_*",
                "arn:aws:ecs:*:724493240358:cluster/IncrementalQueuePopulation",
                "arn:aws:ecs:*:724493240358:cluster/JobManager",
                "arn:aws:ecs:*:724493240358:cluster/Secretsmanager",
                "arn:aws:ecs:*:724493240358:cluster/network-drive-api",
                "arn:aws:ssm:*:*:parameter/UnifiedBackup*",
                "arn:aws:ssm:*:538782569624:parameter/ASG_Name/Instance_type,",
                "arn:aws:ssm:*:538782569624:parameter/ASG_Name/ami",
                "arn:aws:ssm:*:538782569624:parameter/BK_*",
                "arn:aws:ssm:*:538782569624:parameter/Config/Backup/*",
                "arn:aws:ssm:*:538782569624:parameter/Config/Backup/Google",
                "arn:aws:ssm:*:538782569624:parameter/Config/Backup/Google/FeedSync",
                "arn:aws:ssm:*:538782569624:parameter/Config/Backup/Google/OtherService",
                "arn:aws:ssm:*:538782569624:parameter/Config/Backup/O365",
                "arn:aws:ssm:*:*:parameter/ASG_Name/Instance_type,",
                "arn:aws:ssm:*:*:parameter/ASG_Name/ami",
                "arn:aws:ssm:*:*:parameter/BK_*",
                "arn:aws:ssm:*:*:parameter/CLOUDMOVER/*/*",
                "arn:aws:ssm:*:*:parameter/Config*/*",
                "arn:aws:ssm:*:*:parameter/Config/*/*",
                "arn:aws:ssm:*:*:parameter/Config/Backup/Google",
                "arn:aws:ssm:*:*:parameter/Config/Backup/Google/FeedSync",
                "arn:aws:ssm:*:*:parameter/Config/Backup/Google/OtherService",
                "arn:aws:ssm:*:*:parameter/Config/Backup/O365"
            ]
        },
        {
            "Sid": "SSmRead",
            "Effect": "Allow",
            "Action": [
                "ssm:Describe*"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        },
        {
            "Sid": "statemachineSpecificAccess",
            "Effect": "Allow",
            "Action": [
                "states:DescribeExecution",
                "states:DescribeStateMachine",
                "states:DescribeStateMachineForExecution",
                "states:GetExecutionHistory",
                "states:ListExecutions",
                "states:StartExecution",
                "states:StopExecution"
            ],
            "Resource": [
                "arn:aws:states:*:*:execution:CreateAMIAndUpdateStack:*",
                "arn:aws:states:*:*:execution:LustreResize:*",
                "arn:aws:states:*:*:execution:lustreCreation:*",
                "arn:aws:states:*:*:execution:lustreDeletion:*",
                "arn:aws:states:*:*:execution:lustreReplacement:*",
                "arn:aws:states:*:*:stateMachine:CreateAMIAndUpdateStack",
                "arn:aws:states:*:*:stateMachine:LustreResize",
                "arn:aws:states:*:*:stateMachine:lustreCreation",
                "arn:aws:states:*:*:stateMachine:lustreDeletion",
                "arn:aws:states:*:*:stateMachine:lustreReplacement"
            ]
        },
        {
            "Sid": "StatesMachineReadAccess",
            "Effect": "Allow",
            "Action": [
                "states:ListStateMachines"
            ],
            "Resource": "*",
            "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalAccount": [
                        "538782569624",
                        "724493240358",
                        "849689826459"
                    ]
                }
            }
        }
    ]
}
     
// separating Array part to process it differently
const StatementArray = InputJSON.Statement;

// sorting array according to 'Sid' key's values alphabetically
let sortedArray= StatementArray.sort(function(a, b) {
   return a.Sid.localeCompare(b.Sid);
});

// sorting Actions and Resources values alphabetically inside Array internally
sortedArray.map((obj)=>{
  if(Array.isArray(obj.Action)){
  obj.Action.sort();
  }
  if(Array.isArray(obj.Resource)){
    obj.Resource.sort();
  }
})

// copy of Input JSON to show results 
let SortedJSON = {...InputJSON}
SortedJSON.Statement = sortedArray;

// Log to console
// console.log(sortedArray)
console.log(JSON.stringify(SortedJSON));