# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from aws_cdk import core, aws_ec2 as ec2, aws_codebuild as codebuild, aws_iam as iam
from util.metadata import AWS_ACCOUNT, AWS_REGION, GITHUB_REPO_OWNER, GITHUB_REPO_NAME
from util.ecr_util import ecr_arn
from util.iam_policies import bm_framework_policy_in_json
from util.yml_loader import YmlLoader

# detailed documentation can be found here: https://docs.aws.amazon.com/cdk/api/latest/docs/aws-ec2-readme.html

class BmFrameworkStack(core.Stack):
    """Define a stack used to execute the AWS-LC benchmarking framework"""

    def __init__(self,
                 scope: core.Construct,
                 id: str,
                 ecr_repo_name: str,
                 spec_file_path: str,
                 **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Define CodeBuild resource.
        git_hub_source = codebuild.Source.git_hub(
            owner=GITHUB_REPO_OWNER,
            repo=GITHUB_REPO_NAME,
            webhook=True,
            webhook_filters=[
                codebuild.FilterGroup.in_event_of(
                    codebuild.EventAction.PULL_REQUEST_CREATED,
                    codebuild.EventAction.PULL_REQUEST_UPDATED,
                    codebuild.EventAction.PULL_REQUEST_REOPENED)
            ],
            clone_depth=1)

        # Define a IAM role for this stack.
        code_build_batch_policy = iam.PolicyDocument.from_json(bm_framework_policy_in_json())
        inline_policies = {"code_build_batch_policy": code_build_batch_policy}
        role = iam.Role(scope=self,
                        id="{}-role".format(id),
                        assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com"),
                        inline_policies=inline_policies)

        # Create build spec.
        placeholder_map = {"ECR_REPO_PLACEHOLDER": ecr_arn(ecr_repo_name)}
        build_spec_content = YmlLoader.load(spec_file_path, placeholder_map)

        # Define CodeBuild.
        project = codebuild.Project(
            scope=self,
            id=id,
            project_name=id,
            source=git_hub_source,
            role=role,
            timeout=core.Duration.minutes(180),
            environment=codebuild.BuildEnvironment(compute_type=codebuild.ComputeType.SMALL,
                                                   privileged=False,
                                                   build_image=codebuild.LinuxBuildImage.STANDARD_4_0),
            build_spec=codebuild.BuildSpec.from_object(build_spec_content))

        # TODO: add build type BUILD_BATCH when CFN finishes the feature release. See CryptoAlg-575.

        # Add 'BuildBatchConfig' property, which is not supported in CDK.
        # CDK raw overrides: https://docs.aws.amazon.com/cdk/latest/guide/cfn_layer.html#cfn_layer_raw
        # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html#aws-resource-codebuild-project-properties
        cfn_build = project.node.default_child
        cfn_build.add_override("Properties.BuildBatchConfig", {
            "ServiceRole": role.role_arn,
            "TimeoutInMins": 180
        })

        # NOTE: ALL BELOW IS FOR EC2 INSTANCES

        # create vpc for security
        vpc = ec2.Vpc(self, id='bm_framework_vpc')

        # create security group with default rules
        sec_group = ec2.SecurityGroup(self, id='bm_framework_sg',
                                    description='temp desc.',
                                    allow_all_outbound=True,
                                    vpc=vpc,
                                    security_group_name='bm_framework_sg')

        # We want Ubuntu 20.04 AMI for x86
        ubuntu2004 = ec2.MachineImage.generic_linux({
            "us-west-2": "ami-01773ce53581acf22"
        })

        # commands to run on startup
        startup_commands = 'mkdir test'

        # TODO: create vpc endpoint for s3 to connect to ec2s
        x86_ubuntu2004_clang7 = ec2.Instance(self, id='bm_framework_x86_ubuntu-20.04_clang7',
                                             instance_type=ec2.InstanceType("c5.metal"),
                                             machine_image=ubuntu2004,
                                             vpc=vpc,
                                             security_group=sec_group)
        x86_ubuntu2004_clang7.add_user_data(startup_commands)