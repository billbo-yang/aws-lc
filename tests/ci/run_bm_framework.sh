#!/bin/bash
set -exo pipefail
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# start ec2 instances
instance_id=$(aws ec2 describe-instances --filters Name="instance.group-name",Values="bm_framework_sg" --query Reservations[*].Instances[*].[InstanceId] --output text)
aws ec2 start-instances --instance-ids "${instance_id}"

# wait until we've detected uploads to the s3 (for now just sleep 30 seconds)
sleep 30

# stop ec2 instances
aws ec2 stop-instances --instance-ids "${instance_id}"

# check correct s3 bucket results to see whether to pass/fail

# upload success failure messages to cloudwatch logs