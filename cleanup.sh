#!/bin/bash

SOURCE_REPOSITORY=$PWD
STACK_NAME=batch-test

REGION=$(aws ec2 describe-availability-zones --output text --query 'AvailabilityZones[0].[RegionName]')

echo 'Deleting Amazon ECR data'
aws ecr batch-delete-image --repository-name $STACK_NAME-repository --image-ids imageTag=latest
aws ecr batch-delete-image --repository-name $STACK_NAME-repository --image-ids imageTag=untagged

echo 'cleaning up the CloudFormation Stack'
aws cloudformation delete-stack --stack-name $STACK_NAME

echo 'CloudFormation Stack - '$STACK_NAME 'delete initiated successfully!'