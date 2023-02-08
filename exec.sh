#!/bin/bash

STACK_NAME=batch-test
REGION=$(aws ec2 describe-availability-zones --output text --query 'AvailabilityZones[0].[RegionName]')
SOURCE_REPOSITORY=$PWD
cd $SOURCE_REPOSITORY/src
echo ' Updating the Amazon ECR with the code'
docker build -t script .
docker tag script $(aws sts get-caller-identity --query 'Account' --output text).dkr.ecr.$REGION.amazonaws.com/$STACK_NAME-repository
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $(aws sts get-caller-identity --query 'Account' --output text).dkr.ecr.$REGION.amazonaws.com
docker push $(aws sts get-caller-identity --query 'Account' --output text).dkr.ecr.$REGION.amazonaws.com/$STACK_NAME-repository
aws batch submit-job --job-name test --job-queue $STACK_NAME-queue --job-definition $STACK_NAME-BatchJobDefinition