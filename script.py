###*********************************************************
###*  AWS audit manager assesment report generator      *###
###*  version : 1                                       *###
###*********************************************************

'''
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''
###
# This script simplifies generation of assesment reports from AWS Audit Manager
# Following options/filters are provided for users to customize the assesment reports:

# 1. name (String)              : (required) name of the audit manager assesment for which the report is to be generated
# 2. filterAutomatic(Boolean)   : (optional) if set to 'True' excludes manual evidence from the assesment report, defaults to 'False'.
# 3. AccountIds(String)         : (optional) comma seperated AWS Accounts ids for which the report is to be generated, defaults to None
# 4. filterLatest(Boolean)      : (optional) if set to 'True' associates only lastest evidences to the assesment report, defaults to 'False'

# By default this script generates the assessment report with 'ALL' evidences.
# The Assesment report post generation would be generated and uploaded along with the evidences in the S3 bucket specified during the assesment creation

# Note:- once an assessment is created, Audit Manager continuously collects evidence across the selected resources in 1 or more AWS accounts.
# This process rapidly accumulates evidences, hence based on the options the user chooses and the evidences size, the report generation process may take time

# IAM Permissions required to execute the script:
#    auditmanager:BatchAssociateAssessmentReportEvidence
#    auditmanager:ListAssessments
#    auditmanager:GetAssessmentReportUrl
#    auditmanager:GetEvidenceByEvidenceFolder
#    auditmanager:GetEvidenceFoldersByAssessment
#    auditmanager:GetAccountStatus
#    auditmanager:ListAssessmentReports
#    auditmanager:CreateAssessmentReport
#    s3:PutObject
#    s3:GetObject
#    s3:ListBucket
#    s3:DeleteObject
#    s3:GetBucketLocation
#    s3:PutObjectAcl
#    sns:publish
# optional(if S3 bucket is enrypted)
#    kms:Decrypt
#    kms:Encrypt
#    kms:GenerateDataKey
# For more information to IAM Permissions please refer: https://docs.aws.amazon.com/audit-manager/latest/userguide/security_iam_id-based-policy-examples.html#full-administrator-access-assessment-report-destination
# General troubleshooting guide for assesment report generation failures: https://docs.aws.amazon.com/audit-manager/latest/userguide/assessment-report-issues.html
# AWS audit manager user guide : https://docs.aws.amazon.com/audit-manager/latest/userguide/what-is.html
###

# import statements
import logging
import boto3
import uuid
import argparse
import time
import json
import sys
import io
import csv
from botocore.exceptions import InvalidRegionError


#setting logger
LOGGER = logging.getLogger()
syslog = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s : %(message)s')
syslog.setFormatter(formatter)
LOGGER.setLevel(logging.INFO)
LOGGER.addHandler(syslog)

##**********************************MANUAL CONFIG*********************************************************************##

## Note:- It is recommended to use an environment which has AWS CLI configured:-
##        https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-config

# Region in which the audit manager is configured
# if provided will take presidence over region value provided during AWS CLI configure phase

REGION=None
# Credentials
AWS_ACCESS_KEY_ID=None
AWS_SECRET_ACCESS_KEY=None

##*******************************************************************************************************************##

# initializing audit manager client
try:
    # check for active credentials
    if boto3.session.Session().get_credentials() is None:
        LOGGER.error("boto3 was unable to get credentials from the environment")
        LOGGER.info("falling back to manual credentials")
        LOGGER.info('checking if credentials are provided in MANUAL CONFIG section of the script')   
        if REGION and AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:
            LOGGER.info('locally populated credentials found, attempting to instantiate boto3 client')
            client = boto3.client('auditmanager',region_name=REGION,
                aws_access_key_id = AWS_ACCESS_KEY_ID , aws_secret_access_key= AWS_SECRET_ACCESS_KEY )
            LOGGER.info('client creation complete')
        else:
            LOGGER.error("value(s) of : REGION, AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY  are missing")
            
    elif REGION:
        client = boto3.client('auditmanager',region_name=REGION)
    else:
        client = boto3.client('auditmanager')
except InvalidRegionError as invalidRegion:
    LOGGER.error(invalidRegion)
    LOGGER.error("please ensure the correct region is configured")
    LOGGER.error("exiting the program")
    #sys.exit(1)
except Exception as error:
    LOGGER.error(error)
    LOGGER.error("exiting the program")
    raise Exception("boto3 client instantiation failed")
    

#################################input parameters#################################

LOGGER.info("executing script")

# Initialize parser
parser = argparse.ArgumentParser(prog='python3 script.py', usage='%(prog)s [options] assessment report generator ',
    description='script aims to automate evidence association to help generate assesment reports',
    epilog='by default this script generates the assessment report with ALL evidences')


# Adding arguments
requiredNamed = parser.add_argument_group('required named arguments')
requiredNamed.add_argument('--name', type=str, action='store',dest='assesmentName' ,
help = "name of the audit manager assesment for which the report would be generated")
parser.add_argument('--filter_automatic', type=bool, action='store',dest='filterAutomaticEvidence' , choices=[True,False], default=False,
    help = "if set to \'True\' excludes manual evidence from the assesment report, defaults to \'False\'")
parser.add_argument('--account_Ids',  type=str, action='store',dest='filterAccountIds', default=None,
    help = "comma seperated AWS Accounts ids for which the report is to be generated, defaults to include all AWS Account Ids in Assesment scope")
parser.add_argument('--filter_latest', type=bool,  action='store',dest='filterLatestEvidence' , choices=[True,False], default=False,
    help = "if set to \'True\' associates only latest days evidences to the assesment report, defaults to \'False\'")

parser.add_argument('--sns_topic', type=str,  action='store',dest='snsTopic' ,
    help = "SnS Topic to which events are published")

# Read arguments from command line
args = parser.parse_args()

assessmentName=None
if args.assesmentName:
    assessmentName=args.assesmentName
else:
    LOGGER.error(" \'-- name\': name of the audit manager assesment for which the report would be generated is required")
    sys.exit(1)
    
filterAutomaticEvidence = args.filterAutomaticEvidence
if not args.filterAccountIds:
    filterAccountIds=['EMPTY']
else:
    filterAccountIds        = [args.filterAccountIds]

filterLatestEvidence    = args.filterLatestEvidence
snsTopic                = args.snsTopic
csvEvidenceList         = []

LOGGER.info( "parameters values : " + assessmentName + str(snsTopic) + str(filterAutomaticEvidence) +  str(filterAccountIds) + str(filterLatestEvidence) )

##################################################################################

def publish_to_sns_topic(message):
    sns = boto3.client('sns')
    try:
        sns.publish(TopicArn=snsTopic,
        Subject="audit manager report generator - " + str(assessmentName),
        Message=message)
    except Exception:
        LOGGER.exception("Couldn't publish message to %s.", snsTopic)


# generates assesment report
def create_assesment_report(Id):
    response = client.create_assessment_report(name=str(uuid.uuid4()) ,assessmentId=Id,
        description='This report is generated via evidence collector automation')
    return response


# filter evidence folders if latest flag is set
def get_latest_evidence_folders(evidenceFolders,Id):
    latestEvidenceFolders=[]
    evidenceFolders = sorted(evidenceFolders, key=lambda d: d['name'], reverse=True)
    name=evidenceFolders[0]['name']
    for evidenceFolder in evidenceFolders:
        if evidenceFolder['name'] == name:
            latestEvidenceFolders.append(evidenceFolder)
    return(latestEvidenceFolders)

# checks whether audit manager is in 'ACTIVE' state
def is_account_active():
    response = client.get_account_status()
    if response['status'] == "ACTIVE":
        return True
        
    return False

# gets assesment Id based on assesment name
def get_assesment_id():
    assessments = []
    token = None
    assessmentsResult = {}
    while True:
        if not token:
            assessmentsResult = client.list_assessments(status='ACTIVE')
        else:
            assessmentsResult = client.list_assessments(nextToken=token)
        assessments.extend(assessmentsResult)
        if 'nextToken' in assessmentsResult['assessmentMetadata']:
            token = assessmentsResult['assessmentMetadata']['nextToken']
        else:
            break
    for assessment in assessmentsResult['assessmentMetadata']:
        if assessment['name'] == assessmentName:
            return assessment['id']

# retrieves all evidence folders pertaining to the assesment            
def get_evidence_folders(Id):
    evidenceFolders = []
    token = None
    evidenceFoldersResult = {}
    
    while True:
        if not token:
            evidenceFoldersResult = client.get_evidence_folders_by_assessment(assessmentId=Id , maxResults=1000)
        else:
            evidenceFoldersResult = client.get_evidence_folders_by_assessment(assessmentId=Id, maxResults=1000, nextToken=token)
        evidenceFolders.extend(evidenceFoldersResult['evidenceFolders'])
        if 'nextToken' in evidenceFoldersResult:
            token = evidenceFoldersResult['nextToken']
        else:
            return evidenceFolders
    
# retrieves all evidences pertaining to the assesment    
def get_evidence_details(Id,evidenceFolder):
    evidences = []
    token = None
    evidencesResult = {}
    while True:
        LOGGER.info("retrieving evidence details ...")
        if not token:
            evidencesResult = client.get_evidence_by_evidence_folder(assessmentId=Id, controlSetId=evidenceFolder['controlSetId'],
                evidenceFolderId=evidenceFolder['id'], maxResults=1000)
        else:
            evidencesResult = client.get_evidence_by_evidence_folder(assessmentId=Id, controlSetId=evidenceFolder['controlSetId'],
                evidenceFolderId=evidenceFolder['id'],  maxResults=1000, nextToken=token)
        evidences.extend(evidencesResult['evidence'])
        if 'nextToken' in evidencesResult:
            token = evidencesResult['nextToken']
        else:
            evidencesList=[]
            for evidence in evidences:
                if evidence['complianceCheck'] == "NOT_APPLICABLE":
                    LOGGER.info("removing evidences where compliance check is not applicable")
                else:
                    evidencesList.append(evidence)
            return evidencesList

# filters evidences based on AWS Account Ids as provided in the input
def filter_evidences_by_accounts(evidenceDetails):
    evidences=[]
    for evidence in evidenceDetails:
        if evidence['evidenceAwsAccountId'] in filterAccountIds:
            evidences.extend([evidence])
    return evidences

# filters out 'Manual' evidence types    
def filter_evidences_by_type(evidenceDetails):
    evidences=[]
    for evidence in evidenceDetails:
        if evidence['evidenceByType'] and evidence['evidenceByType'] != 'Manual':
            evidences.extend([evidence])
    return evidences


# compiles evidences to add to the assesment report based on input parameters    
def filter_evidences(evidenceDetails):
    evidences=evidenceDetails
    if filterAccountIds != ['EMPTY']:
        evidences=filter_evidences_by_accounts(evidenceDetails)
        if filterAutomaticEvidence:
            evidences=filter_evidences_by_type(evidences)
    if filterAutomaticEvidence:
        evidences=filter_evidences_by_type(evidenceDetails)
        if filterAccountIds != ['EMPTY']:
            evidences=filter_evidences_by_accounts(evidenceDetails)
    return evidences

# adds processed evidences to report
def add_evidences_to_report(accesId,evidences,folderId):
    evidenceIdList=[]
    for evidence in evidences:
        evidenceIdList.append(evidence['id'])
    # max value allowed by the API
    maxItems=50
    evidenceIdList = [evidenceIdList[i * maxItems:(i + 1) * maxItems] for i in range((len(evidenceIdList) + maxItems - 1) // maxItems )]  
    for maxEvidenceIdList in evidenceIdList:
        LOGGER.info("associating processed evidences to assessment report")
        client.batch_associate_assessment_report_evidence(assessmentId=accesId, evidenceFolderId=folderId,evidenceIds=maxEvidenceIdList)
        # LOGGER.info("dissociateting now")
        # re=client.batch_disassociate_assessment_report_evidence(assessmentId=accesId, evidenceFolderId=folderId,evidenceIds=maxEvidenceIdList)
        # LOGGER.info(str(re))


# validates whether the assessment report is generated successfully
def get_assesment_reports():
    reports = []
    token = None
    reportResult = {}
    while True:
        if not token:
            reportResult = client.list_assessment_reports()
        else:
            reportResult = client.list_assessment_reports(nextToken=token)
        reports.extend(reportResult['assessmentReports'])
        if 'nextToken' in reportResult:
            token = reportResult['nextToken']
        else:
            return reports

# waits until the report is successfully generated
def check_assesment_report_status(reportId):
    timeCheck=False
    waitTme=30
    startTime = time.time()
    while True:
        if time.time() - startTime > waitTme:
            LOGGER.info("looks like report generation may take a while, exiting the script ")
            LOGGER.info("Note :- Audit manager would continue generating the report at the backend.")
            LOGGER.info("Once completed you can extract the report from the audit manager console/configured S3 bucket")
            sys.exit()
        assessmentReports=get_assesment_reports()
        for report in assessmentReports:
            if reportId == report['id'] and 'COMPLETE' == report['status']:
                return('COMPLETE')
            elif reportId == report['id'] and 'IN_PROGRESS' == report['status']:
                LOGGER.info("waiting for the report to generate..")
                time.sleep(10)
            elif reportId == report['id'] and 'FAILED' == report['status']:
                LOGGER.info("report generation failed")
                sys.exit()
            else:
                continue

#generates and returns the S3 signed URL
def generate_report_url(reportId,Id):
    response = client.get_assessment_report_url(
        assessmentReportId=reportId,assessmentId=Id)
    publish_to_sns_topic(str(response))
    return response

# associates an evidence folder to the assesment report
def associate_report_evidence_folder(Id,folderId):
    LOGGER.info("associating evidence folder with Id " + folderId)
    client.associate_assessment_report_evidence_folder(assessmentId=Id, evidenceFolderId=folderId)
    # LOGGER.info("dissociateting now")
    # re=client.disassociate_assessment_report_evidence_folder(assessmentId=Id, evidenceFolderId=folderId)
    # LOGGER.info(str(re))
    

# identifies whether filters are applied for the assessment report generation
def process_evidences(evidenceFolder,assesmentId):
    LOGGER.info("processing evidence folder with Id " + evidenceFolder['id'])

    if filterAutomaticEvidence or filterAccountIds != ['EMPTY']:
        LOGGER.info("processing evidences based on filters applied ")
        #compile evidence details
        evidenceDetails=get_evidence_details(assesmentId,evidenceFolder)
        #filter evidences base on input variables
        evidences= filter_evidences(evidenceDetails)
        # append filtered evidence details for csv
        csvEvidenceList.extend(evidences)  
        #add evidences to the audit report
        add_evidences_to_report(assesmentId,evidences,evidenceFolder['id'])
    else:
         # append evidences to the csv list
        evidenceDetails=get_evidence_details(assesmentId,evidenceFolder)
        csvEvidenceList.extend(evidenceDetails)
        # associate evidence folder with the assessment report     
        associate_report_evidence_folder(assesmentId,evidenceFolder['id'] )


#compile evidences into csv     
def compile_evidence_csv(assetList):
    """
    Converts the filtered evidences list to csv and returns a csv object
    :param assetList:formatted evidence details
    :return: csv object comprising of evidences data set
    """
    csvio = io.StringIO()
    writer = csv.writer(csvio)
    writer.writerow(['dataSource', 'evidenceAwsAccountId','eventSource','eventName','evidenceByType','resourcesIncluded','attributes', 'complianceCheck','evidenceFolderId','id'])
    for asset in assetList:
        writer.writerow([asset['dataSource'],asset['evidenceAwsAccountId'],asset['eventSource'],asset['eventName'],asset['evidenceByType'],asset['resourcesIncluded'],
        asset['attributes'],asset['complianceCheck'], asset['evidenceFolderId'],asset['id']])
    return(csvio)


# store the evicences csv to target s3 bucket
def put_report_to_s3(csvio,bucket,key):
    """
    exports the csv object to s3
    :param csvio:csv object
    :param key directory where the evidences are to be stored.
    """
    s3 = boto3.client('s3')
    s3.put_object(Body=csvio.getvalue(), ContentType='text/csv', Bucket=bucket, Key=key,ACL='bucket-owner-full-control')
    csvio.close()

def get_assessment_details(id):
    response = client.get_assessment(assessmentId=id)
    return(response)

def get_assessment_bucket(assessmentDetails):
    if "metadata" in assessmentDetails['assessment'] and "assessmentReportsDestination" in assessmentDetails['assessment']['metadata']:
        if assessmentDetails['assessment']['metadata']['assessmentReportsDestination']:
            if assessmentDetails['assessment']['metadata']['assessmentReportsDestination']['destinationType'] =="S3":
                bucketName=assessmentDetails['assessment']['metadata']['assessmentReportsDestination']['destination']
                return(bucketName.split("://",1)[1])

# entry point into the program
def main():
    try:
        #check if audit manager is active
        if is_account_active() :
            # get assesment id based on the assesment name provided as input
            assesmentId = get_assesment_id()
            if assesmentId:
                LOGGER.info(("assesment {} found with Id {}").format(assessmentName,assesmentId))
                #get evidence folders by assesment Id
                LOGGER.info("retrieving evidence details")
                evidenceFolders=get_evidence_folders(assesmentId)
                LOGGER.info("retrieving evidence details, this may take time depending upon the size of the assesment report")
                #filter evidence folders based on latest date
                if filterLatestEvidence:
                    evidenceFolders=get_latest_evidence_folders(evidenceFolders,assesmentId)
                LOGGER.info("total evidence folders to be processed " + str(len(evidenceFolders)))
                for evidenceFolder in evidenceFolders:
                    process_evidences(evidenceFolder,assesmentId)
                # generate assesment report
                LOGGER.info("generating report")
                response=create_assesment_report(assesmentId)
                #all csv evidence lists
                bucketName=get_assessment_bucket(get_assessment_details(assesmentId))
                if bucketName:
                    path="evidence_csv/"+assessmentName+"/"+response['assessmentReport']['id']+"/"+assessmentName
                    put_report_to_s3(compile_evidence_csv(csvEvidenceList),bucketName,path)
                    LOGGER.info("evidences excel workbook uploaded to : " + bucketName)
                    LOGGER.info("path " + path)
                else:
                     LOGGER.info("unable to extract the target S3 bucket, skipping upload of evidences excel workbook")
                LOGGER.info("Assessment Report Generation initiated, details are as follows : " + str(response['assessmentReport']))
                # check status of the report
                reportStatus=check_assesment_report_status(response['assessmentReport']['id'])
                if reportStatus:
                    #generating urls of the completed report
                    assesmentUrls=generate_report_url(response['assessmentReport']['id'],assesmentId)
                    LOGGER.info('URL details as follows : {}'.format(json.dumps(assesmentUrls['preSignedUrl'], default=str,indent=4)))
            else:
                raise Exception(("assessment {} not found").format(assessmentName))
    except Exception as e:
        LOGGER.error(" exception: {}".format(e))

if __name__ == '__main__':
    exit(main())