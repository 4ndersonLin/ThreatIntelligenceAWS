# IAM role permission requirement:
# * lambda basic excution policy
# * s3:GetObject
# * guardduty:Get*
# * guardduty:List*
# * guardduty:CreateThreatIntelSet
# * guardduty:UpdateThreatIntelSet
# * iam:PutRolePolicy       resource: arn:aws:iam::123456789123:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty
# * iam:DeleteRolePolicy    resource: arn:aws:iam::123456789123:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty

import os
import re
import logging
import boto3
from botocore.exceptions import ClientError
from botocore.vendored import requests

log_level = os.environ['LOG_LEVEL']

logger = logger
logger.setLevel(log_level)

s3 = boto3.client('s3')
gd = boto3.client('guardduty')

# Check TI set exist or not.
def check_gd_ti_exist(d_id,ti_name):
    try:
        ls_ti_rsp = gd.list_threat_intel_sets(
            DetectorId=d_id
        )
    except ClientError as e:
        logger.error('list TI set error: ' + e.response['Error']['Code'])
    
    for set_id in ls_ti_rsp['ThreatIntelSetIds']:
        try:
            get_ti_rsp= gd.get_threat_intel_set(
                DetectorId=d_id,
                ThreatIntelSetId=set_id
            )
        except ClientError as e:
            logger.error('get TI set error: ' + e.response['Error']['Code'])

        if (get_ti_rsp['Name'] == ti_name):
            logger.debug('TI name from search: ' + get_ti_rsp['Name'] + ' TI name from input: ' + ti_name)
            return set_id
    else:
        return None

# Create TI set
def create_gd_ti_feed(d_id,ti_name,s3_url):
    try:
        create_rsp = gd.create_threat_intel_set(
            Activate=True,
            DetectorId=d_id,
            Format='TXT',
            Location=s3_url,
            Name=ti_name
        )
    except ClientError as e:
        logger.error('Guardduty create error: ' + e.response['Error']['Code'])

# Update TI set
def update_gd_ti_feed(d_id,setId,ti_name,s3_url):
    try:
        update_rsp = gd.update_threat_intel_set(
            Activate=True,
            DetectorId=d_id,
            Location=s3_url,
            Name=ti_name,
            ThreatIntelSetId=setId
        )
    except ClientError as e:
        logger.error('Guardduty update error: ' + e.response['Error']['Code'])

def lambda_handler(event, context):
    logger.info('Lambda start')
    # Loop for get data(TI name and url) from event
    for data in event:
        threat_intel_name = data['name']
        s3_url = get_file_to_s3(data['url'],threat_intel_name)
        try:
            list_d_rsp = gd.list_detectors()
            detector_id = list_d_rsp['DetectorIds'][0]
        except ClientError as e:
            logger.error('list TI set error: ' + e.response['Error']['Code'])
            return 'Detector not found, please enable guardduty or check permission'
        
        set_id = check_gd_ti_exist(detector_id,threat_intel_name)

        if set_id == None:
            create_gd_ti_feed(detector_id,threat_intel_name,s3_url)
            logger.info('Create a new threat intel ipset ' + threat_intel_name)

        else:
            update_gd_ti_feed(detector_id,set_id,threat_intel_name,s3_url)
            logger.info('Update threat intel ipset ' + threat_intel_name)

    logger.info('Lambda finished')

    return {
        "statusCode": 200,
        "body": json.dumps('Job finished')
    }