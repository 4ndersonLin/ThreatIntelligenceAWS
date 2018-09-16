# IAM role permission requirement:
# * lambda basic excution policy
# * sfn:start_execution

import json
import os
import boto3
import logging

sfn_arn = os.environ['SFN_ARN']
log_level = os.environ['LOG_LEVEL'].upper()

# define log level
logger = logging.getLogger()
logger.setLevel(log_level)

# aws client
sfn = boto3.client('stepfunctions')

def lambda_handler(event, context):
    logger.info('Lambda start')
    s3_key_name = event['Records'][0]['s3']['object']['key']
    s3_bucket_name = event['Records'][0]['s3']['bucket']['name']
    region = os.environ['AWS_DEFAULT_REGION']
    s3_url = 'https://s3.' + region +'.amazonaws.com/' + s3_bucket_name + '/' + s3_key_name
    data = {
        'bucket' : s3_bucket_name,
        'key' : s3_key_name,
        'url' : s3_url
    }
    try:
        rsp = sfn.start_execution(
            stateMachineArn=sfn_arn,
            input=json.dumps(data)
        )
    except ClientError as e:
        logger.error('Stepfunction start error: ' + e.response['Error']['Code'])
    logger.info('Lambda finished')
    return {
        "statusCode": 200,
        "body": json.dumps('Job finished')
    }