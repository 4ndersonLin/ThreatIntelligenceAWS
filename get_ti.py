# IAM role permission requirement:
# * lambda basic excution policy
# * s3:put_object

import os
import re
import logging
import boto3
from botocore.exceptions import ClientError
from botocore.vendored import requests

s3_bucket_name = os.environ['S3_BUCKET_NAME']
log_level = os.environ['LOG_LEVEL'].upper()

# aws client
s3 = boto3.client('s3')

# set log level
logger = logging.getLogger()
logger.setLevel(log_level)

# compile CIDR format
cidr_block = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}')

# compile IP format
ip_add = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

# alienvault ip reputation data format: <IP>#<RELIABILITY>#<RISK> 
# compile reliability and risk greater than 3
ip_repu = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#[3-5]{1}#[3-5]{1}')

# compile alienvault fromat
ip_repu_format = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#[1-5]{1}#[1-5]{1}')

# update ti to S3
def update_ti(name,url):
    tmp_fpath = '/tmp/parsed.' + name
    s3_key = name + '.txt'
    
    # get threat intelligence source from url
    rsp = requests.get(url)
    logger.info('get TI list from: ' + url)
    
    # parse data from url.get and write to tmp file
    f = open(tmp_fpath,'w+')
    for line in rsp.text.splitlines():
        search_cidr_block =cidr_block.search(line)
        search_ip = ip_add.search(line)
        search_ip_repu = ip_repu.search(line)
        match_ip_repu_format = ip_repu_format.match(line)
        if search_cidr_block:
            f.write(search_cidr_block.group() + '\n')
        elif search_ip_repu:
            f.write(search_ip.group() + '/32' + '\n')
        elif search_ip and match_ip_repu_format == None:
            f.write(search_ip.group() + '/32' + '\n')
    f.close()
    
    # read data from file and put data to s3
    data = open(tmp_fpath,'rb')
    try:
        s3_rsp = s3.put_object(
            Body=data,
            Bucket=s3_bucket_name, 
            Key=s3_key
        )
        data.close()
    except ClientError as e:
        logger.error('S3 put object error : ' + e)


def lambda_handler(event, context):
    logger.info('Lambda start')
    update_ti(event['name'],event['url'])
    logger.info('Lambda finished')
    return {
        "statusCode": 200,
        "body": json.dumps('Job finished')
    }