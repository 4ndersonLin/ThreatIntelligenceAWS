# IAM role permission requirement:
# * lambda basic excution policy
# * s3:GetObject
# * waf:get_ip_set
# * waf:get_change_token
# * waf:update_ip_set

import os
import io
import re
import math
import logging
from botocore.exceptions import ClientError
from botocore.vendored import requests
import boto3

ip_set1 = os.environ['IP_SET1']
ip_set2 = os.environ['IP_SET2']
log_level = os.environ['LOG_LEVEL'].upper()

# define log level
logger = logging.getLogger()
logger.setLevel(log_level)

# AWS hard limit
ip_set_limit = 10000
ip_set_request_limit = 1000

# AWS client
s3 = boto3.client('s3')
waf = boto3.client('waf')

# update waf
def update_waf(ip_set,ip_list):
    try:
        rsp = waf.get_change_token()
    except ClientError as e:
        logger.error('WAF get token error: ' + e.response['Error']['Code'])

    token = rsp['ChangeToken']
    try:
        rsp = waf.update_ip_set(
            IPSetId=ip_set,
            ChangeToken=token,
            Updates=ip_list
        )
        print(rsp)
    except ClientError as e:
        logger.error('WAF update ip set error: ' + e.response['Error']['Code'])

# clean ip set
def wipe_waf(ipset_id):
    logger.info('Start clean ipset: ' + ipset_id)
    try:
        rsp = waf.get_ip_set(
            IPSetId=ipset_id
        )
    except ClientError as e:
        logger.error('WAF get ip set error: ' + e.response['Error']['Code'])
    
    rsp_ip_sets = rsp['IPSet']['IPSetDescriptors']
    
    # get update excute times
    wipe_count = math.ceil(len(rsp_ip_sets)/ip_set_request_limit)
    
    # return when ip set is empty.
    if rsp_ip_sets ==[]:
        logger.info('IP set: ' + ipset_id +' is empty')
        return ipset_id
    
    while wipe_count > 0:
        try:
            rsp = waf.get_ip_set(
                IPSetId=ipset_id
            )
        except ClientError as e:
            logger.error('WAF get ip set error: ' + e.response['Error']['Code'])
        rsp_ip_set = rsp['IPSet']['IPSetDescriptors']
        
        current_ip_list = []
        for position,data in enumerate(rsp_ip_set):

            if position == 1000:
                break
            else:
                del_ip = {
                    'Action': 'DELETE',
                    'IPSetDescriptor': {
                        'Type': 'IPV4',
                        'Value': data['Value']
                    }
                }
                current_ip_list.append(del_ip)

        logger.debug('current_ip_list: ' + str(current_ip_list))
        update_waf(ipset_id,current_ip_list)
        wipe_count -= 1
    logger.info('Finished clean ipset: ' + ipset_id)

# check TI IP
def check_ips(ti_ips):
    ip_add = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    ip_repu = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#[3-5]{1}#[3-5]{1}')
    
    logger.info('Start check IP')

    if len(ti_ips) > (ip_set_limit*2):
        logger.error('IP over ' + str(ip_set_limit*2))
    else:
        ip_count = 1
        request_count = 1
        updateIP = []
        logger.debug('length of TI IP' + len(ti_ips))
        for line in ti_ips:
            insert_ip = {
                'Action': 'INSERT',
                'IPSetDescriptor': {
                    'Type': 'IPV4',
                    'Value': line.replace('\n','')
                }
            }
            updateIP.append(insert_ip)
            if ip_count > ip_set_limit:
                waf_ip_set = ip_set2
            else:
                waf_ip_set = ip_set1

            if (request_count % ip_set_request_limit) ==0:
                update_waf(waf_ip_set,updateIP)
                logger.debug(waf_ip_set +' '+ str(request_count)+ ' ' + str(ip_count))
                updateIP = []
                request_count = 0
            elif len(ti_ips) < ip_set_request_limit and request_count == len(ti_ips):
                
                update_waf(waf_ip_set,updateIP)
                logger.debug(waf_ip_set +' '+ str(request_count)+ ' ' + str(ip_count))

            elif ip_count == len(ti_ips):
                
                update_waf(waf_ip_set,updateIP)
                logger.debug(waf_ip_set +' '+ str(request_count)+ ' ' + str(ip_count))

            request_count += 1
            ip_count += 1

    logger.info('Finished check IP')

def lambda_handler(event, context):
    logger.info('Lambda start')
    s3_bucket_name = event['bucket']
    s3_key = event['key']

    # check ipset 2 and wipe ipset 1/2 if necessary
    try:
        rsp = waf.get_ip_set(
            IPSetId=ip_set2
        )
    except ClientError as e:
        logger.error('WAF get ip set error: ' + e.response['Error']['Code'])

    if rsp['IPSet']['IPSetDescriptors'] != []:
        wipe_waf(ip_set2)

    wipe_waf(ip_set1)

    # get TI IP list from S3
    try:
        rsp = s3.get_object(
            Bucket=s3_bucket_name,
            Key=s3_key
            )
        data = rsp['Body'].read().decode('utf-8')
    except ClientError as e:
        logger.error('S3 get error: ' + e.response['Error']['Code'])

    buf = io.StringIO(data)
    # check and update
    check_ips(buf.readlines())
    logger.info('Lambda finished')

    return {
        "statusCode": 200,
        "body": json.dumps('Job finished')
    }