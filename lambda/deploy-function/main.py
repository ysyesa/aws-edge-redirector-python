from io import BytesIO
import os
import sys
import json
import json
import random
import string
import magic

import boto3
import urllib3
if sys.version_info >= (3, 8):
    import zipfile
else:
    import zipfile38 as zipfile


rule_bucket             = os.getenv('RuleBucket', '')
ui_prefix               = os.getenv('UIPrefix', '')
source_ui_file_bucket   = os.getenv('SourceUIFileBucket', '')
source_ui_file_path     = os.getenv('SourceUIFilePath')


def lambda_handler(event, context):
    lambda_callout_response_handler = LambdaCalloutResponseHandler()

    if (event['RequestType'] == 'Delete'):
        lambda_callout_response_handler.send(event, context, {})
        return

    response_data = {}
    if (event['RequestType'] == 'Create'):
        userpool = event['ResourceProperties']['UserPool']
        username = event['ResourceProperties']['UserName']
        temp_password = generate_password()

        upload_ui_assets(event)
        create_redirect_rule_file()
        create_user(userpool, username, temp_password)

        response_data['username'] = username
        response_data['password'] = temp_password
        
    lambda_callout_response_handler.send(event, context, response_data)


def generate_password():
    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(32))


def upload_ui_assets(event):
    s3_client = boto3.client('s3')
    s3_resource = boto3.resource('s3')
    mime = magic.Magic(mime=True)
    
    data = s3_client.get_object(Bucket=source_ui_file_bucket, Key=source_ui_file_path)
    zip = zipfile.ZipFile(BytesIO(data['Body'].read()))
    zip.extractall('/tmp')
    
    for path, _, files in os.walk('/tmp'):
        for file in files:
            file_path = os.path.join(path, file)
            s3_path = file_path.replace('/tmp', ui_prefix)
            mimetype = mime.from_file(file_path)
            try:
                s3_resource.meta.client.upload_file(file_path, rule_bucket, s3_path, ExtraArgs={'ACL': 'public-read', 'ContentType': mimetype})
            except Exception as e:
                print('[ERROR] Failed to upload UI assets: {0}'.format(str(e)))
                
    with open('/tmp/js/services/configService.js', 'r') as config_file:
        config_str = config_file.read()
        config_str = config_str.replace('BUCKET_URL', rule_bucket)
        config_str = config_str.replace('USER_POOL_ID', event['ResourceProperties']['UserPool'])
        config_str = config_str.replace('CLIENT_ID', event['ResourceProperties']['UserPoolClient'])
        config_str = config_str.replace('IDENTITY_POOL_ID', event['ResourceProperties']['IdentityPool'])

        with open('/tmp/js/services/configServiceNew.js', 'w') as new_config_file:
            new_config_file.write(config_str)
            new_config_file.close()
        
        config_file.close()

    mimetype = mime.from_file('/tmp/js/services/configServiceNew.js')
    s3_resource.meta.client.upload_file('/tmp/js/services/configServiceNew.js', rule_bucket, ui_prefix + '/js/services/configService.js', ExtraArgs={'ACL': 'public-read', 'ContentType': mimetype})


def create_user(userpool, username, password):
    cognito_client = boto3.client('cognito-idp')
    try:
        cognito_client.admin_create_user(
            UserPoolId=userpool,
            Username=username,
            MessageAction='SUPPRESS',
            TemporaryPassword= password,
        )
    except Exception as e:
        print('[ERROR] Error while creating user: {0}'.format(str(e)))
        

def create_redirect_rule_file():
    ruleset = {}
    ruleset['rules'] = []
    ruleset['wildcards'] = []
    ruleset['querystrings'] = []
    ruleset['refreshTime'] = 60

    with open('/tmp/redirector.json', 'w') as rule_file:
        rule_file.write(json.dumps(ruleset))
        rule_file.close()

    s3_resource = boto3.resource('s3')
    try:
        s3_resource.meta.client.upload_file('/tmp/redirector.json', rule_bucket, 'redirector.json', ExtraArgs={'ACL': 'public-read'})
    except Exception as e:
        print('[ERROR] Error while creating redirect rule file: {0}'.format(str(e)))


class LambdaCalloutResponseHandler:
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"

    ## Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-lambda-function-code-cfnresponsemodule.html
    @staticmethod
    def send(event, context, responseData, responseStatus='SUCCESS', physicalResourceId=None, noEcho=False, reason=None):
        responseUrl = event['ResponseURL']
        responseBody = {
            'Status' : responseStatus,
            'Reason' : reason or "See the details in CloudWatch Log Stream: {}".format(context.log_stream_name),
            'PhysicalResourceId' : physicalResourceId or context.log_stream_name,
            'StackId' : event['StackId'],
            'RequestId' : event['RequestId'],
            'LogicalResourceId' : event['LogicalResourceId'],
            'NoEcho' : noEcho,
            'Data' : responseData
        }
        json_responseBody = json.dumps(responseBody)
        headers = {
            'content-type' : '',
            'content-length' : str(len(json_responseBody))
        }
        try:
            http = urllib3.PoolManager()
            http.request('PUT', responseUrl, headers=headers, body=json_responseBody)
        except Exception as e:
            print('[ERROR] Failed to send response LambdaCallout: {0}'.format(str(e)))
