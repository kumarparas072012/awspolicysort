import boto3
import json

def lambda_handler(event, context):
    PolicyNames=['PS_Team_Alpha_1',	'PS_Team_Alpha_2','PS_Team_Alpha_3','PS_Team_CAL_1','PS_Team_CAL_2','PS_Team_CAL_3','PS_Team_CICD_1','PS_Team_CM_1','PS_Team_CM_2',	'PS_Team_DAL_1','PS_Team_DAL_2','PS_Team_DAL_3','PS_Team_DAL_4','PS_Team_DAL_5','PS_Team_DAL_6','PS_Team_DAL_7','PS_Team_Deny_1','PS_Team_JM_1','PS_Team_Leads_1','PS_Team_ProductSecurity_1','PS_Team_ProductSecurity_2','PS_Team_ProductSecurity_3','PS_Team_SRE_1','PS_Team_SRE_2','PS_Team_SRE_3','PS_Team_SRE_4','PS_Team_SRE_5','PS_Team_TDL_1','PS_Team_TDL_2','PS_Team_TDL_3','PS_Team_TDL_4','PS_Team_UB_1','PS_Team_UB_2','PS_Team_UB_3','PS_Team_UB_4','PS_Team_UI_1','PS_Team_UI_2','PS_Team_UI_3','PS_Team_UI_4']
    for policy_name in PolicyNames:
        arn = f"arn:aws:iam::538782569624:policy/{policy_name}"
        iam = boto3.client('iam')
        policy = iam.get_policy(PolicyArn=arn)
        policy_version = iam.get_policy_version(PolicyArn=arn, VersionId=policy['Policy']['DefaultVersionId'])
        policyjson = json.dumps(policy_version['PolicyVersion']['Document'])
        policyres = {'jsonformat': policyjson, 'PolicyName': policy_name}
        print(policy_name)
    
        sts = boto3.client('sts')
        accounts = [
            {"id": "712427214116", "role": "service-role/SSO-ENT-Update-role"},
            {"id": "849689826459", "role": "SSO-DEV-Update-role"}
        ]
        for account in accounts:
            acct_b = sts.assume_role(RoleArn=f"arn:aws:iam::{account['id']}:role/{account['role']}", RoleSessionName="LambdaPushSession")
            ACCESS_KEY = acct_b['Credentials']['AccessKeyId']
            SECRET_KEY = acct_b['Credentials']['SecretAccessKey']
            SESSION_TOKEN = acct_b['Credentials']['SessionToken']
            lambda_client = boto3.client('lambda', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY, aws_session_token=SESSION_TOKEN)
            
    
            function_name = f"arn:aws:lambda:us-east-1:{account['id']}:function:{get_function_name(account['id'])}"
            response = lambda_client.invoke(FunctionName=function_name, InvocationType='RequestResponse', Payload=json.dumps(policyres))
            sending_json = json.load(response['Payload'])
            print(sending_json)

def get_function_name(id):
     if(id=='712427214116'): 
          return "SSO-ENT-Update"
     else: 
          return "SSO-DEV-Update"