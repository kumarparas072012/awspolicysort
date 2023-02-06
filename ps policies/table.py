import boto3
import json

def lambda_handler(event, context):
    # Connect to IAM client
    iam = boto3.client('iam')
    
    # Get the policy document
    response = iam.get_policy(
        PolicyArn='arn:aws:iam::538782569624:policy/Paras-Permission-Sets'
    )
    policy_version = iam.get_policy_version(PolicyArn=arn, VersionId=policy['Policy']['DefaultVersionId'])
    
    # Load the JSON policy document into a dictionary
    policy = json.dumps(policy_version['PolicyVersion']['Document'])
    
    # Connect to the RDS database
    conn = psycopg2.connect(
        host='grafana.chobp4z33geq.us-east-1.rds.amazonaws.com',
        database='grafana',
        user='master',
        password='zxnm1290ZXNM'
    )
    
    # Create a cursor
    cursor = conn.cursor()
    
    # Loop through the policy statements
    for statement in policy['Statement']:
        # Extract the effect, action, and resource from the statement
        effect = statement['Effect']
        action = statement['Action']
        resource = statement['Resource']
        
        # Insert the data into the policy table
        cursor.execute(
            "INSERT INTO public.permissions_cybersecurity (servicetype, actionname, resource_service) VALUES (%s, %s, %s)",
            (sid, action, resource)
        )
    
    # Commit the changes
    conn.commit()
    
    # Close the cursor and connection
    cursor.close()
    conn.close()
