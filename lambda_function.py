import boto3

def lambda_handler(event, context):
    iam = boto3.client('iam')
    response = iam.list_users()
    usernames = [user['UserName'] for user in response['Users']]
    return {
        'statusCode': 200,
        'body': f'IAM users visible with admin role: {usernames}'
    }