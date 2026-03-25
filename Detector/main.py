import sys
import os
import boto3

from ec2_checks import (
    get_all_regions,
    get_all_instances,
    check_open_security_groups,
    check_public_instance_exposure,
    check_ebs_instance_encryption_status
)

def load_aws_credentials():
    access_key = None
    secret_key = None

    for arg in sys.argv[1:]:
        if arg.startswith("clientid="):
            access_key = arg.split("=", 1)[1]
        elif arg.startswith("secretid="):
            secret_key = arg.split("=", 1)[1]

    access_key = access_key or os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = secret_key or os.getenv("AWS_SECRET_ACCESS_KEY")

    if not access_key or not secret_key:
        raise ValueError(
            "AWS credentials not provided.\n"
            "Usage: python main.py clientid=XXX secretid=YYY\n"
            "Or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables."
        )

    return access_key, secret_key

def create_session(access_key, secret_key):
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
    )

def run_checks(session):
    all_regions = get_all_regions(session)
    
    for region in all_regions:
        ec2_client = session.client("ec2", region_name=region)
        
        all_instances = get_all_instances(ec2_client)

        for instance in all_instances:
            #check_open_security_groups(ec2_client, instance, region)
            #check_public_instance_exposure(ec2_client, instance, region)
            check_ebs_instance_encryption_status(ec2_client, instance, region)
    

def main():
    try:
        access_key, secret_key = load_aws_credentials()
        session = create_session(access_key, secret_key)

        findings = run_checks(session)


    except:
        None

if __name__ == "__main__":
    main()