import sys
import os
import boto3

from ec2_checks import (
    check_open_security_groups,
    check_public_instance_exposure,
    check_ebs_instance_encryption_status,
    check_imdsv1_enabled,
    get_all_world_open_security_groups
)

from ec2_utils import(
    create_session,
    get_all_regions,
    get_all_instances,
    get_all_volumes
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

def run_checks(session):
    findings = []
    all_regions = get_all_regions(session)
    
    for region in all_regions:
        ec2_client = session.client("ec2", region_name=region)
        
        all_instances = get_all_instances(ec2_client)
        worldOpenGroups = get_all_world_open_security_groups(ec2_client)
        allVolumes = get_all_volumes(ec2_client)

        for instance in all_instances:
            findings.extend(check_open_security_groups(instance, region, worldOpenGroups))
            findings.extend(check_public_instance_exposure(instance, region, worldOpenGroups))
            findings.extend(check_ebs_instance_encryption_status(instance, region, allVolumes))
            findings.extend(check_imdsv1_enabled(instance, region))

    return findings

def print_findings(findings):
    for find in findings:
        print(f"Severity: {find["severity"]}")
        print(f"Resource: {find["resource"]}")
        print(f"Issue: {find["issue"]}")
        print(f"Details: {find["details"]}")
        print(f"Remediation: {find["remediation"]}")
        print("---------------------------------------------------------\n\n")
    

def main():
    try:
        access_key, secret_key = load_aws_credentials()
        session = create_session(access_key, secret_key)

        findings = run_checks(session)
        print_findings(findings)

    except:
        None

if __name__ == "__main__":
    main()