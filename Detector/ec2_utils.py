import boto3
from botocore.exceptions import ClientError

from ec2_checks import (
    find_world_open_security_groups,
    run_checks_on_instance,
)


def create_session(access_key, secret_key, session_token=None):
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
    )

def get_all_regions(session):
    # Get all enabled regions in the account #
    ec2 = session.client("ec2", region_name = "eu-north-1")

    response = ec2.describe_regions(AllRegions = False)

    regions = [region["RegionName"] for region in response.get("Regions")]

    return regions
    
def get_all_instances(ec2_client):
    # Get All Instances in region
    instances = []

    try:
        paginator = ec2_client.get_paginator("describe_instances")

        for page in paginator.paginate():
            for reservation in page.get("Reservations"):
                for instance in reservation.get("Instances"):
                    instances.append(instance)

    except ClientError as e:
        print(f"[ERROR] Failed to retrieve EC2 instances: {e}")

    except Exception as e:
        print(f"[ERROR] Unexpected error while retrieving EC2 instances: {e}")

    return instances

def get_all_security_groups(ec2_client):
    # Get All Security Groups in region

    securityGroups = {}
    try:
        paginator = ec2_client.get_paginator("describe_security_groups")

        for page in paginator.paginate():
            for group in page.get("SecurityGroups"):
                groupId = group.get("GroupId")
                if groupId:
                    securityGroups[groupId] = group

    except ClientError as e:
        print(f"[ERROR] Failed to retrieve security groups: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error while retrieving security groups: {e}")

    return securityGroups

def get_all_volumes(ec2_client):
    # Get all EBS Volumes in region

    volumes = {}

    try:
        paginator = ec2_client.get_paginator("describe_volumes")

        for page in paginator.paginate():
            for volume in page.get("Volumes"):
                volumeId = volume.get("VolumeId")
                if volumeId:
                    volumes[volumeId] = volume

    except ClientError as e:
        print(f"[ERROR] Failed to retrieve EBS volumes: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error while retrieving EBS volumes: {e}")

    return volumes


def scan_region(ec2_client, region):
    instances = get_all_instances(ec2_client)
    security_groups = get_all_security_groups(ec2_client)
    volumes = get_all_volumes(ec2_client)
    world_open = find_world_open_security_groups(security_groups)

    findings = []
    for instance in instances:
        findings.extend(run_checks_on_instance(instance, region, world_open, volumes))

    return {
        "region": region,
        "instances": instances,
        "security_groups": security_groups,
        "world_open_security_group_ids": list(world_open.keys()),
        "volumes": volumes,
        "findings": findings,
    }


def scan_account(session):
    results = []
    for region in get_all_regions(session):
        ec2_client = session.client("ec2", region_name=region)
        results.append(scan_region(ec2_client, region))
    return results
