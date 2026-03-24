import boto3
from botocore.exceptions import ClientError

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