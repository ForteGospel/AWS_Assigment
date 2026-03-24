import boto3
from botocore.exceptions import ClientError

HIGH_RISK_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
}

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

def check_open_security_groups(ec2_client, instance, region):
	# check for security group with 0.0.0.0/0 to high risk ports

	findings = []
	instanceId = instance.get("InstanceId")

	for group in instance.get("SecurityGroups"):
		groupId = group.get("GroupId")
		try:
			response = ec2_client.describe_security_groups(GroupIds = [groupId])
			securityGroups = response.get("SecurityGroups")

			for securityGroup in securityGroups:
				groupName = securityGroup.get("GroupName")

				for permission in securityGroup.get("IpPermissions"):
					fromPort = permission.get("FromPort")
					toPort = permission.get("ToPort")
					ipProtocol = permission.get("IpProtocol")


					if ipProtocol not in ["tcp", "udp", "-1"]:
						continue

					for ipRange in permission.get("IpRanges"):
						cidr = ipRange.get("CidrIp")

						if cidr != "0.0.0.0/0":
							continue

						if ipProtocol == "-1":
							findings.append(
								{
                                    "severity": "HIGH",
                                    "resource": f"{instanceId} ({region})",
                                    "issue": "Security group allows all traffic from 0.0.0.0/0",
                                    "details": (
                                        f"Instance {instanceId} is associated with security group "
                                        f"{groupId} ({groupName}) that allows all protocols/ports "
                                        f"from the public internet."
                                    ),
                                    "remediation": (
                                        "Restrict inbound access to trusted IP ranges only and avoid "
                                        "allowing all traffic from 0.0.0.0/0."
                                    ),
                                }
							)

						for port, serviceName in HIGH_RISK_PORTS.items():
							if fromPort == port and toPort == port:
								findings.append(
									{
                                        "severity": "HIGH",
                                        "resource": f"{instanceId} ({region})",
                                        "issue": f"Security group allows {serviceName} from 0.0.0.0/0",
                                        "details": (
                                            f"Instance {instanceId} is associated with security group "
                                            f"{groupId} ({groupName}) exposing port {port} "
                                            f"to the public internet."
                                        ),
                                        "remediation": (
                                            f"Restrict port {port} access to trusted IP ranges only, "
                                            "or use a bastion host / AWS Systems Manager Session Manager."
                                        ),
                                    }
								)

		except ClientError as e:
			print(f"[ERROR] Failed to retrieve EC2 instances: {e}")

		except Exception as e:
			print(f"[ERROR] Unexpected error while retrieving EC2 instances: {e}")

	return findings