import boto3
from botocore.exceptions import ClientError

from ec2_utils import(
    get_all_instances,
	get_all_security_groups,
	get_all_volumes
)

HIGH_RISK_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
}

def check_open_security_groups(instance, region, worldOpenGroups):
	# check for security group with 0.0.0.0/0 to high risk ports

	findings = []
	instanceId = instance.get("InstanceId")

	for group in instance.get("SecurityGroups"):
		groupId = group.get("GroupId")

		if groupId not in worldOpenGroups:
			continue

		group = worldOpenGroups[groupId]
		groupName = group.get("GroupName")

		for permission in group.get("IpPermissions"):
			ipProtocol = permission.get("IpProtocol")
			fromPort = permission.get("FromPort")
			toPort = permission.get("ToPort")

			if ipProtocol not in ["tcp", "udp", "-1"]:
				continue
			
			if ipProtocol == "-1":
				findings.append(
					{
							"severity": "HIGH",
							"resource": f"{instanceId} ({region})",
							"issue": "Security group allows all traffic from 0.0.0.0/0",
							"details": (
								f"Instance {instanceId} is associated with security group "
								f"{groupId} ({groupName}) that allows all inbound traffic "
								f"from the public internet."
							),
							"remediation": (
								"Restrict inbound access to trusted IP ranges only and avoid "
								"using 0.0.0.0/0 for unrestricted access."
							),
					}
				)
				continue

			for port, serviceName in HIGH_RISK_PORTS.items():
				if fromPort <= port <= toPort:
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

	return findings

def check_public_instance_exposure(instance, region, worldOpenGroups):
	# Check if the instance is actually publicly exposed
    
	findings = []

	instanceId = instance.get("InstanceId")
	publicIp = instance.get("PublicIpAddress")

	if not publicIp:
		return findings

	exposedGroups = []

	for group in instance.get("SecurityGroups"):
		groupId = group.get("GroupId")

		if groupId in worldOpenGroups:
			group = worldOpenGroups[groupId]
			groupName = group.get("GroupName")
			exposedGroups.append(f"{groupId} {groupName}")

	if exposedGroups:
		findings.append(
			{
				"severity": "HIGH",
                "resource": f"{instanceId} ({region})",
                "issue": "Publicly accessible EC2 instance detected",
                "details": (
                    f"Instance {instanceId} has public IP {publicIp} and is attached "
                    f"to security group(s) open to the internet: {', '.join(exposedGroups)}."
                ),
                "remediation": (
                    "Move the instance to a private subnet where possible, remove the public IP, "
                    "or restrict inbound access to trusted IP ranges only."
                ),
			}
		)
	return findings

def check_ebs_instance_encryption_status(instance, region, allVolumes):
	# find all ebs volumes unencrypted
	
	findings = []

	instanceId = instance.get("InstanceId")

	for block in instance.get("BlockDeviceMappings"):
		ebs = block.get("Ebs")
		if not ebs:
			continue
		
		volumeId = ebs.get("VolumeId")
		if not volumeId:
			continue

		volume = allVolumes.get(volumeId)
		if not volume:
			continue

		encryptionStatus = volume.get("Encrypted", False)

		if encryptionStatus == False:
			findings.append(
				{
					"severity": "HIGH",
                    "resource": f"{instanceId} ({region})",
                    "issue": "Unencrypted EBS volume attached to instance",
                    "details": (
                        f"Instance {instanceId} has an attached EBS volume "
                        f"({volumeId}) that is not encrypted at rest."
                    ),
                    "remediation": (
                        "Enable EBS encryption for volumes and snapshots, and enforce "
                        "encryption by default for newly created EBS volumes."
                    ),
				}
			)
	
	return findings

def check_imdsv1_enabled(instance, region):
	findings = []
	instanceId = instance.get("InstanceId")
	metadataOptions = instance.get("MetadataOptions")
	httpTokens = metadataOptions.get("HttpTokens")

	if httpTokens == "optional":
		findings.append(
			{
				"severity": "MEDIUM",
                "resource": f"{instanceId} ({region})",
                "issue": "IMDSv1 is enabled",
                "details": (
                    f"Instance {instanceId} has MetadataOptions.HttpTokens set to "
                    f"'optional', which means IMDSv2 is not enforced."
                ),
                "remediation": (
                    "Require IMDSv2 by setting MetadataOptions.HttpTokens to 'required' "
                    "to reduce the risk of SSRF-based credential theft."
                ),
			}
		)

	return findings

def get_all_world_open_security_groups(ec2_client):
	# Gets all the security groups that are open with 0.0.0.0/0
	worldOpenGroups = {}

	securityGroups =  get_all_security_groups(ec2_client)
	for group in securityGroups.values():
		groupId = group.get("GroupId")
		isWorldOpen = False

		for permission in group.get("IpPermissions", []):
			ipProtocol = permission.get("IpProtocol")

			if ipProtocol not in ["tcp", "udp", "-1"]:
				continue

			for ipRange in permission.get("IpRanges"):
				if ipRange.get("CidrIp") == "0.0.0.0/0":
					worldOpenGroups[groupId] = group
					isWorldOpen = True
					break

			if isWorldOpen:
				break

	return worldOpenGroups