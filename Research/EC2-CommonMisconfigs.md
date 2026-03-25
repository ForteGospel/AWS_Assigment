# AWS EC2 Security Misconfiguration Analysis

## 1. Service Overview

Amazon EC2 (Elastic Compute Cloud) provides scalable virtual servers in the cloud, allowing organizations to run applications, backend services, administrative systems, and other workloads on demand. Because EC2 instances often process sensitive business data and interact with many other AWS services, they are a central target in cloud attacks.

### Key Features and Assets
EC2 includes several components and related assets that are relevant from a security perspective:

- **EC2 Instances** – virtual machines running workloads
- **Security Groups** – virtual firewalls controlling inbound and outbound traffic
- **Elastic IPs / Public IPs** – internet-facing connectivity
- **IAM Roles and Instance Profiles** – permissions granted to instances
- **EBS Volumes** – persistent block storage attached to instances
- **AMIs (Amazon Machine Images)** – templates used to launch instances

### Potential Targets and Areas of Interest for Attackers
Attackers commonly focus on the following EC2-related targets:

- **Publicly exposed services** accessible over the internet
- **Weak or over-permissive network access controls**
- **Temporary credentials available through instance metadata**
- **Overprivileged IAM roles attached to instances**
- **Sensitive data stored on EBS volumes**
- **Untrusted or improperly shared AMIs**
- **Golden images that spread insecure configurations across many instances**

Because EC2 frequently acts as the execution layer of cloud infrastructure, compromising an EC2 instance can provide both local host access and a path to broader AWS compromise.

## 2. Common EC2 Misconfigurations (Ordered by Severity and Likelihood of Exploitation)

## 1. Security Groups Allow Unrestricted Access (0.0.0.0/0) to Sensitive Ports

### Description & Risk
A security group allows inbound access from `0.0.0.0/0` to administrative or otherwise sensitive ports such as:

- SSH (`22`)
- RDP (`3389`)
- Database ports such as MySQL (`3306`) or PostgreSQL (`5432`)

This exposes the instance directly to the internet and significantly increases the chance of brute-force attacks, exploitation of vulnerable services, and unauthorized access.

### Potential Attack Scenario / Impact
An attacker scans internet-facing IP ranges, discovers an EC2 instance with SSH open to the world, and attempts password spraying, stolen key usage, or exploitation of a service vulnerability. If successful, the attacker gains a foothold on the instance.

### AWS Best Practice Recommendation for Remediation
- Restrict inbound access to trusted IP ranges only
- Avoid exposing management ports directly to the internet
- Use bastion hosts, VPN access, or AWS Systems Manager Session Manager for administration
- Periodically review security group rules for overly broad CIDRs

## 2. Publicly Accessible EC2 Instance

### Description & Risk
An EC2 instance has a public IP address and is associated with security groups that expose services externally. Even if the exposed service is intended for public use, direct exposure increases attack surface and raises the impact of any unpatched vulnerability or misconfiguration.

### Potential Attack Scenario / Impact
An attacker identifies a public-facing EC2 instance and exploits a vulnerable web application, API service, or administrative interface. This may lead to remote code execution, data theft, persistence, or privilege escalation through the attached IAM role.

### AWS Best Practice Recommendation for Remediation
- Place internal workloads in private subnets whenever possible
- Use load balancers, reverse proxies, or NAT rather than exposing instances directly
- Minimize open inbound ports
- Segment public-facing and internal workloads

## 3. Overprivileged IAM Role Attached to EC2 Instance

### Description & Risk
The EC2 instance is attached to an IAM role with excessive permissions, such as `AdministratorAccess` or broad wildcard permissions. This violates the principle of least privilege.

If the instance is compromised, the attacker can use the instance role credentials to access other AWS resources and expand the compromise.

### Potential Attack Scenario / Impact
An attacker gains shell access to an EC2 instance and retrieves temporary credentials from the Instance Metadata Service. With an overly permissive role, the attacker may create users, modify policies, access S3 data, or disable logging mechanisms.

### AWS Best Practice Recommendation for Remediation
- Use least-privilege IAM roles
- Avoid broad managed policies like `AdministratorAccess` unless strictly required
- Regularly review role permissions and attached policies
- Separate application roles from administrative roles

## 4. Untrusted or Unverified AMI Used as a Golden Image

### Description & Risk
An organization uses a public, unverified, or otherwise untrusted AMI as a base “golden image” for launching EC2 instances. Because AMIs define the starting state of deployed instances, a compromised or poorly configured AMI can spread insecurity across the environment at scale.

This is both a supply chain risk and a persistence risk.

### Potential Attack Scenario / Impact
An attacker publishes or tampers with an AMI that includes malicious startup scripts, backdoors, credential theft logic, or insecure default settings. If the organization uses that AMI as a standard image, every newly launched EC2 instance may inherit the compromise.

### AWS Best Practice Recommendation for Remediation
- Use only trusted AMIs from verified publishers or internal image pipelines
- Maintain hardened internal golden images
- Validate and scan AMIs before approving them for production use
- Apply image governance and version control for approved AMIs

## 5. Publicly Shared AMI (Unintended Data Exposure)

### Description & Risk
An AMI created from an organization’s EC2 instance is shared publicly or with unintended AWS accounts. Because AMIs can include installed software, configuration files, scripts, logs, cached artifacts, and embedded secrets, sharing them publicly can result in serious information disclosure.

This is a high-risk data exposure issue and may also enable follow-on attacks.

### Potential Attack Scenario / Impact
An attacker identifies a publicly shared AMI owned by the organization and launches an instance from it. The attacker then inspects the disk contents and discovers sensitive information such as API tokens, SSH keys, application secrets, internal service endpoints, or proprietary code.

### AWS Best Practice Recommendation for Remediation
- Ensure AMIs are not publicly shared unless explicitly required
- Regularly audit AMI launch permissions
- Remove public access from AMIs that do not need to be shared
- Sanitize images before creating or distributing them
- Avoid storing secrets, credentials, or unnecessary logs in machine images

## 6. Unencrypted EBS Volumes

### Description & Risk
EBS volumes attached to EC2 instances are not encrypted at rest. Unencrypted storage increases the risk of sensitive data exposure if snapshots, backups, or underlying storage are accessed without authorization.

### Potential Attack Scenario / Impact
An attacker gains access to a snapshot or otherwise obtains access to unencrypted storage data. Sensitive material such as application data, credentials, tokens, and logs may be exposed.

### AWS Best Practice Recommendation for Remediation
- Enable encryption by default for EBS volumes
- Use AWS KMS-managed keys where appropriate
- Enforce encryption requirements through policy and provisioning controls
- Audit existing volumes and snapshots for encryption status

## 7. Instance Metadata Service v1 (IMDSv1) Enabled

### Description & Risk
The EC2 instance allows IMDSv1 instead of enforcing IMDSv2. IMDSv1 is more vulnerable to misuse in SSRF-style attack paths because it lacks the session-oriented protections introduced in IMDSv2.

If an attacker can trigger requests from a vulnerable application on the instance, they may be able to retrieve metadata and temporary IAM credentials.

### Potential Attack Scenario / Impact
An attacker exploits an SSRF vulnerability in a web application hosted on EC2 and accesses the metadata endpoint. They retrieve role credentials and use them to interact with AWS APIs, potentially leading to privilege escalation or lateral movement.

### AWS Best Practice Recommendation for Remediation
- Require IMDSv2 by setting `HttpTokens` to `required`
- Disable or limit metadata access where possible
- Monitor workloads for SSRF vulnerabilities
- Review applications exposed to untrusted input

## 8. Secrets Stored Locally on EC2 Instances Instead of Using a Secure Secrets Manager

### Description & Risk
Sensitive information such as API keys, database credentials, private keys, or tokens is stored directly on the EC2 instance (e.g., in environment variables, configuration files, scripts, or application code) instead of being managed through a secure service such as AWS Secrets Manager or AWS Systems Manager Parameter Store.

This practice increases the risk of credential exposure if the instance is compromised, improperly backed up, or included in an AMI or snapshot.

### Potential Attack Scenario / Impact
An attacker gains access to an EC2 instance (via exposed service, SSH compromise, or vulnerability). Once inside, they search the filesystem and environment variables and retrieve hardcoded secrets. These credentials are then used to access databases, APIs, or other AWS services, enabling lateral movement and data exfiltration.

Additionally, if the instance is used to create an AMI or snapshot, embedded secrets may unintentionally propagate across multiple systems or become publicly exposed.

### AWS Best Practice Recommendation for Remediation
- Store secrets in AWS Secrets Manager or AWS Systems Manager Parameter Store
- Retrieve secrets dynamically at runtime instead of hardcoding them
- Rotate credentials regularly
- Avoid storing secrets in AMIs, user data scripts, or configuration files
- Use IAM roles for EC2 instead of static credentials whenever possible

## References

- AWS Security Hub – EC2 Exposure Findings  
  https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-ec2-instance.html  

- Amazon EC2 Best Practices  
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-best-practices.html  

- Boto3 EC2 Documentation  
  https://docs.aws.amazon.com/boto3/latest/reference/services/ec2.html  