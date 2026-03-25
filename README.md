# AWS EC2 Misconfiguration Detector

## Overview

This project is a Python-based tool designed to identify common security misconfigurations in AWS EC2 environments.

It scans all AWS regions and analyzes EC2 instances, security groups, and attached resources to detect issues that could expose infrastructure to potential attacks.

The tool focuses on identifying real-world security risks such as public exposure, weak network configurations, and insecure instance settings.

## Features

The tool currently detects the following misconfigurations:

### 1. Open Security Groups
Identifies security groups that allow inbound access from `0.0.0.0/0`, including:
- SSH (22)
- RDP (3389)
- Database ports
- All traffic (`IpProtocol = -1`)

### 2. Publicly Accessible EC2 Instances
Detects instances that:
- Have a public IP address
- Are attached to security groups open to the internet

### 3. IMDSv1 Enabled
Detects instances that do not enforce IMDSv2:
- `MetadataOptions.HttpTokens = optional`

### 4. Unencrypted EBS Volumes
Identifies EC2 instances with attached EBS volumes that are not encrypted at rest.

## How It Works

1. Authenticate using AWS credentials
2. Retrieve all AWS regions
3. For each region:
   - Fetch EC2 instances
   - Fetch security groups
   - Identify world-open security groups
   - Fetch EBS volumes
4. Run detection checks per instance
5. Output findings

## Output Example
Severity: HIGH
Resource: i-0fc995db07c0bfeea (eu-north-1)
Issue: Security group allows all traffic from 0.0.0.0/0
Details: Instance i-0fc995db07c0bfeea is associated with security group sg-07969a3eafa8c854d (launch-wizard-1) that allows all inbound traffic from the public internet.
Remediation: Restrict inbound access to trusted IP ranges only and avoid using 0.0.0.0/0 for unrestricted access.
---------------------------------------------------------


Severity: HIGH
Resource: i-0fc995db07c0bfeea (eu-north-1)
Issue: Security group allows SSH from 0.0.0.0/0
Details: Instance i-0fc995db07c0bfeea is associated with security group sg-07969a3eafa8c854d (launch-wizard-1) exposing port 22 to the public internet.
Remediation: Restrict port 22 access to trusted IP ranges only, or use a bastion host / AWS Systems Manager Session Manager.
---------------------------------------------------------

## TODO

### Organization-Level Scanning
Currently, the tool operates at the **single AWS account level**.

Future improvement:
- Extend scanning across multiple AWS accounts using **AWS Organizations**
- Provide a unified view of misconfigurations across the organization

### Improved Reporting with Pandas
Current output is printed to console.

Future improvement:
- Use **pandas** to structure findings into DataFrames
- Export results to:
  - CSV
  - Excel
  - JSON
- Enable sorting, filtering, and aggregation of findings (e.g., by severity, region)
