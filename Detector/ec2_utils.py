import glob
import json
import os
from datetime import datetime, timezone

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


DEFAULT_ASSUME_ROLE = "OrganizationAccountAccessRole"
SSO_CACHE_DIR = os.path.expanduser("~/.aws/sso/cache")


def get_current_account_id(session):
    try:
        return session.client("sts").get_caller_identity()["Account"]
    except (ClientError, Exception):
        return None


def find_sso_token():
    """Return the freshest non-expired SSO access token from ~/.aws/sso/cache, or None."""
    if not os.path.isdir(SSO_CACHE_DIR):
        return None

    candidates = []
    for path in glob.glob(os.path.join(SSO_CACHE_DIR, "*.json")):
        try:
            with open(path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue

        token = data.get("accessToken")
        expires_at = data.get("expiresAt")
        if not token or not expires_at:
            continue

        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            continue

        if expiry <= datetime.now(timezone.utc):
            continue

        candidates.append({
            "access_token": token,
            "region": data.get("region") or "us-east-1",
            "expires_at": expiry,
            "start_url": data.get("startUrl"),
        })

    if not candidates:
        return None

    candidates.sort(key=lambda c: c["expires_at"], reverse=True)
    return candidates[0]


def _role_priority(role_name):
    name = (role_name or "").lower()
    if "readonly" in name or "read-only" in name:
        return 0
    if "audit" in name or "security" in name:
        return 1
    if "view" in name:
        return 2
    return 10


def discover_sso_accounts(session, sso_token):
    """Return [{account_id, account_name, role_name}, ...] picking one role per account."""
    sso = session.client("sso", region_name=sso_token["region"])

    entries = []
    paginator = sso.get_paginator("list_accounts")
    for page in paginator.paginate(accessToken=sso_token["access_token"]):
        for acct in page.get("accountList", []):
            account_id = acct["accountId"]
            account_name = acct.get("accountName")
            roles = []
            roles_paginator = sso.get_paginator("list_account_roles")
            for rpage in roles_paginator.paginate(
                accessToken=sso_token["access_token"],
                accountId=account_id,
            ):
                roles.extend(rpage.get("roleList", []))
            if not roles:
                continue
            roles.sort(key=lambda r: _role_priority(r.get("roleName")))
            entries.append({
                "account_id": account_id,
                "account_name": account_name,
                "role_name": roles[0].get("roleName"),
            })
    return entries


def sso_session_for(base_session, sso_token, account_id, role_name):
    sso = base_session.client("sso", region_name=sso_token["region"])
    response = sso.get_role_credentials(
        accessToken=sso_token["access_token"],
        accountId=account_id,
        roleName=role_name,
    )
    creds = response["roleCredentials"]
    return boto3.Session(
        aws_access_key_id=creds["accessKeyId"],
        aws_secret_access_key=creds["secretAccessKey"],
        aws_session_token=creds["sessionToken"],
    )


def discover_accounts(session):
    """Return [{Id, Name, Status}] for org accounts, or None if Organizations isn't accessible."""
    try:
        org = session.client("organizations")
        accounts = []
        paginator = org.get_paginator("list_accounts")
        for page in paginator.paginate():
            for acct in page.get("Accounts", []):
                accounts.append({
                    "Id": acct["Id"],
                    "Name": acct.get("Name"),
                    "Status": acct.get("Status"),
                })
        return accounts
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in {"AccessDeniedException", "AWSOrganizationsNotInUseException"}:
            return None
        raise


def assume_role_session(base_session, account_id, role_name, session_name="ec2-detector"):
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    sts = base_session.client("sts")
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def scan_organization(session, assume_role_name=DEFAULT_ASSUME_ROLE, sso_token=None):
    """Scan every account the caller can reach.

    Resolution order:
      1. If sso_token is provided (or auto-discovered), enumerate via SSO and scan each.
      2. Else try organizations:ListAccounts + sts:AssumeRole into member accounts.
      3. Else scan only the current account.

    Returns a list of per-account dicts:
        {
            "account_id": str,
            "account_name": str | None,
            "is_management": bool,
            "status": "completed" | "failed" | "skipped",
            "error": str | None,
            "regions": [scan_region results],
        }
    """
    if sso_token is None:
        sso_token = find_sso_token()

    current_account_id = get_current_account_id(session)

    if sso_token is not None:
        return _scan_via_sso(session, sso_token, current_account_id)

    org_accounts = discover_accounts(session)
    results = []

    if org_accounts is None:
        results.append(_scan_one_account(session, current_account_id, account_name=None, is_management=True))
        return results

    for acct in org_accounts:
        account_id = acct["Id"]
        account_name = acct.get("Name")
        if acct.get("Status") and acct["Status"] != "ACTIVE":
            results.append({
                "account_id": account_id,
                "account_name": account_name,
                "is_management": account_id == current_account_id,
                "status": "skipped",
                "error": f"Account status is {acct['Status']}",
                "regions": [],
            })
            continue

        if account_id == current_account_id:
            results.append(_scan_one_account(session, account_id, account_name, is_management=True))
            continue

        try:
            assumed = assume_role_session(session, account_id, assume_role_name)
        except ClientError as e:
            results.append({
                "account_id": account_id,
                "account_name": account_name,
                "is_management": False,
                "status": "failed",
                "error": f"AssumeRole into {assume_role_name} failed: {e.response.get('Error', {}).get('Code', 'Unknown')}",
                "regions": [],
            })
            continue

        results.append(_scan_one_account(assumed, account_id, account_name, is_management=False))

    return results


def _scan_via_sso(base_session, sso_token, current_account_id):
    try:
        sso_entries = discover_sso_accounts(base_session, sso_token)
    except ClientError as e:
        # If the token is bad, fall back to single-account behavior signalled via an empty list
        # and a marker entry — easier to debug than swallowing silently.
        return [{
            "account_id": current_account_id or "unknown",
            "account_name": None,
            "is_management": True,
            "status": "failed",
            "error": f"SSO ListAccounts failed: {e.response.get('Error', {}).get('Code', 'Unknown')}",
            "regions": [],
        }]

    results = []
    for entry in sso_entries:
        account_id = entry["account_id"]
        try:
            account_session = sso_session_for(base_session, sso_token, account_id, entry["role_name"])
        except ClientError as e:
            results.append({
                "account_id": account_id,
                "account_name": entry["account_name"],
                "is_management": account_id == current_account_id,
                "status": "failed",
                "error": f"SSO GetRoleCredentials failed (role {entry['role_name']}): {e.response.get('Error', {}).get('Code', 'Unknown')}",
                "regions": [],
            })
            continue

        results.append(_scan_one_account(
            account_session,
            account_id,
            entry["account_name"],
            is_management=(account_id == current_account_id),
        ))

    return results


def _scan_one_account(session, account_id, account_name, is_management):
    try:
        regions = scan_account(session)
        return {
            "account_id": account_id,
            "account_name": account_name,
            "is_management": is_management,
            "status": "completed",
            "error": None,
            "regions": regions,
        }
    except ClientError as e:
        return {
            "account_id": account_id,
            "account_name": account_name,
            "is_management": is_management,
            "status": "failed",
            "error": f"{e.response.get('Error', {}).get('Code', 'Unknown')}: {e.response.get('Error', {}).get('Message', str(e))}",
            "regions": [],
        }
    except Exception as e:
        return {
            "account_id": account_id,
            "account_name": account_name,
            "is_management": is_management,
            "status": "failed",
            "error": str(e),
            "regions": [],
        }
