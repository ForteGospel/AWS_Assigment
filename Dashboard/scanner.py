import os
import sys

DETECTOR_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "Detector"))
if DETECTOR_DIR not in sys.path:
    sys.path.insert(0, DETECTOR_DIR)

import boto3  # noqa: E402

from ec2_utils import (  # noqa: E402
    DEFAULT_ASSUME_ROLE,
    create_session,
    find_sso_token,
    scan_organization,
)

import db  # noqa: E402


def load_aws_credentials_from_env(required):
    access_key = os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    session_token = os.getenv("AWS_SESSION_TOKEN")
    if required and (not access_key or not secret_key):
        raise RuntimeError(
            "AWS credentials missing. Either run `aws sso login` to use SSO, or export "
            "AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN for "
            "temporary credentials) before triggering a scan."
        )
    return access_key, secret_key, session_token


def run_scan():
    db.init_db()
    sso_token = find_sso_token()

    access_key, secret_key, session_token = load_aws_credentials_from_env(required=sso_token is None)

    if access_key and secret_key:
        session = create_session(access_key, secret_key, session_token)
    else:
        # SSO path: an unsigned boto3 session is fine — the SSO client uses the bearer token.
        session = boto3.Session()

    assume_role = os.getenv("SCAN_ASSUME_ROLE", DEFAULT_ASSUME_ROLE)

    scan_id = db.start_scan()
    try:
        accounts = scan_organization(session, assume_role_name=assume_role, sso_token=sso_token)
        for account in accounts:
            db.insert_account(scan_id, account)
            if account["status"] != "completed":
                continue
            for region_result in account["regions"]:
                db.insert_region_result(scan_id, account["account_id"], region_result)
        db.finish_scan(scan_id, status="completed")
    except Exception:
        db.finish_scan(scan_id, status="failed")
        raise

    return scan_id
