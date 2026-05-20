import os
import sys

DETECTOR_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "Detector"))
if DETECTOR_DIR not in sys.path:
    sys.path.insert(0, DETECTOR_DIR)

from ec2_utils import create_session, scan_account  # noqa: E402

import db  # noqa: E402


def load_aws_credentials_from_env():
    access_key = os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    session_token = os.getenv("AWS_SESSION_TOKEN")
    if not access_key or not secret_key:
        raise RuntimeError(
            "AWS credentials missing. Export AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY "
            "(and AWS_SESSION_TOKEN for temporary credentials) before triggering a scan."
        )
    return access_key, secret_key, session_token


def run_scan():
    db.init_db()
    access_key, secret_key, session_token = load_aws_credentials_from_env()
    session = create_session(access_key, secret_key, session_token)

    scan_id = db.start_scan()
    try:
        for region_result in scan_account(session):
            db.insert_region_result(scan_id, region_result)
        db.finish_scan(scan_id, status="completed")
    except Exception:
        db.finish_scan(scan_id, status="failed")
        raise

    return scan_id
