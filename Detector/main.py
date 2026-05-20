import sys
import os

from ec2_utils import (
    create_session,
    scan_account,
)

def load_aws_credentials():
    access_key = None
    secret_key = None
    session_token = None

    for arg in sys.argv[1:]:
        if arg.startswith("clientid="):
            access_key = arg.split("=", 1)[1]
        elif arg.startswith("secretid="):
            secret_key = arg.split("=", 1)[1]
        elif arg.startswith("sessiontoken="):
            session_token = arg.split("=", 1)[1]

    access_key = access_key or os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = secret_key or os.getenv("AWS_SECRET_ACCESS_KEY")
    session_token = session_token or os.getenv("AWS_SESSION_TOKEN")

    if not access_key or not secret_key:
        raise ValueError(
            "AWS credentials not provided.\n"
            "Usage: python main.py clientid=XXX secretid=YYY [sessiontoken=ZZZ]\n"
            "Or set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN for temporary credentials) environment variables."
        )

    return access_key, secret_key, session_token

def run_checks(session):
    findings = []
    for region_result in scan_account(session):
        findings.extend(region_result["findings"])
    return findings

def print_findings(findings):
    for find in findings:
        print(f"Severity: {find['severity']}")
        print(f"Resource: {find['resource']}")
        print(f"Issue: {find['issue']}")
        print(f"Details: {find['details']}")
        print(f"Remediation: {find['remediation']}")
        print("---------------------------------------------------------\n\n")
    

def main():
    try:
        access_key, secret_key, session_token = load_aws_credentials()
        session = create_session(access_key, secret_key, session_token)

        findings = run_checks(session)
        print_findings(findings)

    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    main()