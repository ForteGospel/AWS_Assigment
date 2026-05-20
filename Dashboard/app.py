import traceback
from flask import Flask, redirect, render_template, request, url_for, flash

import db
import scanner

app = Flask(__name__)
app.secret_key = "local-dev-only"


@app.context_processor
def inject_latest_scan():
    return {"latest_scan": db.latest_scan()}


@app.route("/")
def overview():
    scan = db.latest_scan()
    summary = db.scan_summary(scan["id"]) if scan else None
    return render_template("overview.html", scan=scan, summary=summary)


@app.post("/scan")
def trigger_scan():
    try:
        scan_id = scanner.run_scan()
        flash(f"Scan #{scan_id} completed.", "success")
    except Exception as exc:
        traceback.print_exc()
        flash(f"Scan failed: {exc}", "error")
    return redirect(url_for("overview"))


@app.route("/resources")
def resources():
    scan = db.latest_scan()
    if not scan:
        return render_template("resources.html", scan=None)

    tab = request.args.get("tab", "instances")
    region = request.args.get("region") or None
    has_issue = request.args.get("has_issue") or None

    instances = db.list_instances(scan["id"], region=region, has_issue=has_issue) if tab == "instances" else []
    security_groups = db.list_security_groups(scan["id"], region=region) if tab == "security_groups" else []
    volumes = db.list_volumes(scan["id"], region=region) if tab == "volumes" else []

    summary = db.scan_summary(scan["id"])
    return render_template(
        "resources.html",
        scan=scan,
        tab=tab,
        region=region,
        has_issue=has_issue,
        instances=instances,
        security_groups=security_groups,
        volumes=volumes,
        regions=summary["regions"],
    )


@app.route("/resources/<instance_id>")
def resource_detail(instance_id):
    scan = db.latest_scan()
    if not scan:
        return redirect(url_for("overview"))
    instance = db.get_instance(scan["id"], instance_id)
    if not instance:
        return render_template("resource_detail.html", scan=scan, instance=None, instance_id=instance_id)
    return render_template("resource_detail.html", scan=scan, instance=instance)


@app.route("/findings")
def findings():
    scan = db.latest_scan()
    if not scan:
        return render_template("findings.html", scan=None, findings=[])

    severity = request.args.get("severity") or None
    region = request.args.get("region") or None
    issue_substring = request.args.get("issue") or None
    summary = db.scan_summary(scan["id"])

    rows = db.list_findings(
        scan["id"],
        severity=severity,
        region=region,
        issue_substring=issue_substring,
    )
    return render_template(
        "findings.html",
        scan=scan,
        findings=rows,
        severity=severity,
        region=region,
        issue=issue_substring,
        regions=summary["regions"],
    )


if __name__ == "__main__":
    db.init_db()
    app.run(host="127.0.0.1", port=5001, debug=True)
