"""Benchmark evaluation scenarios with authentic telemetry and ground truth."""

from __future__ import annotations

from acip.types import ArtifactKind, Severity
from experiments.datasets.ground_truth import GroundTruthFinding, GroundTruthScenario

SSH_BRUTE_FORCE_LOG = (
    "Mar 10 03:11:01 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.55 port 44120 ssh2\n"  # noqa: E501
    "Mar 10 03:11:05 web01 sshd[1235]: Failed password for invalid user root from 203.0.113.55 port 44122 ssh2\n"  # noqa: E501
    "Mar 10 03:11:09 web01 sshd[1236]: Failed password for invalid user test from 203.0.113.55 port 44124 ssh2\n"  # noqa: E501
    "Mar 10 03:11:12 web01 sshd[1237]: Failed password for deploy from 203.0.113.55 port 44126 ssh2\n"  # noqa: E501
    "Mar 10 03:11:15 web01 sshd[1238]: Failed password for deploy from 203.0.113.55 port 44128 ssh2\n"  # noqa: E501
    "Mar 10 03:11:20 web01 sshd[1239]: Accepted password for deploy from 203.0.113.55 port 44130 ssh2\n"  # noqa: E501
    "Mar 10 03:11:25 web01 sudo[1245]:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow\n"  # noqa: E501
)

WEB_SQLI_LOG = (
    '198.51.100.44 - - [10/Mar/2026:04:15:20 +0000] "GET /products HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n'  # noqa: E501
    '198.51.100.44 - - [10/Mar/2026:04:15:22 +0000] "GET /products?id=1%27%20OR%201=1 HTTP/1.1" 200 4520 "-" "sqlmap/1.7"\n'  # noqa: E501
    '198.51.100.44 - - [10/Mar/2026:04:15:25 +0000] "GET /products?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 200 8192 "-" "sqlmap/1.7"\n'  # noqa: E501
    '198.51.100.44 - - [10/Mar/2026:04:15:30 +0000] "GET /../../../../etc/passwd HTTP/1.1" 403 210 "-" "Mozilla/5.0"\n'  # noqa: E501
)

MULTI_SOURCE_WEB_LOG = (
    '198.51.100.44 - - [10/Mar/2026:05:01:00 +0000] "GET /login HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'  # noqa: E501
    '198.51.100.44 - - [10/Mar/2026:05:01:05 +0000] "POST /login?user=admin%27%20OR%201=1 HTTP/1.1" 200 1200 "-" "Mozilla/5.0"\n'  # noqa: E501
)

MULTI_SOURCE_AUTH_LOG = (
    "Mar 10 05:02:10 srv1 sshd[4011]: Failed password for alice from 198.51.100.44 port 51100 ssh2\n"  # noqa: E501
    "Mar 10 05:02:15 srv1 sshd[4012]: Accepted password for alice from 198.51.100.44 port 51102 ssh2\n"  # noqa: E501
    "Mar 10 05:02:22 srv1 sudo[4020]:    alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash\n"  # noqa: E501
)

CLEAN_AUTH_LOG = (
    "Mar 10 08:00:01 web01 sshd[5001]: Accepted publickey for backup from 10.0.0.99 port 41000 ssh2: RSA SHA256:abc1234\n"  # noqa: E501
    "Mar 10 08:05:02 web01 CRON[5005]: (root) CMD (/usr/local/bin/check_disk.sh)\n"
    "Mar 10 08:10:01 web01 sshd[5010]: Accepted publickey for sysadmin from 10.0.0.100 port 41002 ssh2: RSA SHA256:def5678\n"  # noqa: E501
)

CLEAN_WEB_LOG = (
    '10.0.0.50 - - [10/Mar/2026:08:00:10 +0000] "GET /health HTTP/1.1" 200 45 "-" "Prometheus/2.40"\n'  # noqa: E501
    '10.0.0.50 - - [10/Mar/2026:08:00:25 +0000] "GET /metrics HTTP/1.1" 200 2300 "-" "Prometheus/2.40"\n'  # noqa: E501
    '10.0.0.51 - - [10/Mar/2026:08:01:10 +0000] "GET /index.html HTTP/1.1" 200 1420 "-" "Mozilla/5.0"\n'  # noqa: E501
)

# Benchmark Scenarios
SCENARIOS: dict[str, GroundTruthScenario] = {
    "ssh_brute_force_sudo": GroundTruthScenario(
        id="ssh_brute_force_sudo",
        name="SSH Brute Force with Sudo Privilege Escalation",
        description=(
            "SSH credential guessing followed by successful login and shadow file exfiltration"
        ),
        target_type="log",
        target_value="auth.log",
        artifacts=(("auth.log", SSH_BRUTE_FORCE_LOG, ArtifactKind.LINUX_AUTH_LOG),),
        expected_findings=(
            GroundTruthFinding(
                id="gt_ssh_bruteforce",
                title="SSH Password Guessing Attack",
                behavior_class="credential_access",
                technique_id="T1110.001",
                primary_entities=frozenset({"203.0.113.55", "deploy"}),
                severity=Severity.HIGH,
            ),
            GroundTruthFinding(
                id="gt_sudo_priv_esc",
                title="Privileged Sudo Execution to Shadow File",
                behavior_class="privilege_escalation",
                technique_id="T1548.003",
                primary_entities=frozenset({"deploy", "root"}),
                severity=Severity.HIGH,
            ),
        ),
        is_benign=False,
    ),
    "web_sqli_attack": GroundTruthScenario(
        id="web_sqli_attack",
        name="Web SQL Injection & Path Traversal Exploitation",
        description="Automated SQL injection probe followed by union select and traversal",
        target_type="log",
        target_value="access.log",
        artifacts=(("access.log", WEB_SQLI_LOG, ArtifactKind.WEB_SERVER_LOG),),
        expected_findings=(
            GroundTruthFinding(
                id="gt_sql_injection",
                title="SQL Injection Exploit",
                behavior_class="web_attack",
                technique_id="T1190",
                primary_entities=frozenset({"198.51.100.44"}),
                severity=Severity.HIGH,
            ),
        ),
        is_benign=False,
    ),
    "multi_source_attack_chain": GroundTruthScenario(
        id="multi_source_attack_chain",
        name="Multi-Source Ingress to Privilege Escalation Chain",
        description="Cross-source attack spanning web SQL injection and SSH host authentication",
        target_type="log",
        target_value="multi_source.log",
        artifacts=(
            ("access.log", MULTI_SOURCE_WEB_LOG, ArtifactKind.WEB_SERVER_LOG),
            ("auth.log", MULTI_SOURCE_AUTH_LOG, ArtifactKind.LINUX_AUTH_LOG),
        ),
        expected_findings=(
            GroundTruthFinding(
                id="gt_ms_web_attack",
                title="Web Exploitation Ingress",
                behavior_class="web_attack",
                technique_id="T1190",
                primary_entities=frozenset({"198.51.100.44"}),
                severity=Severity.HIGH,
            ),
            GroundTruthFinding(
                id="gt_ms_attack_chain",
                title="End-to-End Lateral Movement & Escalation Chain",
                behavior_class="attack_chain",
                technique_id="T1548.003",
                primary_entities=frozenset({"198.51.100.44", "alice"}),
                severity=Severity.HIGH,
            ),
        ),
        is_benign=False,
    ),
    "clean_benign_baseline": GroundTruthScenario(
        id="clean_benign_baseline",
        name="Clean Routine Operations Baseline",
        description="Routine sysadmin publickey logins, cron jobs, and health check requests",
        target_type="log",
        target_value="clean.log",
        artifacts=(
            ("auth.log", CLEAN_AUTH_LOG, ArtifactKind.LINUX_AUTH_LOG),
            ("access.log", CLEAN_WEB_LOG, ArtifactKind.WEB_SERVER_LOG),
        ),
        expected_findings=(),  # Zero attacks expected
        is_benign=True,
    ),
}
