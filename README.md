# OPA Governance Toolkit

This project provides a reference implementation of an automated governance layer that
wraps a development platform with [Open Policy Agent](https://www.openpolicyagent.org/) (OPA)
policies. The toolkit demonstrates how to:

- Enforce HIPAA log redaction controls so protected health information (PHI) never reaches logs or API responses.
- Validate every generated Terraform, Helm or general Kubernetes YAML manifest before it is merged or applied.
- Apply compliance guardrails that ensure security groups are never opened to `0.0.0.0/0`,
  container images are cosign signed, and pods always run as non-root.
- Automatically adopt new governance rules as soon as they are published by a compliance team,
  removing the need for manual policy rollouts.

## Architecture Overview

```
┌────────────────┐        ┌──────────────────────────┐        ┌──────────────────┐
│ Developer Tool │ -----> │ Governance Flask API     │ -----> │ OPA Server       │
│ (CI/CD, IDE)   │        │ - PolicyManager pushes   │        │ - Evaluates Rego │
│                │ <----- │   and refreshes policies │ <----- │   policies       │
└────────────────┘        └──────────────────────────┘        └──────────────────┘
                                   ▲
                                   │ dynamic policy feed
                                   ▼
                           `policy_feed/*.rego`
```

* `app.py` exposes REST endpoints that delegate decisions to OPA.
* `PolicyManager` automatically publishes all Rego policies from `policies/base` and
  watches `policy_feed` for new rules from the compliance team.
* Each Rego module contributes to the `gatekeeper` and `logsecurity` packages which the
  API queries at run time.

## Endpoints

| Endpoint | Description |
| --- | --- |
| `POST /logs/check` | Validates that a log entry contains no PHI and does not include debug logging statements. |
| `POST /gatekeeper/validate` | Validates Terraform, Helm, Kubernetes YAML and container image metadata before a merge/apply. |
| `POST /policies/reload` | Forces an immediate republish of all policies. |
| `GET /policies/status` | Returns metadata about the currently loaded policies and the last sync times. |

### Log evaluation payload

```json
{
  "log": {
    "language": "python",
    "message": "Patient SSN 123-45-6789 saved",
    "fields": {
      "patient_name": "Jane Doe"
    }
  }
}
```

The `logsecurity` policy blocks common debugging statements and a rich set of PHI indicators
(field names and regular expressions for SSNs, MRNs, and medical emails).

### Gatekeeper payload

```json
{
  "artifacts": [
    {
      "type": "terraform",
      "name": "networking",
      "content": {
        "security_groups": [
          {
            "name": "web-sg",
            "rules": [
              {"name": "ingress", "cidr": "0.0.0.0/0"}
            ]
          }
        ]
      }
    },
    {
      "type": "kubernetes",
      "name": "api-pod",
      "content": {
        "pods": [
          {
            "name": "api",
            "containers": [
              {"name": "api", "securityContext": {"runAsNonRoot": false}}
            ]
          }
        ]
      },
      "metadata": {
        "cms_guidance_required": true,
        "annotations": {}
      }
    },
    {
      "type": "container_image",
      "name": "backend",
      "content": {"image": "registry/my/backend:1.2.3", "cosign_verified": true}
    }
  ]
}
```

OPA returns detailed violation messages for any artifacts that are not compliant. The example above would
produce three violations: an open security group, a pod that runs as root, and a CMS/FDA guidance annotation
violation supplied via the dynamic `policy_feed/cms_fda_guidance.rego` rule.

## Automated policy updates

The governance layer polls the `policy_feed` directory (or any directory supplied through the
`DYNAMIC_POLICY_DIR` environment variable). When a new `.rego` file is added, modified or removed the
`PolicyManager` publishes the change to OPA without needing to redeploy the API container. The supplied
`cms_fda_guidance.rego` file demonstrates how compliance teams can inject additional guardrails at run time.

## Running locally with Docker Compose

```bash
docker-compose up --build
```

The compose file starts both the OPA server and the governance API. Policies from `policies/base` are published at
startup, and any additional rules copied into `policy_feed` are detected automatically.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
FLASK_ENV=development python app.py
```

Unit tests (if added) can import the Flask application without requiring a running OPA instance because
policy publishing errors are logged but do not abort start-up.

## Repository layout

```
.
├── app.py                   # Flask API with policy synchronisation
├── policies
│   └── base                 # Default governance policies
│       ├── gatekeeper.rego
│       └── log_security.rego
├── policy_feed              # Dynamic policies sourced from compliance
│   └── cms_fda_guidance.rego
├── docker-compose.yml       # Sample environment with OPA and the API
├── Dockerfile
└── requirements.txt
```
