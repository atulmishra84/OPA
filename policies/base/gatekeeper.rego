package gatekeeper

# Primary entry point that the API queries to receive all policy violations.
violations[v] {
    artifact := input.artifacts[_]
    lower(artifact.type) == "terraform"
    v := terraform_security_group_open(artifact)
}

violations[v] {
    artifact := input.artifacts[_]
    lower(artifact.type) == "kubernetes"
    v := kubernetes_runs_as_root(artifact)
}

violations[v] {
    artifact := input.artifacts[_]
    lower(artifact.type) == "helm"
    v := kubernetes_runs_as_root(artifact)
}

violations[v] {
    artifact := input.artifacts[_]
    lower(artifact.type) == "container_image"
    v := image_not_cosign_signed(artifact)
}

# Terraform compliance: security groups must not allow 0.0.0.0/0 ingress or egress.
terraform_security_group_open(artifact) = violation {
    sg := artifact.content.security_groups[_]
    rule := sg.rules[_]
    cidr := rule.cidr
    cidr == "0.0.0.0/0"
    violation := {
        "artifact": artifact.name,
        "type": "terraform",
        "rule": "sg-no-open-ingress",
        "message": sprintf("Security group '%s' exposes rule '%s' to 0.0.0.0/0", [sg.name, rule.name])
    }
}

# Kubernetes/Helm compliance: every pod must run as non-root.
kubernetes_runs_as_root(artifact) = violation {
    pod := artifact.content.pods[_]
    not pod_runs_as_non_root(pod)
    violation := {
        "artifact": artifact.name,
        "type": artifact.type,
        "rule": "pods-must-run-as-non-root",
        "message": sprintf("Pod '%s' is missing runAsNonRoot security context", [pod.name])
    }
}

pod_runs_as_non_root(pod) {
    security := pod.securityContext
    security.runAsNonRoot == true
}

pod_runs_as_non_root(pod) {
    container := pod.containers[_]
    security := container.securityContext
    security.runAsNonRoot == true
}

# Container image compliance: images must be cosign verified.
image_not_cosign_signed(artifact) = violation {
    not artifact.content.cosign_verified
    violation := {
        "artifact": artifact.name,
        "type": "container_image",
        "rule": "image-must-be-cosign-signed",
        "message": sprintf("Container image '%s' is not cosign signed", [artifact.content.image])
    }
}

allow {
    count(violations) == 0
}
