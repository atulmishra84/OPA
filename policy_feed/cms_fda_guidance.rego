package gatekeeper

violations[v] {
    artifact := input.artifacts[_]
    required := artifact.metadata.cms_guidance_required
    required == true
    not has_guidance_version(artifact)
    v := {
        "artifact": artifact.name,
        "type": artifact.type,
        "rule": "cms-guidance-version-required",
        "message": sprintf("Artifact '%s' requires CMS/FDA guidance annotation", [artifact.name])
    }
}

has_guidance_version(artifact) {
    annotations := artifact.metadata.annotations
    annotations.cms_guidance_version != ""
}
