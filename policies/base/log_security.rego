package logsecurity

# Patterns that represent verbose debug logging for various languages.
debug_patterns = {
    "javascript": "console.log",
    "node.js": "console.log",
    "python": "print",
    "java": "system.out.println",
    "c#": "console.writeline",
    "go": "fmt.println"
}

# Keywords that usually represent protected health information (PHI) fields.
phi_field_keywords := {"patient", "ssn", "mrn", "dob", "diagnosis", "medical", "treatment", "plan"}

# Regular expressions that match PHI-like values that must never appear in logs.
phi_patterns = [
    {
        "name": "us-ssn",
        "pattern": "(?i)\\b(?!000|666)[0-8][0-9]{2}[- ]?(?!00)[0-9]{2}[- ]?(?!0000)[0-9]{4}\\b",
        "message": "Log entry appears to contain a US social security number"
    },
    {
        "name": "mrn",
        "pattern": "(?i)mrn[:= ]?[0-9]{6,10}",
        "message": "Log entry appears to contain a medical record number"
    },
    {
        "name": "hipaa-email",
        "pattern": "(?i)[a-z0-9._%+-]+@(?:hospital|clinic|healthcare)\\.[a-z]{2,}",
        "message": "Log entry exposes an email address that looks like PHI"
    }
]

# Rule: Deny if debug logging pattern is detected for the language of the log entry.
deny[reason] {
    log := input.log
    log.message
    lang := lower(log.language)
    msg := lower(log.message)
    pattern := debug_patterns[lang]
    contains(msg, pattern)
    reason := sprintf("Blocked debug log for language '%s' due to pattern '%s'", [log.language, pattern])
}

# Rule: Deny when a field name hints that PHI data is present in the payload.
deny[reason] {
    source := log_sources[_]
    fields := source.fields
    fields[key]
    key_lower := lower(key)
    some keyword
    keyword := phi_field_keywords[_]
    contains(key_lower, keyword)
    reason := sprintf("%s field '%s' is considered PHI and must be redacted", [source.name, key])
}

# Rule: Deny when the message content matches well known PHI patterns (SSN, MRN, etc.).
deny[reason] {
    source := message_sources[_]
    pattern := phi_patterns[_]
    re_match(pattern.pattern, source.message)
    reason := sprintf("%s: %s", [source.name, pattern.message])
}

log_sources[s] {
    log := input.log
    log.fields
    s := {"name": "Log", "fields": log.fields}
}

log_sources[s] {
    response := input.response
    response.fields
    s := {"name": "Response", "fields": response.fields}
}

log_sources[s] {
    response := input.response
    body := response.body
    is_object(body)
    s := {"name": "Response body", "fields": body}
}

message_sources[s] {
    log := input.log
    msg := log.message
    is_string(msg)
    s := {"name": "Log entry", "message": msg}
}

message_sources[s] {
    log := input.log
    msg := log.message
    not is_string(msg)
    s := {"name": "Log entry", "message": json.marshal(msg)}
}

message_sources[s] {
    response := input.response
    body := response.body
    is_string(body)
    s := {"name": "Response body", "message": body}
}

message_sources[s] {
    response := input.response
    body := response.body
    not is_string(body)
    s := {"name": "Response body", "message": json.marshal(body)}
}

# Default allow is true when the deny set is empty.
allow {
    count(deny) == 0
}
