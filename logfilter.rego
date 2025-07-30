package logfilter

# Mapping of language to disallowed debug patterns
debug_patterns = {
    "JavaScript": "console.log",
    "Node.js": "console.log",
    "Python": "print",
    "Java": "System.out.println",
    "C#": "Console.WriteLine",
    "Go": "fmt.Println"
}

# Deny rule based on language and debug pattern
deny[reason] {
    lang := input.log.language
    msg := input.log.message
    pattern := debug_patterns[lang]
    contains(lower(msg), lower(pattern))
    reason := sprintf("Blocked debug log for language '%s' due to pattern '%s'", [lang, pattern])
}
