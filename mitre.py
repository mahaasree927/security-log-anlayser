"""MITRE ATT&CK mapping used by every detection rule."""

TECHNIQUES = {
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access"),
    "T1078":     ("Valid Accounts", "Initial Access"),
    "T1078.003": ("Valid Accounts: Local Accounts", "Initial Access"),
    "T1046":     ("Network Service Discovery", "Discovery"),
}


def describe(technique_id):
    """Return (name, tactic) for a technique ID."""
    return TECHNIQUES.get(technique_id, ("Unknown technique", "Unknown"))
