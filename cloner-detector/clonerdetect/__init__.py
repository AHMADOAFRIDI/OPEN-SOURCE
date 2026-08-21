"""ClonerHunter - defensive scanner for Termux/Facebook "cloning" toolkits.

ClonerHunter detects credential-stuffing / account-takeover tooling by
fingerprinting the code, tokens, endpoints, headers and behaviour patterns
that this tool family uses. It is defensive software: it reads files and
logs, never sends traffic to any target, and never touches live accounts.
"""

__version__ = "1.0.0"
TOOL_NAME = "ClonerHunter"
TOOL_TAGLINE = "Defensive scanner for Termux/Facebook cloning toolkits"
