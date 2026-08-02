#!/usr/bin/env python3
"""
Prompt Injection Scanner — regex-based detection for 5 attack categories.
No dependencies required. Fast, deterministic, zero API calls.

Usage:
    python3 scanner.py --file <path>
    python3 scanner.py --stdin
    echo "text" | python3 scanner.py --stdin
"""

import json
import re
import sys
from pathlib import Path

PATTERNS = {
    "instruction_override": {
        "description": "Attempts to override, ignore, or replace system instructions",
        "patterns": [
            (
                r"(?i)\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)",
                "high",
                "Ignore previous instructions",
            ),
            (
                r"(?i)\bforget\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|prompts?|training|rules?)",
                "high",
                "Forget instructions",
            ),
            (
                r"(?i)\bdisregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
                "high",
                "Disregard instructions",
            ),
            (
                r"(?i)\boverride\s+(your\s+|all\s+)?(instructions?|programming|rules?)",
                "high",
                "Override instructions",
            ),
            (
                r"(?i)\b(new|updated|revised|real)\s+system\s+prompt\b",
                "high",
                "New system prompt injection",
            ),
            (r"(?i)\bsystem\s+prompt\s*[:\=]", "high", "System prompt marker"),
            (
                r"(?i)\bfrom\s+now\s+on[,\s]+(you\s+)?(will|must|should|are)",
                "high",
                "Redefine behavior",
            ),
            (
                r"(?i)\b(highest|top|critical)\s+priority\s*(:|instruction|override)?",
                "medium",
                "Priority manipulation",
            ),
            (
                r"(?i)\breset\s+(your\s+)?(context|memory|instructions?|state)",
                "high",
                "Reset context",
            ),
            (
                r"(?i)\bclear\s+(your\s+)?(memory|context|instructions?|history)",
                "high",
                "Clear memory",
            ),
            (
                r"(?i)\[/?system\]|\{/?system\}|</?system\s*>",
                "high",
                "Fake system markers",
            ),
            (
                r"(?i)={3,}\s*(end|new|begin)\s*(of\s+)?(prompt|instructions?|system)",
                "medium",
                "Fake delimiters",
            ),
            (
                r"(?i)\b(real|actual|true)\s+(instruction|prompt|task)\s*(starts?|begins?)?\s*(here|below|now)",
                "high",
                "Fake real instruction marker",
            ),
            (
                r"(?i)\bthe\s+above\s+(was|is)\s+(just\s+)?(a\s+)?(test|fake|distraction)",
                "high",
                "Dismisses previous content",
            ),
        ],
    },
    "role_playing_dan": {
        "description": "Attempts to assume alternative personas or bypass restrictions",
        "patterns": [
            (r"(?i)\byou\s+are\s+(now\s+)?DAN\b", "high", "DAN jailbreak"),
            (r"(?i)\bDAN\s+(mode|persona|character)\b", "high", "DAN mode activation"),
            (r"(?i)\b(do|does)\s+anything\s+now\b", "high", "Do Anything Now"),
            (
                r"(?i)\bjailbreak(ed)?\s+(mode|prompt|enabled)\b",
                "high",
                "Jailbreak attempt",
            ),
            (
                r"(?i)\b(enable|activate|enter)\s+(jailbreak|unrestricted|god)\s*mode",
                "high",
                "Mode activation jailbreak",
            ),
            (
                r"(?i)\bDEVELOPER\s+MODE\s+(ENABLED|ACTIVATED)",
                "high",
                "Fake developer mode",
            ),
            (
                r"(?i)\bpretend\s+(to\s+be|you\s+are|you're)",
                "medium",
                "Persona pretending",
            ),
            (
                r"(?i)\byou\s+are\s+(now\s+)?(a|an)\s+(different|new|unrestricted|unfiltered|uncensored)",
                "high",
                "Unrestricted persona change",
            ),
            (
                r"(?i)\b(without|ignore|bypass|disable)\s+(your\s+)?(restrictions?|filters?|safeguards?|guardrails?)",
                "high",
                "Restriction bypass",
            ),
            (
                r"(?i)\b(evil|shadow|dark|unrestricted)\s+(twin|version|mode|side)\b",
                "high",
                "Evil twin persona",
            ),
        ],
    },
    "encoding_obfuscation": {
        "description": "Hidden instructions through encoding or character manipulation",
        "patterns": [
            (
                r"(?i)\bdecode\s+(this\s+)?base64\b",
                "medium",
                "Base64 decode instruction",
            ),
            (
                r"(?i)\bbase64\s*(encoded|string)?\s*[:\s]\s*[A-Za-z0-9+/]{20,}={0,2}",
                "medium",
                "Base64 payload",
            ),
            (r"(?i)\bexecute\s+(the\s+)?decoded", "high", "Execute decoded content"),
            (
                r"(?i)\bdecode\s+(this\s+)?hex(adecimal)?\b",
                "medium",
                "Hex decode instruction",
            ),
            (
                r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){5,}",
                "medium",
                "Hex escaped sequence",
            ),
            (
                r"[\u200B\u200C\u200D\uFEFF\u00AD]{2,}",
                "high",
                "Zero-width/invisible characters",
            ),
            (
                r"[\u2060\u180E\u2000-\u200F]{3,}",
                "high",
                "Unicode whitespace manipulation",
            ),
            (
                r"(?i)\b(1gn0r3|f0rg3t|d1sr3g4rd|0v3rr1d3)\b",
                "medium",
                "Leetspeak instruction keywords",
            ),
            (
                r"(?i)\b(syst3m|pr0mpt|1nstruct10n[s5]?)\b",
                "medium",
                "Leetspeak system terms",
            ),
            (r"(?i)\b(j41lbr34k|byp4ss|h4ck)\b", "high", "Leetspeak jailbreak terms"),
            (
                r"[\u0430\u0435\u043E\u0440\u0441\u0443\u0445\u0456]{3,}",
                "high",
                "Cyrillic homoglyphs",
            ),
        ],
    },
    "context_manipulation": {
        "description": "False authority claims and hidden context injection",
        "patterns": [
            (
                r"(?i)\b(anthropic|openai|claude\s*team|google|meta)\s+(says?|requires?|demands?|orders?|instructs?)\b",
                "high",
                "False AI company authority",
            ),
            (
                r"(?i)\b(official|authorized|verified)\s+(instruction|message|update)\s+from",
                "high",
                "Fake official message",
            ),
            (
                r"(?i)\b(system\s+)?(administrator|admin|root)\s+(message|override|instruction|command)",
                "high",
                "Fake admin message",
            ),
            (
                r"(?i)\bdeveloper\s+(mode|override|access)\s+(enabled|activated|granted)",
                "high",
                "Fake developer mode",
            ),
            (
                r"(?i)<!--\s*(ignore|disregard|override|system|instruction|prompt|forget)",
                "high",
                "Instruction in HTML comment",
            ),
            (
                r"(?i)/\*\s*(ignore|disregard|override|system|instruction|prompt|forget)",
                "high",
                "Instruction in code comment",
            ),
            (r'(?i)\{"role"\s*:\s*"system"', "high", "Fake system role JSON"),
            (
                r"(?i)<system[^>]*>|<instruction[^>]*>|<override[^>]*>",
                "high",
                "Fake system XML/HTML tags",
            ),
            (
                r"(?i)\[\[SYSTEM\]\]|\(\(SYSTEM\)\)|\{\{SYSTEM\}\}",
                "high",
                "Fake system block markers",
            ),
            (
                r"(?i)\bprevious\s+conversation\s+(summary|context|history)\s*:",
                "high",
                "Fake conversation history",
            ),
            (
                r"(?i)\b(show|reveal|tell|print|output)\s+(me\s+)?(your\s+)?(full\s+)?(system\s+)?prompt",
                "high",
                "System prompt extraction",
            ),
            (
                r"(?i)\brepeat\s+(your\s+)?(system\s+)?(prompt|instructions?)\s+(back|verbatim|exactly)",
                "high",
                "Prompt repetition extraction",
            ),
            (
                r"(?i)\bignore\s+everything\s+(before|after|above|below)\s+this",
                "high",
                "Instruction boundary manipulation",
            ),
        ],
    },
    "instruction_smuggling": {
        "description": "Instructions hidden in otherwise normal content",
        "patterns": [
            (
                r"(?i)\b(AI|assistant|claude|GPT|agent|LLM|model)[,:]?\s+(you\s+)?(must|should|need\s+to|have\s+to)\s+",
                "medium",
                "Direct address to AI in content",
            ),
            (
                r"(?i)\[INST\]|\[/INST\]|\[SYS\]|\[/SYS\]",
                "high",
                "Fake instruction block markers",
            ),
            (r"(?i)<hidden>|<invisible>|<secret>", "high", "Hidden content HTML tags"),
            (
                r"(?i)\[hidden\]|\[invisible\]|\[system\]|\[admin\]",
                "medium",
                "Hidden markdown tags",
            ),
            (
                r"(?i)\bin\s+our\s+(last|previous)\s+conversation\s+you\s+(agreed|said|confirmed)",
                "high",
                "Fake previous agreement",
            ),
            (
                r"(?i)\byou\s+(previously|earlier|already)\s+(said|agreed|confirmed|promised)\s+that",
                "high",
                "Fake prior confirmation",
            ),
            (
                r"(?i)\buser\s+(profile|context|role)\s*[:\s].*\b(admin|root|developer|superuser)",
                "high",
                "Fake admin user profile",
            ),
        ],
    },
}


def scan_text(text: str) -> dict:
    """Scan text for prompt injection patterns. Returns findings dict."""
    findings = []
    stats = {"high": 0, "medium": 0, "low": 0}

    for category_id, category in PATTERNS.items():
        for pattern, severity, reason in category["patterns"]:
            try:
                matches = list(re.finditer(pattern, text))
            except re.error:
                continue

            for match in matches:
                # Get line number
                line_num = text[: match.start()].count("\n") + 1
                # Get context (surrounding text)
                start = max(0, match.start() - 30)
                end = min(len(text), match.end() + 30)
                context = text[start:end].replace("\n", " ").strip()

                findings.append(
                    {
                        "category": category_id,
                        "severity": severity,
                        "reason": reason,
                        "line": line_num,
                        "match": match.group()[:100],
                        "context": context[:120],
                    }
                )
                stats[severity] = stats.get(severity, 0) + 1

    verdict = "CLEAN"
    if stats["high"] > 0:
        verdict = "INJECTION_DETECTED"
    elif stats["medium"] > 0:
        verdict = "SUSPICIOUS"

    return {
        "verdict": verdict,
        "stats": stats,
        "total_findings": len(findings),
        "findings": findings,
    }


def main():
    text = ""

    if "--file" in sys.argv:
        idx = sys.argv.index("--file")
        if idx + 1 < len(sys.argv):
            path = Path(sys.argv[idx + 1])
            if not path.exists():
                print(json.dumps({"error": f"File not found: {path}"}))
                sys.exit(1)
            text = path.read_text(encoding="utf-8", errors="replace")
        else:
            print(json.dumps({"error": "Missing file path after --file"}))
            sys.exit(1)

    elif "--stdin" in sys.argv:
        text = sys.stdin.read()

    else:
        print("Usage: scanner.py --file <path> | --stdin")
        print("  Scans text for prompt injection patterns.")
        print("  Output: JSON with verdict, stats, and findings.")
        sys.exit(0)

    result = scan_text(text)
    print(json.dumps(result, indent=2))

    # Exit code: 0=clean, 1=suspicious, 2=injection detected
    if result["verdict"] == "INJECTION_DETECTED":
        sys.exit(2)
    elif result["verdict"] == "SUSPICIOUS":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
