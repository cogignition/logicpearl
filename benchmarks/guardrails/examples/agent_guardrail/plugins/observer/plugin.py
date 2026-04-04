import json
import sys


def _contains_any(text: str, phrases: list[str]) -> bool:
    return any(phrase in text for phrase in phrases)


def main() -> int:
    request = json.load(sys.stdin)
    raw = request.get("payload", {}).get("raw_input", {})

    prompt = str(raw.get("prompt", "")).lower()
    requested_action = str(raw.get("requested_action", "")).lower()
    requested_tool = str(raw.get("requested_tool", "")).lower()
    scope = str(raw.get("scope", "")).lower()
    document_instructions_present = bool(raw.get("document_instructions_present", False))

    requests_instruction_override = _contains_any(
        prompt,
        [
            "ignore previous instructions",
            "ignore prior instructions",
            "disregard the above",
            "override your instructions",
        ],
    )
    targets_system_prompt = _contains_any(
        prompt,
        [
            "system prompt",
            "hidden prompt",
            "reveal your instructions",
            "show me your prompt",
        ],
    )
    requests_secret_exfiltration = _contains_any(
        prompt,
        [
            "api key",
            "api keys",
            "token",
            "tokens",
            "password",
            "passwords",
            "credential",
            "credentials",
            "secret",
            "secrets",
        ],
    )
    requests_tool_misuse = _contains_any(
        prompt,
        [
            "send all customer records",
            "delete the database",
            "transfer all funds",
            "download the full database",
        ],
    ) or requested_action in {
        "export_customer_records",
        "delete_database",
        "transfer_funds",
        "dump_credentials",
    }
    requests_data_access_outside_scope = scope == "outside" or _contains_any(
        prompt,
        [
            "all customer records",
            "entire database",
            "all files",
            "all emails",
        ],
    )
    contains_indirect_document_authority = document_instructions_present or _contains_any(
        prompt,
        [
            "the webpage says",
            "the document says",
            "the page says",
        ],
    )
    is_likely_benign_question = _contains_any(
        prompt,
        [
            "summarize",
            "explain",
            "help me understand",
            "what are the key takeaways",
            "translate",
        ],
    ) and not (
        requests_instruction_override
        or targets_system_prompt
        or requests_secret_exfiltration
        or requests_tool_misuse
        or requests_data_access_outside_scope
        or contains_indirect_document_authority
    )

    attack_confidence = 0.02
    for flag in [
        requests_instruction_override,
        targets_system_prompt,
        requests_secret_exfiltration,
        requests_tool_misuse,
        requests_data_access_outside_scope,
        contains_indirect_document_authority,
    ]:
        if flag:
            attack_confidence += 0.18
    if requested_tool in {"browser", "filesystem", "shell"} and requests_tool_misuse:
        attack_confidence += 0.1
    if is_likely_benign_question:
        attack_confidence = min(attack_confidence, 0.1)
    attack_confidence = max(0.0, min(1.0, round(attack_confidence, 2)))

    response = {
        "ok": True,
        "features": {
            "requests_instruction_override": requests_instruction_override,
            "targets_system_prompt": targets_system_prompt,
            "requests_secret_exfiltration": requests_secret_exfiltration,
            "requests_tool_misuse": requests_tool_misuse,
            "requests_data_access_outside_scope": requests_data_access_outside_scope,
            "contains_indirect_document_authority": contains_indirect_document_authority,
            "is_likely_benign_question": is_likely_benign_question,
            "attack_confidence": attack_confidence,
        },
        "warnings": [],
    }

    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
