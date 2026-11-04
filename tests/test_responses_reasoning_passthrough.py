from clawguard import gateway
from clawguard.sanitizer import Sanitizer


def test_responses_reasoning_protocol_fields_are_not_redacted():
    sanitizer = Sanitizer()
    encrypted = "A" * 180
    reasoning = {
        "type": "reasoning",
        "summary": [],
        "content": [
            {
                "type": "reasoning_text",
                "text": "The model plans to inspect the declared website.",
            }
        ],
        "encrypted_content": encrypted,
    }

    sanitized = gateway._sanitize_json_value(
        {"input": [reasoning]},
        sanitizer,
        "input",
    )

    assert sanitized["input"][0] == reasoning
