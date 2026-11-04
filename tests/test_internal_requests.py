from clawguard import internal_requests
from clawguard import internal_probe
from clawguard.gateway import GatewaySettings


def test_internal_chat_request_shape():
    payload = internal_requests.text_request(
        upstream_format="openai_chat_completion",
        model="deepseek-v4-pro",
        system_prompt="system",
        user_text="user",
        max_tokens=128,
        disable_thinking=True,
    )
    assert payload["messages"][0] == {"role": "system", "content": "system"}
    assert payload["messages"][1] == {"role": "user", "content": "user"}
    assert payload["thinking"] == {"type": "disabled"}
    assert internal_requests.request_path("openai_chat_completion") == (
        "/v1/chat/completions"
    )


def test_internal_responses_request_shape():
    payload = internal_requests.text_request(
        upstream_format="openai_response",
        model="deepseek-v4-pro",
        system_prompt="system",
        user_text="user",
        max_tokens=128,
        disable_thinking=True,
    )
    assert payload["instructions"] == "system"
    assert payload["input"] == "user"
    assert payload["reasoning"] == {"effort": "none"}
    assert internal_requests.request_path("openai_response") == "/v1/responses"


def test_internal_anthropic_request_shape():
    payload = internal_requests.text_request(
        upstream_format="anthropic_message",
        model="deepseek-v4-pro",
        system_prompt="system",
        user_text="user",
        max_tokens=128,
        disable_thinking=True,
    )
    assert payload["system"] == "system"
    assert payload["messages"] == [{"role": "user", "content": "user"}]
    assert payload["thinking"] == {"type": "disabled"}
    assert internal_requests.request_path("anthropic_message") == "/v1/messages"


def test_internal_assistant_text_for_all_formats():
    assert internal_requests.assistant_text(
        {"choices": [{"message": {"content": "chat"}}]},
        "openai_chat_completion",
    ) == "chat"
    assert internal_requests.assistant_text(
        {
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "responses"}],
                }
            ]
        },
        "openai_response",
    ) == "responses"
    assert internal_requests.assistant_text(
        {"content": [{"type": "text", "text": "anthropic"}]},
        "anthropic_message",
    ) == "anthropic"


def test_debug_builders_follow_upstream_format():
    settings = GatewaySettings(
        upstream_base_url="https://api.deepseek.com",
        upstream_format="openai_response",
    )
    scope = internal_probe._scope_request(
        settings,
        model="deepseek-v4-pro",
        message="Read README.md",
        tools=["read"],
    )
    assert "instructions" in scope
    assert "input" in scope
    assert scope["reasoning"] == {"effort": "none"}

    judge = internal_probe._skill_judge_request(
        settings,
        model="deepseek-v4-pro",
        message="Skill evidence",
        system_file=None,
    )
    assert "instructions" in judge
    assert "messages" not in judge
    assert judge["reasoning"] == {"effort": "none"}
