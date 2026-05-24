import litellm


class ProviderRouter:
    """
    Thin wrapper around LiteLLM for the /v1/chat/completions path.

    The client passes real model strings (e.g. "claude-haiku-4-5-20251001",
    "gpt-4o", "ollama/llama3"). LiteLLM auto-detects the upstream provider
    from the model name and reads credentials from environment variables.
    No model mapping or alias resolution is performed here.
    """

    def __init__(self) -> None:
        litellm.suppress_debug_info = True

    async def call(
        self,
        messages: list[dict],
        model: str | None = None,
        stream: bool = False,
        api_key: str | None = None,
        **kwargs,
    ):
        if not model:
            raise ValueError("model is required for /v1/chat/completions")
        return await litellm.acompletion(
            model=model,
            messages=messages,
            stream=stream,
            api_key=api_key,
            **kwargs,
        )
