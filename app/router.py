import litellm

from app.config import AppConfig


class ProviderRouter:
    """
    Routes obfuscated prompts to LLM providers via LiteLLM.

    Resolves model aliases (e.g., "smart" -> "claude-opus-4-5"), configures
    fallback chains, and delegates to litellm.acompletion().
    """

    def __init__(self, config: AppConfig) -> None:
        self._alias_map = {p.alias: p.model for p in config.providers}
        self._default_alias = config.router.default_alias
        self._fallback_chain = config.router.fallback_chain

        litellm.suppress_debug_info = True

    def _resolve_model(self, model_or_alias: str | None) -> str:
        """
        Resolve a model alias to a LiteLLM model string.

        If the value is not a known alias, treat it as a literal model string
        (pass-through), allowing clients to specify e.g. 'gpt-4o' directly.
        """
        if model_or_alias is None:
            return self._alias_map[self._default_alias]
        return self._alias_map.get(model_or_alias, model_or_alias)

    async def call(
        self,
        messages: list[dict],
        model: str | None = None,
        stream: bool = False,
        **kwargs,
    ):
        """
        Call LiteLLM with the resolved model and fallback chain.

        Returns a LiteLLM ModelResponse (non-streaming) or
        async generator (streaming).
        """
        resolved = self._resolve_model(model)

        fallback_models = [
            self._alias_map[alias]
            for alias in self._fallback_chain
            if alias != model and self._alias_map.get(alias) != resolved
        ]

        return await litellm.acompletion(
            model=resolved,
            messages=messages,
            stream=stream,
            fallbacks=fallback_models if fallback_models else None,
            **kwargs,
        )
