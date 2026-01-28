"""Multi-provider LLM client for Claude and OpenAI."""

import json
import re
from typing import Any, Literal

import anthropic
import openai
from pydantic import BaseModel

from ftl_gen.config import Settings


class LLMClient:
    """Multi-provider LLM client supporting Claude and OpenAI."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or Settings()
        self._claude_client: anthropic.Anthropic | None = None
        self._openai_client: openai.OpenAI | None = None

    @property
    def provider(self) -> Literal["claude", "openai"]:
        return self.settings.llm_provider

    @property
    def model(self) -> str:
        return self.settings.llm_model

    def _get_claude_client(self) -> anthropic.Anthropic:
        if self._claude_client is None:
            self._claude_client = anthropic.Anthropic(
                api_key=self.settings.anthropic_api_key
            )
        return self._claude_client

    def _get_openai_client(self) -> openai.OpenAI:
        if self._openai_client is None:
            self._openai_client = openai.OpenAI(
                api_key=self.settings.openai_api_key
            )
        return self._openai_client

    def generate(
        self,
        prompt: str,
        system: str | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        """Generate text completion from LLM."""
        if self.provider == "claude":
            return self._generate_claude(prompt, system, max_tokens, temperature)
        else:
            return self._generate_openai(prompt, system, max_tokens, temperature)

    def _generate_claude(
        self,
        prompt: str,
        system: str | None,
        max_tokens: int,
        temperature: float,
    ) -> str:
        client = self._get_claude_client()

        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }

        if system:
            kwargs["system"] = system

        # Claude doesn't support temperature=0, use 0.01 instead
        if temperature > 0:
            kwargs["temperature"] = temperature

        response = client.messages.create(**kwargs)
        return response.content[0].text

    def _generate_openai(
        self,
        prompt: str,
        system: str | None,
        max_tokens: int,
        temperature: float,
    ) -> str:
        client = self._get_openai_client()

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )

        return response.choices[0].message.content or ""

    def generate_json(
        self,
        prompt: str,
        system: str | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.5,
    ) -> dict[str, Any]:
        """Generate JSON output from LLM."""
        json_prompt = f"""{prompt}

IMPORTANT: Return ONLY valid JSON with no additional text, markdown formatting, or code blocks.
Start your response with {{ and end with }}."""

        response = self.generate(json_prompt, system, max_tokens, temperature)
        return self._parse_json_response(response)

    def generate_structured(
        self,
        prompt: str,
        schema: type[BaseModel],
        system: str | None = None,
        max_tokens: int = 4096,
        max_retries: int = 2,
    ) -> BaseModel:
        """Generate structured output matching a Pydantic schema."""
        schema_json = schema.model_json_schema()

        structured_prompt = f"""{prompt}

Return a JSON object matching this schema:
```json
{json.dumps(schema_json, indent=2)}
```

IMPORTANT: Return ONLY valid JSON with no additional text or markdown. Start with {{ and end with }}."""

        for attempt in range(max_retries + 1):
            try:
                response = self.generate(structured_prompt, system, max_tokens, temperature=0.5)
                data = self._parse_json_response(response)
                return schema.model_validate(data)
            except Exception as e:
                if attempt == max_retries:
                    raise ValueError(f"Failed to generate valid structured output after {max_retries + 1} attempts: {e}")
                # Add error context for retry
                structured_prompt = f"""{prompt}

Previous attempt failed with error: {str(e)}

Please fix the error and return a valid JSON object matching this schema:
```json
{json.dumps(schema_json, indent=2)}
```

IMPORTANT: Return ONLY valid JSON with no additional text or markdown. Start with {{ and end with }}."""

    def _parse_json_response(self, response: str) -> dict[str, Any]:
        """Parse JSON from LLM response, handling markdown code blocks."""
        text = response.strip()

        # Remove markdown code blocks if present
        if text.startswith("```"):
            # Find the end of the opening fence
            first_newline = text.find("\n")
            if first_newline != -1:
                text = text[first_newline + 1:]
            # Remove closing fence
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()

        # Try to find JSON object in the text
        json_match = re.search(r'\{[\s\S]*\}', text)
        if json_match:
            text = json_match.group(0)

        return json.loads(text)

    def generate_list(
        self,
        prompt: str,
        item_schema: type[BaseModel],
        count: int = 3,
        system: str | None = None,
        max_tokens: int = 8192,
    ) -> list[BaseModel]:
        """Generate a list of structured items."""
        schema_json = item_schema.model_json_schema()

        list_prompt = f"""{prompt}

Generate exactly {count} items.

Return a JSON object with an "items" array containing {count} objects, each matching this schema:
```json
{json.dumps(schema_json, indent=2)}
```

Example format:
{{"items": [{{...}}, {{...}}, {{...}}]}}

IMPORTANT: Return ONLY valid JSON. Start with {{ and end with }}."""

        response = self.generate(list_prompt, system, max_tokens, temperature=0.7)
        data = self._parse_json_response(response)

        items = data.get("items", data.get("weapons", data.get("events", [])))
        if not isinstance(items, list):
            items = [data]

        return [item_schema.model_validate(item) for item in items[:count]]
