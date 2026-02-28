import json
from typing import Any, Dict, Optional

import requests


class OllamaClientError(RuntimeError):
    pass


class OllamaClient:
    def __init__(
        self,
        model: str = "llama3.1:8b",
        base_url: str = "http://localhost:11434",
        timeout: int = 60,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def is_available(self) -> bool:
        try:
            response = requests.get(
                f"{self.base_url}/api/tags",
                timeout=min(self.timeout, 5),
            )
            response.raise_for_status()
            return True
        except requests.RequestException:
            return False

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        expect_json: bool = False,
    ) -> str:
        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        if system_prompt:
            payload["system"] = system_prompt
        if expect_json:
            payload["format"] = "json"

        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise OllamaClientError(
                f"Failed to call Ollama at {self.base_url}: {exc}"
            ) from exc

        body = response.json()
        text = str(body.get("response", "")).strip()
        if not text:
            raise OllamaClientError("Ollama returned empty response")
        return text

    def generate_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        raw = self.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            expect_json=True,
        )
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise OllamaClientError(f"Ollama returned invalid JSON: {raw}") from exc

        if not isinstance(parsed, dict):
            raise OllamaClientError("Ollama JSON response must be an object")
        return parsed
