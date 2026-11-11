"""AI provider implementations: null (rules only), mock (tests), Anthropic Claude."""

from __future__ import annotations

import base64
import json
import time

from app.providers.ai.base import AI_OUTPUT_SCHEMA, SYSTEM_PROMPT, AIProvider, AIResult, sanitize_ai_output


class NullAIProvider(AIProvider):
    name = "null"
    model = "none"

    async def analyse(self, *, text: str | None, image_png: bytes | None, language: str) -> AIResult:
        return AIResult(provider=self.name, model=self.model, ok=False, error="ai_disabled")


class MockAIProvider(AIProvider):
    """Deterministic double. Simulates OCR for images and a prompt-injection attempt for tests."""

    name = "mock"
    model = "mock-1"

    def __init__(self, ocr_text: str = "", raw_output: dict | None = None):
        self._ocr = ocr_text
        self._raw = raw_output

    async def analyse(self, *, text: str | None, image_png: bytes | None, language: str) -> AIResult:
        raw = self._raw or {
            "extracted_text": self._ocr if image_png else "",
            "claimed_organisation": "",
            "signals": [],
        }
        analysed = (text or "") + "\n" + (self._ocr if image_png else "")
        extracted, org, signals, dropped = sanitize_ai_output(raw, analysed)
        return AIResult(
            provider=self.name,
            model=self.model,
            ok=True,
            extracted_text=extracted,
            claimed_organisation=org,
            signals=signals,
            dropped_signals=dropped,
            input_tokens=100,
            output_tokens=50,
        )


# Approximate EUR per million tokens, converted from USD list prices (Nov 2026). Estimates for cost monitoring
# only, not invoicing; review in the Phase 3 financial model.
_PRICES_EUR_PER_MTOK = {
    "claude-opus-5-5": (3.7, 18.5),
    "claude-sonnet-5-5": (1.85, 9.25),
    "claude-haiku-5-5": (0.093, 0.46),
}


class AnthropicProvider(AIProvider):
    name = "anthropic"

    def __init__(self, api_key: str, model: str, timeout: float, effort: str = "low"):
        import anthropic

        self.model = model
        self._effort = effort
        self._client = anthropic.AsyncAnthropic(api_key=api_key, timeout=timeout, max_retries=1)

    async def analyse(self, *, text: str | None, image_png: bytes | None, language: str) -> AIResult:
        import anthropic

        started = time.monotonic()
        content: list[dict] = []
        if image_png:
            content.append(
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/png",
                        "data": base64.standard_b64encode(image_png).decode(),
                    },
                }
            )
        content.append(
            {
                "type": "text",
                "text": f"Language hint: {language}\n<untrusted_content>\n{text or ''}\n</untrusted_content>",
            }
        )
        try:
            resp = await self._client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": content}],
                output_config={"effort": self._effort, "format": {"type": "json_schema", "schema": AI_OUTPUT_SCHEMA}},
            )
        except anthropic.RateLimitError:
            return self._fail(started, "rate_limited")
        except anthropic.APITimeoutError:
            return self._fail(started, "timeout")
        except anthropic.APIStatusError as exc:
            return self._fail(started, f"http_{exc.status_code}")
        except anthropic.APIConnectionError:
            return self._fail(started, "connection_error")
        latency = int((time.monotonic() - started) * 1000)
        in_tok = getattr(resp.usage, "input_tokens", 0) or 0
        out_tok = getattr(resp.usage, "output_tokens", 0) or 0
        pin, pout = _PRICES_EUR_PER_MTOK.get(self.model, (5.0, 25.0))
        cost = int(in_tok * pin + out_tok * pout)  # micro-EUR (EUR/Mtok * tokens = micro-EUR)
        if resp.stop_reason == "refusal":
            return AIResult(
                self.name,
                self.model,
                False,
                error="refusal",
                input_tokens=in_tok,
                output_tokens=out_tok,
                cost_micro_eur=cost,
                latency_ms=latency,
            )
        raw = next((b.text for b in resp.content if b.type == "text"), "")
        try:
            json.loads(raw)
        except ValueError:
            return AIResult(
                self.name,
                self.model,
                False,
                error="invalid_json",
                input_tokens=in_tok,
                output_tokens=out_tok,
                cost_micro_eur=cost,
                latency_ms=latency,
            )
        # Evidence must appear in the user's text or in the OCR text the model itself produced for an image.
        extracted, org, signals, dropped = sanitize_ai_output(raw, text or "")
        return AIResult(
            provider=self.name,
            model=self.model,
            ok=True,
            extracted_text=extracted,
            claimed_organisation=org,
            signals=signals,
            dropped_signals=dropped,
            input_tokens=in_tok,
            output_tokens=out_tok,
            cost_micro_eur=cost,
            latency_ms=latency,
        )

    def _fail(self, started: float, code: str) -> AIResult:
        return AIResult(self.name, self.model, False, error=code, latency_ms=int((time.monotonic() - started) * 1000))
