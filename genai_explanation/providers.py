"""Optional LLM providers for Part 4.

Part 4 works WITHOUT any provider (it then uses a template-based fallback).
To add a real LLM later, set SENTINEL_LLM_PROVIDER and the variables listed in
.env.example. To support a new service (for example IBM watsonx.ai), write one
function like _build_openai_compatible and add it to PROVIDERS at the bottom.

A provider is just a function:  call(system_prompt, user_prompt) -> reply text.
It must raise LLMError (with a safe message, never containing a key) on any failure.
"""
import json
import os
import socket
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_TIMEOUT = 20.0


class LLMError(Exception):
    """The LLM call failed or its answer was unusable. The message is safe to show."""


def load_env_file(path=None):
    """Read KEY=VALUE lines from genai_explanation/.env into os.environ.

    Values that are already set in the environment are never overridden.
    A missing file is fine and is silently ignored.
    """
    env_path = Path(path) if path else Path(__file__).resolve().parent / ".env"
    try:
        text = env_path.read_text(encoding="utf-8-sig")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _build_openai_compatible():
    """Provider for any OpenAI-compatible chat API (OpenAI, Groq, and others).

    Returns (call_function, None) or (None, warning_text).
    """
    api_key = os.environ.get("SENTINEL_LLM_API_KEY", "").strip()
    base_url = os.environ.get("SENTINEL_LLM_BASE_URL", "").strip()
    model = os.environ.get("SENTINEL_LLM_MODEL", "").strip()

    missing = [name for name, value in (("SENTINEL_LLM_API_KEY", api_key),
                                        ("SENTINEL_LLM_BASE_URL", base_url),
                                        ("SENTINEL_LLM_MODEL", model)) if not value]
    if missing:
        return None, ("Missing environment variable(s): " + ", ".join(missing)
                      + ". The template-based fallback was used.")
    local = base_url.startswith(("http://localhost", "http://127.0.0.1"))
    if not (base_url.startswith("https://") or local):
        return None, ("SENTINEL_LLM_BASE_URL must start with https://. "
                      "The template-based fallback was used.")
    try:
        timeout = float(os.environ.get("SENTINEL_LLM_TIMEOUT", DEFAULT_TIMEOUT))
        if timeout <= 0:
            raise ValueError
    except ValueError:
        timeout = DEFAULT_TIMEOUT

    def call(system_prompt, user_prompt):
        body = {
            "model": model,
            "temperature": 0.2,
            "messages": [{"role": "system", "content": system_prompt},
                         {"role": "user", "content": user_prompt}],
        }
        request = urllib.request.Request(
            base_url.rstrip("/") + "/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer " + api_key},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as err:        # must come before URLError
            raise LLMError(f"The LLM API returned HTTP {err.code}.") from None
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError):
            raise LLMError("Could not reach the LLM API (network problem or timeout).") from None
        try:
            content = json.loads(raw)["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise LLMError("The LLM API response had an unexpected format.") from None
        if not isinstance(content, str):
            raise LLMError("The LLM API response had no text content.")
        return content

    return call, None


# Add new providers here: {"name used in SENTINEL_LLM_PROVIDER": builder_function}
PROVIDERS = {
    "openai_compatible": _build_openai_compatible,
}


def load_provider():
    """Pick a provider from the environment.

    Returns (call_function_or_None, provider_name_or_None, warning_or_None).
    No provider configured is a normal situation: the caller then uses the fallback.
    """
    load_env_file()
    name = os.environ.get("SENTINEL_LLM_PROVIDER", "").strip().lower()
    if name in ("", "none", "fallback"):
        return None, None, ("No LLM provider is configured (SENTINEL_LLM_PROVIDER is not set). "
                            "The template-based fallback was used.")
    builder = PROVIDERS.get(name)
    if builder is None:
        return None, None, ("Unknown SENTINEL_LLM_PROVIDER (known: "
                            + ", ".join(sorted(PROVIDERS))
                            + "). The template-based fallback was used.")
    call, warning = builder()
    if call is None:
        return None, None, warning
    return call, name, None