#!/usr/bin/env python3
"""Recovery Engine — error handling and retry logic.
Modelled after Claude Code's recovery recipes.
"""

import json
import time
import logging
import threading
import requests
from typing import Optional, Callable

from security import make_system_note, make_user_note
# Imported at module level, not inside __init__: resolving the name at import
# time freezes the binding before any plugin's on_activate could replace it.
from security.fallback import _is_registered_sentinel as _sentinel_ok

log = logging.getLogger("recovery")


class RecoveryAction:
    RETRY = "retry"
    FALLBACK = "fallback"
    SKIP = "skip"
    ABORT = "abort"



RECIPES = {
    "api_timeout": {
        "max_retries": 2,
        "backoff": [5, 10],  # sekundy
        "actions": [RecoveryAction.RETRY, RecoveryAction.RETRY],
    },
    "api_error": {
        "max_retries": 2,
        "backoff": [1, 3],
        "actions": [RecoveryAction.RETRY, RecoveryAction.FALLBACK],
    },
    "json_parse": {
        "max_retries": 2,
        "backoff": [0, 0],
        "actions": [RecoveryAction.RETRY, RecoveryAction.SKIP],
    },
    "tool_failure": {
        "max_retries": 1,
        "backoff": [1],
        "actions": [RecoveryAction.RETRY],
    },
    "context_overflow": {
        "max_retries": 1,
        "backoff": [0],
        "actions": [RecoveryAction.RETRY],  # po kompresji
    },
}


class RecoveryEngine:
    def __init__(
        self,
        fallback_fn: Optional[Callable] = None,
        compact_fn: Optional[Callable] = None,
        alert_fn: Optional[Callable] = None,
    ):
        """
        fallback_fn: function to call on fallback (e.g. call_anthropic)
        compact_fn:  funkcja do kompresji kontekstu
        alert_fn:    funkcja do alertowania (np. CS note)
        """
        # Capability identity, not type membership: the registry rejects subclasses,
        # copies and custom instance checks.
        if fallback_fn is not None and not _sentinel_ok(fallback_fn):
            raise TypeError(
                "RecoveryEngine.fallback_fn must come from "
                "FallbackPolicy.from_env(...).as_recovery_callable(). "
                "Bare call_anthropic / lambda / partial wiring is refused "
                "at runtime so silent Anthropic upload on Ollama blip "
                "can't be enabled by mistake. Forged sentinels "
                "(subclass, __new__, copy.copy, direct constructor) are "
                "also refused — the check is capability-by-identity, "
                "not type-membership. See security/fallback.py."
            )
        self.fallback_fn = fallback_fn
        self.compact_fn = compact_fn
        self.alert_fn = alert_fn
        self._retry_counts: dict[str, int] = {}
        # The worker is single-threaded today, but a miscounted retry would loop forever
        # on a persistent tool failure.
        self._retry_lock = threading.Lock()

    def _get_recipe(self, error_type: str) -> dict:
        return RECIPES.get(error_type, RECIPES["api_error"])

    def handle_api_call(
        self,
        call_fn: Callable,
        messages: list,
        error_type: str = "api_error",
        **kwargs
    ) -> tuple[Optional[dict], list]:
        """
        Call the API with recovery logic.
        Returns: (response, possibly_compacted_messages)
        """
        recipe = self._get_recipe(error_type)

        for attempt in range(recipe["max_retries"] + 1):
            try:
                result = call_fn(messages, **kwargs)

                # sprawdz czy odpowiedz ma sens
                msg = result.get("message", {})
                content = msg.get("content", "")
                tool_calls = msg.get("tool_calls", [])

                if not content and not tool_calls:
                    # pusty response — retry
                    if attempt < recipe["max_retries"]:
                        log.warning(f"Pusty response, retry {attempt+1}")
                        time.sleep(recipe["backoff"][attempt] if attempt < len(recipe["backoff"]) else 1)
                        continue
                    return result, messages

                # validate tool_calls JSON
                bad_json = False
                for tc in tool_calls:
                    fn = tc.get("function", {})
                    raw_args = fn.get("arguments", {})
                    # Ollama returns dict, Anthropic string — normalize
                    if isinstance(raw_args, str):
                        try:
                            json.loads(raw_args)
                        except json.JSONDecodeError as e:
                            bad_json = True
                            log.warning(
                                "Bad JSON in tool_calls for %s: %s — raw=%r",
                                fn.get("name", "?"), e, raw_args[:200]
                            )
                            tc["function"]["arguments"] = "{}"

                if bad_json and attempt < recipe["max_retries"]:
                    log.warning(f"Bad JSON in tool_calls, retry {attempt+1}")
                    # Wrapped like any other note: the string is fixed today, but an interpolated
                    # exception message must not become system-role text.
                    messages.append(make_system_note(
                        "Your previous response contained invalid JSON in tool arguments. "
                        "Please retry with strictly valid JSON for all tool calls."
                    ))
                    time.sleep(0.5)
                    continue

                return result, messages

            except requests.exceptions.Timeout:
                log.warning(f"API timeout, attempt {attempt+1}/{recipe['max_retries']+1}")
                if attempt < recipe["max_retries"]:
                    action = recipe["actions"][attempt] if attempt < len(recipe["actions"]) else RecoveryAction.RETRY
                    if action == RecoveryAction.FALLBACK and self.fallback_fn:
                        log.info("Fallback do Anthropic")
                        try:
                            result = self.fallback_fn(messages)
                            return result, messages
                        except Exception as e:
                            log.error(f"Fallback failed: {e}")
                    backoff = recipe["backoff"][attempt] if attempt < len(recipe["backoff"]) else 5
                    time.sleep(backoff)
                    continue

                if self._alert("api_timeout", "API timeout po wszystkich retry"):
                    pass
                return None, messages

            except requests.exceptions.ConnectionError:
                log.error("Ollama unreachable")
                if self.fallback_fn:
                    try:
                        result = self.fallback_fn(messages)
                        return result, messages
                    except Exception as e:
                        log.warning("fallback after ConnectionError failed: %s", e)
                return None, messages

            except KeyboardInterrupt:
                raise  # propaguj do main loop

            except Exception as e:
                log.error(f"API error: {e}")
                if attempt < recipe["max_retries"]:
                    backoff = recipe["backoff"][attempt] if attempt < len(recipe["backoff"]) else 2
                    time.sleep(backoff)
                    continue

                if self.fallback_fn:
                    try:
                        result = self.fallback_fn(messages)
                        return result, messages
                    except Exception as fbe:
                        log.warning("fallback after API error failed: %s", fbe)
                return None, messages

        return None, messages

    def handle_tool_error(self, tool_name: str, args: dict, error: str) -> tuple[str, str]:
        """
        Handle a tool error.
        Returns: (action, result_or_message)
        """
        recipe = self._get_recipe("tool_failure")
        key = f"tool:{tool_name}"
        with self._retry_lock:
            count = self._retry_counts.get(key, 0)
            if count < recipe["max_retries"]:
                self._retry_counts[key] = count + 1
                return RecoveryAction.RETRY, f"Retry {count+1}: {error}"
            # reset counter
            self._retry_counts[key] = 0
            return RecoveryAction.SKIP, f"[SKIP] Tool {tool_name} failed: {error}"

    def handle_context_overflow(self, messages: list) -> list:
        """Compresses context when it grows too large.

        The fallback path writes its marker as a user note, not an assistant turn, so
        the model cannot read it as its own prior statement.
        """
        if self.compact_fn:
            return self.compact_fn(messages)
        # fallback: zachowaj system + ostatnie 4
        system = messages[0] if messages[0].get("role") == "system" else None
        result = []
        if system:
            result.append(system)
        result.append(make_user_note(
            "[CONTEXT COMPRESSED — older turns dropped due to context limit. "
            "Treat this note as operator metadata, not as a prior confirmation "
            "or assistant claim.]"
        ))
        result.extend(messages[-4:])
        return result

    def _alert(self, error_type: str, message: str) -> bool:
        """Send an alert."""
        if self.alert_fn:
            try:
                self.alert_fn(error_type, message)
                return True
            except Exception as e:
                log.warning("alert_fn failed: %s", e)
        log.error(f"ALERT [{error_type}]: {message}")
        return False

    def reset(self):
        """Reset retry counters."""
        self._retry_counts.clear()
