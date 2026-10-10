"""WebPassword rules and generation."""

from __future__ import annotations

from dataclasses import dataclass, field
import secrets
import string

MIN_LENGTH = 8
MAX_LENGTH = 32  # Tasmota stores at most 32 characters
# Printable ASCII without space (the command parser splits on it) and ';' (Backlog
# separator). "0" and "1" are reserved: they clear or reset the password.
_FORBIDDEN = {" ", ";"}
_RESERVED = {"0", "1"}
# Generated passwords avoid characters that are awkward to type or to URL-encode.
_ALPHABET = string.ascii_letters + string.digits + "-_.!@#%+="
GENERATED_LENGTH = 20


def password_problem(password: str) -> str | None:
    """Translation key of the first problem with the password, or None if it is valid."""
    if password in _RESERVED:
        return "password_reserved"
    if not MIN_LENGTH <= len(password) <= MAX_LENGTH:
        return "password_length"
    if any(ch in _FORBIDDEN or not (33 <= ord(ch) <= 126) for ch in password):
        return "password_chars"
    return None


def generate_password() -> str:
    """Random password valid for Tasmota."""
    while True:
        password = "".join(secrets.choice(_ALPHABET) for _ in range(GENERATED_LENGTH))
        # At least one letter and one digit, so it never looks like a number.
        if any(c.isalpha() for c in password) and any(c.isdigit() for c in password):
            return password


@dataclass(slots=True)
class ApplyResult:
    """Outcome of setting the WebPassword on several devices (names, not MACs)."""

    applied: list[str] = field(default_factory=list)
    already: list[str] = field(default_factory=list)  # already had this password
    other_password: list[str] = field(default_factory=list)  # protected, different pw
    offline: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)  # set but not verified, or errors

    @property
    def ok(self) -> bool:
        """Nothing left to do."""
        return not (self.other_password or self.offline or self.failed)
