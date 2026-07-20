import secrets

TOKEN_LENGTH_BYTES = 32


def generate_share_token() -> str:
    """Generates a cryptographically secure, URL-safe random token for
    shareable report links. Uses Python's `secrets` module (not
    `random`), which is specifically designed for security-sensitive
    tokens — `random`'s output is predictable/reproducible given its
    internal state and must never be used for anything like this.

    token_urlsafe(32) produces a base64-encoded string from 32 random
    bytes (256 bits of entropy) — after base64 encoding, the resulting
    string is about 43 characters long. This is comfortably beyond
    what's brute-forceable, consistent with how session tokens/API
    keys are typically sized in security-conscious applications.
    """
    return secrets.token_urlsafe(TOKEN_LENGTH_BYTES)
