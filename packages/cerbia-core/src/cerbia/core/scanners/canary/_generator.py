import hashlib
import secrets
import time


class CanaryTokenGenerator:
    """Generates unique canary tokens to embed in system prompts.

    Args:
        token_prefix (str): Prefix for generated tokens.
        token_length (int): Length of the hash portion of the token.
        namespace (str): Namespace prefix used in the hash seed.
        inject_format (str): Format string for prompt injection with ``{canary}`` placeholder.
    """

    def __init__(
        self,
        token_prefix: str = "CANARY-",
        token_length: int = 32,
        namespace: str = "cerbia",
        inject_format: str = "<-@!-- {canary} --@!->",
    ) -> None:
        self._token_prefix = token_prefix
        self._token_length = token_length
        self._namespace = namespace
        self._inject_format = inject_format

    def generate(self) -> str:
        """Create a new unique canary token.

        Returns:
            str: A token string in the form ``{prefix}{hash}`` where ``hash`` is a SHA-256 hash of a random seed and
            timestamp cropped to the specified length.
        """
        entropy = secrets.token_hex(16)
        timestamp = str(time.time_ns())

        raw = f"{self._namespace}:{entropy}:{timestamp}"
        token_hash = hashlib.sha256(raw.encode()).hexdigest()[: self._token_length]

        return f"{self._token_prefix}{token_hash}"

    def inject(self, prompt: str) -> tuple[str, str]:
        """Generate a canary token and inject it into a prompt.

        Args:
            prompt (str): The system prompt to inject into.

        Returns:
            tuple[str, str]: ``(modified_prompt, token)``.
        """
        token = self.generate()
        header = self._inject_format.format(canary=token)

        return f"{header}\n{prompt}", token
