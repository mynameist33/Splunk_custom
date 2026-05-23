from typing import Any


def vault_add(
    container_id: int,
    file_location: str,
    file_name: str,
    metadata: dict[str, Any] | None = None,
) -> tuple[bool, str, str]:
    return True, "Vault file captured by SDK compatibility layer", file_location
