from __future__ import annotations

import hashlib
import os
from contextlib import suppress
from pathlib import Path
from typing import Any

from soar_sdk.action_results import ActionResult


class BaseConnector:
    def __init__(self) -> None:
        self.action_results: list[ActionResult] = []
        self.action_identifier = ""
        self.config: dict[str, Any] = {}
        self._state: dict[str, Any] = {}
        self._saved_containers: list[dict[str, Any]] = []
        self._saved_artifacts: list[dict[str, Any]] = []
        self._status = True
        self._message = ""

    @staticmethod
    def _get_phantom_base_url() -> str:
        return "https://localhost:9999/"

    def get_product_installation_id(self) -> str:
        content = f"soar-sdk-{os.getpid()}".encode()
        return hashlib.sha256(content).hexdigest()

    def send_progress(
        self, progress_str_const: str, *args: object, **kwargs: object
    ) -> None:
        self.save_progress(progress_str_const, *args, **kwargs)

    def save_progress(
        self, progress_str_const: str, *args: object, **kwargs: object
    ) -> None:
        with suppress(IndexError, KeyError, ValueError):
            progress_str_const = progress_str_const.format(*args, **kwargs)
        print(progress_str_const)

    def error_print(self, tag: str, dump_object: object = "", **kwargs: object) -> None:
        if "dump_object" in kwargs:
            dump_object = kwargs["dump_object"]
        print(tag, dump_object)

    def debug_print(self, tag: str, dump_object: object = "", **_: object) -> None:
        print(tag, dump_object)

    def set_status(
        self,
        status_code: bool,
        status_message: str = "",
        *args: object,
        **kwargs: object,
    ) -> bool:
        with suppress(IndexError, KeyError, ValueError):
            status_message = status_message.format(*args, **kwargs)
        self._status = bool(status_code)
        self._message = status_message
        return self._status

    def get_status(self) -> bool:
        return self._status

    def get_message(self) -> str:
        return self._message

    def get_action_results(self) -> list[ActionResult]:
        return self.action_results

    def add_action_result(self, action_result: ActionResult) -> ActionResult:
        self.action_results.append(action_result)
        return action_result

    def get_action_identifier(self) -> str:
        return self.action_identifier

    def get_action_name(self) -> str:
        return self.action_identifier.replace("_", " ")

    def get_app_run_id(self) -> str:
        return "sdk-app-run"

    def get_container_id(self) -> int:
        return int(self.config.get("container_id") or 0)

    def save_container(
        self, container: dict[str, Any], fail_on_duplicate: bool = False
    ) -> tuple[bool, str, int | None]:
        self._saved_containers.append(container)
        return True, "Container captured for SDK polling", len(self._saved_containers)

    def save_artifacts(
        self, artifacts: list[dict[str, Any]] | dict[str, Any]
    ) -> tuple[bool, str, int | list[int]]:
        if isinstance(artifacts, dict):
            artifacts = [artifacts]
        self._saved_artifacts.extend(artifacts)
        return (
            True,
            "Artifacts captured for SDK polling",
            list(range(1, len(artifacts) + 1)),
        )

    def get_config(self) -> dict[str, Any]:
        return self.config

    def get_asset_id(self) -> str:
        return str(self.config.get("asset_id", ""))

    def get_app_id(self) -> str:
        return "f2fef467-93b5-455d-b5c9-4afcf0748b38"

    def get_state_dir(self) -> str:
        return str(
            Path(os.getenv("PHANTOM_HOME", "/opt/phantom"))
            / "local_data"
            / "app_states"
            / self.get_app_id()
        )

    def save_state(self, state: dict[str, Any]) -> None:
        self._state = state

    def load_state(self) -> dict[str, Any]:
        return self._state

    def _set_csrf_info(self, token: str, referer: str) -> None:
        return None

    def initialize(self) -> bool:
        return True

    def finalize(self) -> bool:
        return True

    def get_app_dir(self) -> str:
        return str(Path.cwd())
