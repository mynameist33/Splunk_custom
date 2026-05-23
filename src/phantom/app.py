from typing import Any

from soar_sdk.action_results import ActionResult


APP_SUCCESS = True
APP_ERROR = False

ACTION_ID_TEST_ASSET_CONNECTIVITY = "test_asset_connectivity"

APP_JSON_ACTION_NAME = "action_name"
APP_JSON_APP_RUN_ID = "app_run_id"
APP_JSON_CONTAINER_COUNT = "container_count"
APP_JSON_DEVICE = "device"
APP_JSON_IP_HOSTNAME = "ip_hostname"
APP_JSON_PASSWORD = "password"
APP_JSON_PORT = "port"
APP_JSON_USERNAME = "username"
APP_JSON_VERIFY = "verify_server_cert"

APP_PROG_CONNECTING_TO_ELLIPSES = "Connecting to {}"
APP_ERR_FILE_ADD_TO_VAULT = "Error adding file to Vault: {err}"


def is_fail(status: Any) -> bool:
    return not bool(status)


def get_value(data: dict[str, Any] | None, key: str, default: Any = None) -> Any:
    if not isinstance(data, dict):
        return default
    return data.get(key, default)


__all__ = [
    "ACTION_ID_TEST_ASSET_CONNECTIVITY",
    "APP_ERROR",
    "APP_ERR_FILE_ADD_TO_VAULT",
    "APP_JSON_ACTION_NAME",
    "APP_JSON_APP_RUN_ID",
    "APP_JSON_CONTAINER_COUNT",
    "APP_JSON_DEVICE",
    "APP_JSON_IP_HOSTNAME",
    "APP_JSON_PASSWORD",
    "APP_JSON_PORT",
    "APP_JSON_USERNAME",
    "APP_JSON_VERIFY",
    "APP_PROG_CONNECTING_TO_ELLIPSES",
    "APP_SUCCESS",
    "ActionResult",
    "get_value",
    "is_fail",
]
