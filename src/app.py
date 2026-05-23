from typing import Any
from collections.abc import Iterator
from zoneinfo import ZoneInfo
from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.params import Param, Params, OnPollParams
from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.logging import getLogger
from soar_sdk.models.container import Container
from soar_sdk.models.artifact import Artifact

from .legacy_splunk_connector import SplunkConnector

logger = getLogger()


def _asset_config(asset: "Asset") -> dict[str, Any]:
    config = asset.model_dump(mode="python")
    if config.get("timezone") is not None:
        config["timezone"] = str(config["timezone"])
    return config


def _params_dict(params: Params | OnPollParams | dict[str, Any]) -> dict[str, Any]:
    if isinstance(params, dict):
        return {key: value for key, value in params.items() if value is not None}
    return params.model_dump(mode="python", by_alias=True, exclude_none=True)


def _legacy_result_to_sdk(
    connector: SplunkConnector, result: bool | None = None
) -> ActionResult:
    action_results = connector.get_action_results()
    if action_results:
        return action_results[-1]
    return ActionResult(status=bool(result), message=connector.get_message())


def _run_legacy_action(
    identifier: str,
    params: Params | OnPollParams | dict[str, Any],
    soar: SOARClient,
    asset: "Asset",
) -> tuple[SplunkConnector, ActionResult]:
    connector = SplunkConnector()
    connector.config = _asset_config(asset)
    connector.action_identifier = identifier
    connector.soar_client = soar
    connector.initialize()
    try:
        result = connector.handle_action(_params_dict(params))
    finally:
        connector.finalize()
    return connector, _legacy_result_to_sdk(connector, result)


def run_query_view_handler(
    action: str,
    all_app_runs: list[tuple[Any, list[ActionResult]]],
    context: Any,
) -> dict:
    results = []
    for _summary, action_results in all_app_runs:
        for result in action_results:
            param = result.get_param()
            data = result.get_data()
            headers = []
            processed_data = []
            if data:
                if param.get("display"):
                    headers = [
                        item.strip()
                        for item in param["display"].split(",")
                        if item.strip()
                    ]
                else:
                    headers = [key for key in data[0] if not key.startswith("_")]
                for item in data:
                    processed_data.append(
                        {header: item.get(header) for header in headers}
                    )
            results.append(
                {
                    "param": param,
                    "action_name": action,
                    "summary": result.get_summary(),
                    "data": data,
                    "processed_data": processed_data,
                    "headers": headers,
                }
            )
    return {"results": results}


class Asset(BaseAsset):
    device: str = AssetField(description="Device IP/Hostname")
    port: float | None = AssetField(description="Port", default=8089.0)
    username: str | None = AssetField(description="Username")
    password: str | None = AssetField(description="Password", sensitive=True)
    api_token: str | None = AssetField(description="API token", sensitive=True)
    splunk_owner: str | None = AssetField(
        description="The owner context of the namespace"
    )
    splunk_app: str | None = AssetField(description="The app context of the namespace")
    timezone: ZoneInfo = AssetField(description="Splunk Server Timezone")
    verify_server_cert: bool | None = AssetField(
        description="Verify Server Certificate", default=True
    )
    on_poll_command: str | None = AssetField(
        description="Command for query to use with On Poll",
        value_list=["", "search", "eval", "savedsearch", "stats", "table", "tstats"],
        category=FieldCategory.INGEST,
    )
    on_poll_query: str | None = AssetField(
        description="Query to use with On Poll", category=FieldCategory.INGEST
    )
    on_poll_display: str | None = AssetField(
        description="Fields to save with On Poll", category=FieldCategory.INGEST
    )
    on_poll_parse_only: bool | None = AssetField(
        description="Parse Only", default=True, category=FieldCategory.INGEST
    )
    max_container: float | None = AssetField(
        description="Max events to ingest for Scheduled Polling (Default: 100)",
        default=100.0,
        category=FieldCategory.INGEST,
    )
    container_update_state: float | None = AssetField(
        description="Container count to update the state file",
        default=100.0,
        category=FieldCategory.INGEST,
    )
    container_name_prefix: str | None = AssetField(
        description="Name to give containers created via ingestion",
        category=FieldCategory.INGEST,
    )
    container_name_values: str | None = AssetField(
        description="Values to append to container name", category=FieldCategory.INGEST
    )
    retry_count: float | None = AssetField(
        description="Number of retries", default=3.0, category=FieldCategory.ACTION
    )
    remove_empty_cef: bool | None = AssetField(
        description="Remove CEF fields having empty values from the artifact",
        default=True,
        category=FieldCategory.INGEST,
    )
    sleeptime_in_requests: float | None = AssetField(
        description="The time to wait for next REST call (max 120 seconds)",
        default=1.0,
        category=FieldCategory.ACTION,
    )
    include_cim_fields: bool | None = AssetField(
        description="Option to keep original Splunk CIM together with SOAR CEF fields",
        default=True,
        category=FieldCategory.INGEST,
    )
    splunk_job_timeout: float | None = AssetField(
        description="The duration in seconds to wait before a scheduled Splunk job times out",
        default=1200.0,
        category=FieldCategory.ACTION,
    )
    use_event_id_sdi: bool | None = AssetField(
        description="Option to use the event_id field value as the source data identifier instead of the full event hash",
        default=True,
        category=FieldCategory.INGEST,
    )
    poll_cursor_lookback_sec: float | None = AssetField(
        description="Polling cursor overlap window (seconds) (Default: 180)",
        default=180.0,
        category=FieldCategory.INGEST,
    )


app = App(
    name="Splunk_custom",
    app_type="siem",
    logo="logo_splunk.svg",
    logo_dark="logo_splunk_dark.svg",
    product_vendor="Splunk Inc._clone",
    product_name="Splunk Enterprise_clone",
    publisher="Splunk",
    appid="f2fef467-93b5-455d-b5c9-4afcf0748b38",
    fips_compliant=True,
    asset_cls=Asset,
)

run_query_view_handler = app.view_handler(template="splunk_run_query.html")(
    run_query_view_handler
)


@app.on_poll()
def on_poll(
    soar: SOARClient, asset: Asset, params: OnPollParams
) -> Iterator[Container | Artifact]:
    connector, result = _run_legacy_action("on_poll", params, soar, asset)
    if not result.get_status():
        raise RuntimeError(result.get_message())
    for container in connector._saved_containers:
        yield Container.model_validate(container)
    for artifact in connector._saved_artifacts:
        yield Artifact.model_validate(artifact)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    _connector, result = _run_legacy_action("test_asset_connectivity", {}, soar, asset)
    if not result.get_status():
        raise RuntimeError(result.get_message())


class GetHostEventsParams(Params):
    ip_hostname: str = Param(
        description="Hostname/IP to search the events of",
        primary=True,
        cef_types=["ip", "host name"],
    )
    last_n_days: float | None = Param(description="Number of days ago")


class GetHostEventsOutput(ActionOutput):
    bkt: str = OutputField(alias="_bkt")
    cd: str = OutputField(alias="_cd")
    indextime: str = OutputField(alias="_indextime")
    raw: str = OutputField(alias="_raw")
    serial: str = OutputField(alias="_serial")
    si: str = OutputField(alias="_si")
    sourcetype: str
    time: str = OutputField(alias="_time")
    host: str = OutputField(cef_types=["host name"])
    index: str
    linecount: str
    source: str
    splunk_server: str = OutputField(cef_types=["host name"])


@app.action(
    description="Get events pertaining to a host that have occurred in the last 'N' days",
    action_type="investigate",
    verbose="<ul><li>The <b>last_n_days</b> parameter must be greater than 0.</li><li>The action will search for the events of the hostname (provided in the 'ip_hostname' parameter) in the default index configured on the Splunk instance.</li></ul>",
)
def get_host_events(
    params: GetHostEventsParams, soar: SOARClient, asset: Asset
) -> GetHostEventsOutput:
    _connector, result = _run_legacy_action("get_host_events", params, soar, asset)
    return result


class RunQueryParams(Params):
    command: str | None = Param(
        description="Beginning command (in Splunk Processing Language)",
        default="search",
        value_list=["search", "eval", "savedsearch", "stats", "table", "tstats"],
    )
    query: str = Param(
        description="Query to run (in Splunk Processing Language)",
        primary=True,
        cef_types=["splunk query"],
    )
    display: str | None = Param(description="Display fields (comma-separated)")
    parse_only: bool | None = Param(description="Parse only", default=False)
    add_raw_field: bool | None = Param(
        description="Ingest _raw field data", default=True
    )
    attach_result: bool | None = Param(
        description="Attach result to the vault", default=False
    )
    start_time: str | None = Param(description="Earliest time modifier")
    end_time: str | None = Param(description="Latest time modifier")
    search_mode: str | None = Param(
        description="Search mode",
        default="smart",
        value_list=["fast", "verbose", "smart"],
    )
    time_format: str | None = Param(description="Custom timestamp format")


class ContentOutput(ActionOutput):
    app: str = OutputField(example_values=["search"])
    host: str = OutputField(example_values=["test"])
    info: str = OutputField(example_values=["granted"])
    search: str = OutputField(example_values=["index = main"])
    search_type: str = OutputField(example_values=["adhoc"])
    sid: str = OutputField(example_values=["1621953839.25275"])
    source: str = OutputField(example_values=["source"])
    sourcetype: str = OutputField(example_values=["source"])
    uri: str = OutputField(
        example_values=[
            "/en-US/app/search/search?q=search%20index%3Dmain%20%7C%20head%2010&sid=1651356328.532450&display.page.search.mode=smart&dispatch.sample_ratio=1&workload_pool=&earliest=-24h%40h&latest=now"
        ]
    )
    view: str = OutputField(example_values=["search"])


class RunQueryOutput(ActionOutput):
    bkt: str = OutputField(alias="_bkt")
    cd: str = OutputField(alias="_cd")
    indextime: str = OutputField(alias="_indextime")
    key: str = OutputField(example_values=["user"], alias="_key")
    kv: str = OutputField(example_values=["1"], alias="_kv")
    origtime: str = OutputField(example_values=["1659398400"], alias="_origtime")
    raw: str = OutputField(alias="_raw")
    serial: str = OutputField(alias="_serial")
    si: str = OutputField(alias="_si")
    sourcetype: str
    subsecond: str = OutputField(example_values=[".427"], alias="_subsecond")
    time: str = OutputField(alias="_time")
    value: str = OutputField(example_values=["184"], alias="_value")
    a: str = OutputField(example_values=["abc"])
    content: ContentOutput
    count: str = OutputField(example_values=["3058733"])
    count_host_: str = OutputField(example_values=["28"], alias="count(host)")
    event: str = OutputField(
        example_values=[
            '{"data": {"count": 3, "size": 112, "transform": "access_app_tracker"}, "version": "1.0"}'
        ]
    )
    host: str = OutputField(
        cef_types=["host name"], example_values=["10.1.67.187:8088"]
    )
    index: str
    is_Acceleration_Jobs: str = OutputField(example_values=["0"])
    is_Adhoc_Jobs: str = OutputField(example_values=["1"])
    is_Failed_Jobs: str = OutputField(example_values=["0"])
    is_Realtime_Jobs: str = OutputField(example_values=["0"])
    is_Scheduled_Jobs: str = OutputField(example_values=["0"])
    is_Subsearch_Jobs: str = OutputField(example_values=["0"])
    is_not_Acceleration_Jobs: str = OutputField(example_values=["1"])
    is_not_Adhoc_Jobs: str = OutputField(example_values=["0"])
    is_not_Failed_Jobs: str = OutputField(example_values=["1"])
    is_not_Realtime_Jobs: str = OutputField(example_values=["1"])
    is_not_Scheduled_Jobs: str = OutputField(example_values=["1"])
    is_not_Subsearch_Jobs: str = OutputField(example_values=["1"])
    linecount: str
    source: str
    spent: str = OutputField(example_values=["223"])
    splunk_server: str = OutputField(cef_types=["host name"])
    user: str = OutputField(example_values=["admin"])
    values_source_: str = OutputField(
        example_values=["/opt/splunk/var/log/splunk/scheduler.log"],
        alias="values(source)",
    )


@app.action(
    description="Run a search query on the Splunk device. Please escape any quotes that are part of the query string",
    action_type="investigate",
    verbose="By default, the widget for the &quot;run query&quot; action will show the host, time, and raw fields. If you would like to see specific fields parsed out, they can be listed in a comma-separated format in the &quot;display&quot; parameter.<br><br>Please keep in mind that Splunk does not always return all possible fields. Splunk may not return fields that are calculated or not present in the event.<br><br>To work around this you can force Splunk to return specific fields by using the &quot;fields&quot;. By appending &quot;| fields + *&quot; to your query, Splunk will return every field. You can replace the asterisk with a comma-separated list of fields to only return specific fields.<br><br>Finally, some searches (such as those based on data models) can contain name-spaced fields. If a data model called &quot;my_model&quot; with a search &quot;my_search&quot; has a field &quot;hash&quot; then the field will be named &quot;my_search.hash&quot; and that is what must be used in the Splunk fields command and the display parameter. If using a non-global lookup file that is only accessible by a specific Splunk App, make sure to note the specific Splunk App in your asset configuration. The <b>parse_only</b> parameter, if <b>True</b>, it disables the expansion of search due to evaluation of sub-searches, time term expansion, lookups, tags, eventtypes, and sourcetype alias. This parameter is used for the validation of the Splunk query before fetching the results.<br><br>Learn more below:<ul><li><a href='https://docs.splunk.com/Documentation/Splunk/8.2.5/SearchReference/SearchTimeModifiers' target='_blank'>Time modifiers</a></li><li><a href='https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch#search.2Fjobs' target='_blank'>Splunk REST APIs</a></li><li><a href='https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/howtousesplunkpython/howtorunsearchespython/' target='_blank'>Splunk SDK</a></li></ul>",
    view_handler=run_query_view_handler,
)
def run_query(params: RunQueryParams, soar: SOARClient, asset: Asset) -> RunQueryOutput:
    _connector, result = _run_legacy_action("run_query", params, soar, asset)
    return result


class UpdateEventParams(Params):
    event_ids: str = Param(
        description="Event ID to update",
        primary=True,
        cef_types=["splunk notable event id"],
    )
    owner: str | None = Param(description="New owner for the event")
    status: str | None = Param(
        description="New status for the event",
        value_list=[
            "",
            "unassigned",
            "new",
            "in progress",
            "pending",
            "resolved",
            "closed",
        ],
    )
    integer_status: float | None = Param(
        description="Integer representing custom status value"
    )
    urgency: str | None = Param(
        description="New urgency for the event",
        value_list=["", "informational", "low", "medium", "high", "critical"],
    )
    comment: str | None = Param(description="New comment for the event")
    disposition: str | None = Param(
        description="New disposition field",
        value_list=[
            "",
            "Unassigned",
            "True Positive - Suspicious Activity",
            "Benign Positive - Suspicious But Expected",
            "False Positive - Incorrect Analytic Logic",
            "False Positive - Inaccurate Data",
            "Undetermined",
            "Other",
        ],
    )
    integer_disposition: float | None = Param(
        description="Integer representing custom disposition value"
    )
    wait_for_confirmation: bool | None = Param(
        description="Validate event_ids", default=False
    )


class UpdateEventOutput(ActionOutput):
    failure_count: float = OutputField(example_values=[0])
    message: str = OutputField(example_values=["1 event updated successfully"])
    success: bool = OutputField(example_values=[False, True])
    success_count: float = OutputField(example_values=[1])


@app.action(
    description="Update a notable event",
    action_type="generic",
    read_only=False,
    verbose="The <b>event_ids</b> parameter takes a single event_id (which has the format: 68E08B8B-A853-3A20-9768-231C97B7EE76@@notable@@a4bd78810ae8e03e285e552fac0ddb23) or an adaptive response SID + RID combo (which has the format: scheduler__admin__SplunkEnterpriseSecuritySuite__RMD515d4671130158e57_at_1532441220_4982+0).<br><br>NOTE: This action only works with a notable event from Splunk ES.<br><br>Second Note: The <b>status</b> parameter takes a string value, but custom status values are unique to installation and not available at app creation. The <b>integer_status</b> parameter takes a positive integer denoting the custom value desired. This integer must be determined by the customer on-site. If set it will override <b>status</b>.",
)
def update_event(
    params: UpdateEventParams, soar: SOARClient, asset: Asset
) -> UpdateEventOutput:
    _connector, result = _run_legacy_action("update_event", params, soar, asset)
    return result


class PostDataParams(Params):
    data: str = Param(description="Data to post")
    host: str | None = Param(
        description="Host for event", primary=True, cef_types=["ip", "host name"]
    )
    index: str | None = Param(description="Index to send event to")
    source: str | None = Param(description="Source for event", default="Phantom")
    source_type: str | None = Param(
        description="Type of source for event",
        default="Automation/Orchestration Platform",
    )


@app.action(
    description="Post data to Splunk",
    action_type="generic",
    read_only=False,
    verbose="This action creates an event on Splunk with the data included in the <b>data</b> parameter. If not specified the parameters will default to the following:<ul><li><b>host</b> - The IP of the Splunk SOAR instance running the action.</li><li><b>index</b> - The default index configured on the Splunk instance.</li><li><b>source</b> - &quot;Phantom&quot;.</li><li><b>source_type</b> - &quot;Automation/Orchestration Platform&quot;.</li></ul>",
)
def post_data(params: PostDataParams, soar: SOARClient, asset: Asset) -> ActionOutput:
    _connector, result = _run_legacy_action("post_data", params, soar, asset)
    return result


if __name__ == "__main__":
    app.cli()
