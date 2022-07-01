from sys import argv
from upload import CsApiClient, getenv_or_exit, to_global_id
from urllib.parse import urljoin


def main():
    root_url = getenv_or_exit("CS_ROOT_URL")
    api_key = getenv_or_exit("CS_API_KEY")
    project_id = getenv_or_exit("CS_PROJECT_ID")
    profile_id = getenv_or_exit("CS_PROFILE_ID")

    api_url = urljoin(root_url, "/api/v2")
    print(f"API URL = {api_url}")
    api_client = CsApiClient(api_key=api_key, api_url=api_url, ca_cert=None)
    opaque_profile_id = to_global_id(type_="Profile", id_=profile_id)
    opaque_project_id = to_global_id(type_="Project", id_=project_id)
    trace_id = api_client.get_trace_id_from_name(opaque_project_id, argv[1])
    report_id = api_client.generate_report(trace_id, opaque_profile_id)
    api_client.wait_for_report_done(report_id)

    api_client.print_report_info(
        root_url=root_url,
        report_id=report_id,
        is_java=False,
    )


if __name__ == "__main__":
    main()
