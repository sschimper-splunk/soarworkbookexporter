# File: soarworkbookexporter_connector.py
#
# Copyright (c) 2023 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

import json
import os
import time

# Phantom App imports
import phantom.app as phantom
import phantom.rules as phantom_rules
import requests
import yaml
from bs4 import BeautifulSoup
from phantom import vault
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from pdf_exporter import PDF


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class SoarWorkbookExporterConnector(BaseConnector):
    def __init__(self):

        # Call the BaseConnectors init first
        super(SoarWorkbookExporterConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ),
            None,
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code, error_text
        )

        message = message.replace("{", "{{").replace("}", "}}")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to parse JSON response. Error: {0}".format(str(e)),
                ),
                None,
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Invalid method: {0}".format(method)
                ),
                resp_json,
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get("verify_server_cert", False),
                **kwargs,
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: {0}".format(str(e)),
                ),
                resp_json,
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")
        self.save_progress("Url is {url}".format(url=self._base_url))
        ret_val, response = self._make_rest_call(
            "/rest/workbook_task", action_result, params=None, headers=self.auth_header
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.set_status(phantom.APP_ERROR, "Connection Failed")

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    # formats json according to described format
    def _reformat_dict(self, response_json, comment):
        data = {"Comment": comment, "Phases": {}}
        data_phases = data["Phases"]

        for org_phase in response_json["data"]:
            phase_name = org_phase["name"]
            data_phases[phase_name] = {}

            current_data_phase = data_phases[phase_name]

            for task in org_phase["tasks"]:

                task_name = task["name"]
                desc = task["description"]
                suggestions = task["suggestions"]
                actions = suggestions.get("actions", {})
                playbooks = suggestions.get("playbooks", {})

                this_task = {
                    "Description": desc,
                    "Actions": actions,
                    "Playbooks": playbooks,
                }

                current_data_phase[task_name] = this_task

        return data

    # Creates and returns PDF document
    def _get_pdf(self, phases_dict):
        pdf = PDF()
        pdf.add_page()
        pdf.write_title("Export_as_PDF Summary")

        phases_dict = phases_dict["Phases"]
        for phase in phases_dict:
            pdf.write_phase(phase)
            current_phase = phases_dict[phase]
            for task in current_phase:
                pdf.write_task_name(task)

                task_properties = current_phase[task]
                pdf.write_section("Description", task_properties["Description"])
                pdf.write_actions(task_properties["Actions"])
                pdf.write_playbooks(task_properties["Playbooks"])

        return pdf

    # saves file contents to the container vault
    def _save_to_vault(self, c_id, data, is_pdf):
        filename_no_extension = f"wb_{c_id}_{time.strftime('%Y%m%d-%H%M%S')}"
        filename = None

        # save files temporarily to /opt/phantom/vault/tmp
        if not is_pdf:
            filename = filename_no_extension + ".yaml"
            with open(
                os.path.join(vault.get_phantom_vault_tmp_dir(), filename), "w"
            ) as outfile:
                yaml.dump(data, outfile, default_flow_style=False)
        else:
            filename = filename_no_extension + ".pdf"
            data.output(os.path.join(vault.get_phantom_vault_tmp_dir(), filename), "F")

        # add current file to vault
        success, message, vault_id = vault.vault_add(
            container=c_id,
            file_location=f"{vault.get_phantom_vault_tmp_dir()}/{filename}",
        )

        phantom_rules.debug(
            "phantom.vault_add results: success: {}, message: {}, vault_id: {}".format(
                success, message, vault_id
            )
        )

        return message

    # Get workbook info via Splunk REST API call, format it, and return it
    def _get_workbook_info(self, workbook_id, comment, action_result):
        self.save_progress(
            "Connecting to endpoint for retrieving workbook information."
        )

        ret_val, response = self._make_rest_call(
            f"rest/workbook_template?_filter_id={workbook_id}",
            action_result,
            params=None,
            headers=None,
        )

        response = requests.get()

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.set_status(phantom.APP_ERROR, "Connection Failed")

        if response["count"] == 0 and response["num_pages"] == 0:
            return action_result.set_status(
                phantom.APP_ERROR,
                "API Response is empty. Is a workbook associated with the Container?",
            )

        formatted_response = self._reformat_dict(response, comment)
        return formatted_response, action_result

    def _handle_export_as_json(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        _filter_workbook_id = param["workbook_id"]
        _user_comment = param.get("comment", "")

        # make rest call
        response_dict, action_result = self._get_workbook_info(
            _filter_workbook_id, _user_comment, action_result
        )
        
        '''
        response_json_str = json.dumps(response_dict)
        response_json = json.loads(response_json_str)

        # debug
        # write json file /opt/phantom/vault/tmp
        filelocation = vault.get_phantom_vault_tmp_dir()
        filename = "test_output.json"

        with open(os.path.join(filelocation, filename), 'w', encoding='utf-8') as f:
            json.dump(response_dict, f, ensure_ascii=False, indent=4)
        '''

        # action_result.add_data({"json_exported": response_json})
        self.save_progress("Json Export Action completed sucessfully!")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_export_as_yaml(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        _filter_workbook_id = param["workbook_id"]
        _user_comment = param.get("comment", "")

        # make rest call
        response_dict, action_result = self._get_workbook_info(
            _filter_workbook_id, _user_comment, action_result
        )

        # convert to yaml
        response_json_str = json.dumps(response_dict)
        response_json = json.loads(response_json_str)
        response_yaml = yaml.dump(response_json, allow_unicode=True)

        # save to container vault
        save_to_vault_message = self._save_to_vault(_filter_workbook_id, response_yaml, False)

        action_result.add_data({"vault_info": save_to_vault_message})
        self.save_progress("Yaml Export Action completed sucessfully!")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_export_as_pdf(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        _filter_workbook_id = param["workbook_id"]
        _user_comment = param.get("comment", "")

        # make rest call
        response_dict, action_result = self._get_workbook_info(
            _filter_workbook_id, _user_comment, action_result
        )

        # create pdf
        pdf_file = self._get_pdf(response_dict)

        # save to container vault
        save_to_vault_message = self._save_to_vault(_filter_workbook_id, pdf_file, True)

        action_result.add_data({"vault_info": save_to_vault_message})
        self.save_progress("PDF Export Action completed sucessfully!")
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "export_as_pdf":
            ret_val = self._handle_export_as_pdf(param)

        if action_id == "export_as_yaml":
            ret_val = self._handle_export_as_yaml(param)

        if action_id == "export_as_json":
            ret_val = self._handle_export_as_json(param)

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        self.auth_token = config.get("ph-auth-token")
        self.server = config.get("server")
        self._base_url = f"https://{self.server}"
        self.auth_header = {
            "ph-auth-token" : self.auth_token
        }

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = SoarWorkbookExporterConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SoarWorkbookExporterConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
