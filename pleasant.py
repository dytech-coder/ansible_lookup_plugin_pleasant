# (c) 2022, Aleksandar Trkulja <aleksandar.trkulja@dytech.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = """
name: pleasant
author: Aleksandar Trkulja
version_added: "1.0"
short_description: lookup passwords in Pleasant Password server by GUID.  
   This is using Python Requests https://docs.python-requests.org/en/latest/api/
description:
    - Returns the content of the URL requested to be used as data in play.
options:
  _terms:
    description: Pleasant Entry GUID
  pleasant_verify:
    description: Flag to control SSL certificate validation.  Set to the path to the ca bundle ( /etc/ssl/certs/ca-bundle.crt ) or true
    default: True
    vars:
      - name: pleasant_lookup_ca_path
    env:
      - name: PLEASANT_LOOKUP_CA_PATH
    ini:
      - section: pleasant_lookup
        key: ca_path
  pleasant_username:
    description: Username to authenticate to Pleasant
    type: string
  pleasant_password:
    description: Password to authenticate to Pleasant
    type: str
  headers:
    description: HTTP request headers
    type: dictionary
    default: {Content-Type: application/json}
    version_added: "2.8"
  force:
    description: Whether or not to set "cache-control" header with value "no-cache"
    type: boolean
    default: False
  timeout:
    description: How long to wait for the server to send data before giving up
    type: float
    default: 5
    vars:
      - name: pleasant_lookup_timeout
    env:
      - name: PLEASANT_LOOKUP_TIMEOUT
    ini:
      - section: pleasant_lookup
        key: timeout
"""

EXAMPLES = """

- name: password
  debug: msg="{{ lookup('tombosmansibm.pleasant_lookup.password', pleasant_host='https://pleasant.com:10001', username='bob', password='hunter2', pleasant_search='itemname') }}"

# lookup example with search parameter and filter on username and path, with reference to the ca bundle of the system.
- name: Lookup
  run_once: True
  debug:
    msg: "{{ lookup('tombosmansibm.pleasant_lookup.password', pleasant_host='https://pleasant.com:10001', username='myuser', password='mypassword', pleasant_filter_path='Root/DEV/', 
       pleasant_filter_username='root', pleasant_search='root', verify='/etc/ssl/certs/ca-bundle.crt', timeout=2) }}"
  delegate_to: localhost

The result is a list of items:
        [{
            "password": "the password",
            "path": "Root/Path/",
            "username": "the username"
        }]

"""

RETURN = """
  _list:
    description: list of password objects: {username, password, path}
    type: list
    elements: dict
"""

from ansible.errors import AnsibleError
import requests
from ansible.module_utils._text import to_text, to_native
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

display = Display()

class LookupModule(LookupBase):
    def get_token(self, pleasant_host, pleasant_username, pleasant_password, pleasant_verify, pleasant_timeout):
        verify  = pleasant_verify
        timeout = pleasant_timeout

        if timeout is None: timeout = 5

        try:
            url      = pleasant_host + "/oauth2/token"
            payload  = f'grant_type=password&username={pleasant_username}&password={pleasant_password}'
            headers  = {'Content-Type': 'application/x-www-form-urlencoded'}
            response = requests.request("POST", url, headers=headers, data=payload, verify=verify, timeout=timeout)

            if response.status_code != 200:
                display.display(f"Authentication failed getting an access token from Pleasant {response.status_code} {response.reason}")
                response.raise_for_status()
        except requests.ConnectionError as e:
            raise AnsibleError(f"Can't connect to host to get token {to_native(e)}")
        except requests.HTTPError as e:
            raise AnsibleError(f"An HTTP Error occured {to_native(e)}")
        except requests.URLRequired as e:
            raise AnsibleError(f"Invalid url {to_native(e)}")
        except requests.ConnectTimeout as e:
            raise AnsibleError(f"The request timed out while trying to connect to the remote server. Retry later. {to_native(e)}")
        except requests.Timeout as e:
            raise AnsibleError(f"The request timed out {to_native(e)}")

        try:
            pleasant_at = response.json()
        except Exception as e:
            raise AnsibleError(f"can't decode access token : {pleasant_at} , {to_native(e)}")
        return pleasant_at

    def get_pps_entry(self, pleasant_host, guid, verify, timeout, pleasant_at):
        url = f'{pleasant_host}/api/v5/rest/entries/{guid}'
        headers = {"Content-type": "application/json", "Authorization": "Bearer " + pleasant_at}

        if not timeout: timeout = 5

        try:
            response = requests.request("GET", url,
                                        headers=headers, verify=verify, timeout=timeout)
            if response.status_code != 200:
                display.display(f"Getting crredential failed: ({response.status_code} {response.reason})")
                response.raise_for_status()
        except requests.ConnectionError as e:
            raise AnsibleError(f"Can't connect to host to get token {to_native(e)}")
        except requests.HTTPError as e:
            raise AnsibleError(f"An HTTP Error occured {to_native(e)}")
        except requests.URLRequired as e:
            raise AnsibleError(f"Invalid url {to_native(e)}")
        except requests.ConnectTimeout as e:
            raise AnsibleError(f"The request timed out while trying to connect to the remote server. Retry later. {to_native(e)}")
        except requests.Timeout as e:
            raise AnsibleError(f"The request timed out {to_native(e)}")
        except Exception as e:
            raise AnsibleError(f"Failed to execute get_pps_entry: error {to_native(e)}")
        return response

    def get_password(self, pleasant_host, pleasant_id, verify, timeout, pleasant_at):
        url = f"{pleasant_host}/api/v5/rest/entries/{pleasant_id}/password"
        headers = {"Content-type": "application/json", "Authorization": "Bearer " + pleasant_at}

        if not timeout: timeout = 5

        try:
            response = requests.request("GET", url, headers=headers, verify=verify, timeout=timeout)

            if response.status_code != 200:
                response.raise_for_status()
        except requests.ConnectionError as e:
            raise AnsibleError(f"Can't connect to host to get token {to_native(e)}")
        except requests.HTTPError as e:
            raise AnsibleError(f"An HTTP Error occured {to_native(e)}")
        except requests.URLRequired as e:
            raise AnsibleError(f"Invalid url {to_native(e)}")
        except requests.ConnectTimeout as e:
            raise AnsibleError(f"The request timed out while trying to connect to the remote server. Retry later. {to_native(e)}")
        except requests.Timeout as e:
            raise AnsibleError(f"The request timed out {to_native(e)}")
        except Exception as e:
            raise AnsibleError(f"Failed to get password {pleasant_id} - error {to_native(e)}")
        return response

    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)

        ret = []
        pps_host = variables.get('pleasant_host')
        username = variables.get('pleasant_username')
        password = variables.get('pleasant_password')
        verify   = variables.get('pleasant_verify')
        timeout  = variables.get('pleasant_timeout')
        guid     = terms[0]

        at = self.get_token(pps_host, username, password, verify, timeout)
        try:
            access_token = at.get('access_token', 'default')
            retval = self.get_pps_entry(pps_host, guid, verify, timeout, access_token)
            entry = retval.json()
            
            retval = self.get_password(pps_host, guid, verify, timeout, access_token)
            passwd = retval.json()

            idusername = entry.get("Username")

            ret.append({"username": to_text(idusername), "password": to_text(passwd)})

        except requests.ConnectionError as e:
            raise AnsibleError(f"Can't connect to host to get token {to_native(e)}")
        except requests.HTTPError as e:
            raise AnsibleError(f"An HTTP Error occured {to_native(e)}")
        except requests.URLRequired as e:
            raise AnsibleError(f"Invalid url: {to_native(e)}")
        except requests.ConnectTimeout as e:
            raise AnsibleError(f"The request timed out while trying to connect to the remote server. Retry later: {to_native(e)}")
        except requests.Timeout as e:
            raise AnsibleError(f"The request timed out: {to_native(e)}")
        except Exception as e:
            raise AnsibleError(f"No entry found {to_native(e)}")
        return ret