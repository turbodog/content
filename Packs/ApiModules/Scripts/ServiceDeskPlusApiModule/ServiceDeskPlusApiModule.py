import traceback

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Dict, Tuple

# authorization types
OPROXY_AUTH_TYPE = 'oproxy'
SELF_DEPLOYED_AUTH_TYPE = 'self_deployed'


class ServiceDeskPlusClient(BaseClient):
    def __init__(self,
                 # oproxy
                 auth_token: str = '',

                 # self deployed - code flow
                 auth_code: str = '',
                 token_retrieval_url: str = 'https://accounts.zoho.com/oauth/v2/token',
                 redirect_uri: str = 'https://localhost/myapp',

                 # shared (oproxy + self deployed)
                 auth_id: str = '',  # can also be client id
                 enc_key: str = '',  # can also be client secret
                 scope: str = 'SDPOnDemand.requests.ALL',

                 # optional - self deployed refresh token flow
                 refresh_token: str = '',

                 self_deployed: bool = False,
                 verify: bool = True,
                 base_url: str = 'https://www.zohoapis.com',
                 *args, **kwargs):
        """
        Service Desk Plus OAuth 2 client
        :param auth_token: Oproxy token
        :param token_retrieval_url: Accounts server to get token from
        :param redirect_uri: Redirect URI
        :param auth_id: Oproxy ID OR client ID
        :param enc_key: Oproxy Key OR client Secret
        :param scope: Access token scope
        :param (Optional) auth_code: Code to generate refresh token with. In self_deployed use this or refresh_token
        :param (Optional) refresh_token: Token to refresh token with. In self_deployed use this or auth_code
        :param self_deployed: is self deployed
        :param verify: is verify
        :param base_url: URL to send requests to
        :param args:
        :param kwargs:
        """
        super().__init__(base_url=base_url, verify=verify, *args, **kwargs)  # type: ignore[misc]

        self.scope = scope
        # oproxy flow
        if not self_deployed:
            # provide support for dev oproxy
            auth_id_and_token_retrieval_url = auth_id.split('@')
            auth_id = auth_id_and_token_retrieval_url[0]
            if len(auth_id_and_token_retrieval_url) != 2:
                self.token_retrieval_url = 'https://oproxy.demisto.ninja/sdp-token'  # guardrails-disable-line
            else:
                self.token_retrieval_url = auth_id_and_token_retrieval_url[1]

            self.auth_id = auth_id
            self.enc_key = enc_key
            self.auth_token = auth_token

        # self deployed flow
        else:
            self.token_retrieval_url = token_retrieval_url
            self.client_id = auth_id
            self.client_secret = enc_key
            self.auth_code = auth_code
            self.redirect_uri = redirect_uri

            # optional flow
            self.refresh_token = refresh_token

        self.auth_type = SELF_DEPLOYED_AUTH_TYPE if self_deployed else OPROXY_AUTH_TYPE


    def http_request(self, *args, resp_type='json', headers=None, **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        Returns:
            requests.Response: The http response
        """
        token = self.get_access_token()
        default_headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        if headers:
            default_headers.update(headers)

        return super()._http_request(   # type: ignore[misc]
            *args, resp_type=resp_type, headers=default_headers, **kwargs)

    def get_access_token(self):
        """
        Obtains access and refresh token from oproxy server or just a token from a self deployed app.
        Access token is used and stored in the integration context
        until expiration time. After expiration, new refresh token and access token are obtained and stored in the
        integration context.

        Returns:
            str: Access token that will be added to authorization header.
        """
        integration_context = demisto.getIntegrationContext()
        access_token = integration_context.get('access_token')
        refresh_token = integration_context.get('refresh_token')
        valid_until = integration_context.get('valid_until')
        if access_token and valid_until:
            if self.epoch_seconds() < valid_until:
                return access_token

        auth_type = self.auth_type
        if auth_type == OPROXY_AUTH_TYPE:
            access_token, expires_in = self._oproxy_authorize()
        else:
            access_token, expires_in, refresh_token = self._get_self_deployed_token(refresh_token)
        time_now = self.epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer

        integration_context = {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'valid_until': time_now + expires_in,
        }

        demisto.setIntegrationContext(integration_context)
        return access_token

    def _oproxy_authorize(self) -> Tuple[str, int]:
        """
        Gets a token by authorizing with oproxy.

        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        content = self.auth_token
        headers = self._add_info_headers()
        oproxy_response = requests.post(
            self.token_retrieval_url,
            headers=headers,
            json={
                'oproxy_id': self.auth_id,
                'enc_token': self.get_encrypted(content, self.enc_key),
                'scope': self.scope
            },
            verify=self._verify
        )

        if not oproxy_response.ok:
            msg = 'Error in authentication. Try checking the credentials you entered.'
            try:
                demisto.info('Authentication failure from server: {} {} {}'.format(
                    oproxy_response.status_code, oproxy_response.reason, oproxy_response.text))
                err_response = oproxy_response.json()
                server_msg = err_response.get('message')
                if not server_msg:
                    title = err_response.get('title')
                    detail = err_response.get('detail')
                    if title:
                        server_msg = f'{title}. {detail}'
                    elif detail:
                        server_msg = detail
                if server_msg:
                    msg += ' Server message: {}'.format(server_msg)
            except Exception as ex:
                demisto.error('Failed parsing error response - Exception: {}'.format(ex))
            raise Exception(msg)
        try:
            gcloud_function_exec_id = oproxy_response.headers.get('Function-Execution-Id')
            demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
            parsed_response = oproxy_response.json()
        except ValueError:
            raise Exception(
                'There was a problem in retrieving an updated access token.\n'
                'The response from the Oproxy server did not contain the expected content.'
            )

        return (parsed_response.get('access_token', ''), parsed_response.get('expires_in', 3595))

    def _get_self_deployed_token(self, refresh_token: str = None):
        if refresh_token is None:
            if self.refresh_token is None:
                if self.auth_code:
                    # todo: implement create refresh token from code flow
                    pass
                raise Exception('Error - Unable to create access token without refresh token, Please provide a valid refresh token')

            refresh_token = self.refresh_token
        data = {
            'refresh_token': refresh_token,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'refresh_token',
            'redirect_uri': self.redirect_uri,
            'scope': self.scope
        }

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self._verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Service Desk Plus. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Self Service Desk authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        return access_token, expires_in, refresh_token

    @staticmethod
    def error_parser(error: requests.Response) -> str:
        """

        Args:
            error (requests.Response): response with error

        Returns:
            str: string of error

        """
        try:
            response = error.json()
            inner_error = response.get('error', {})
            if isinstance(inner_error, dict):
                err_str = f"{inner_error.get('code')}: {inner_error.get('message')}"
            else:
                err_str = inner_error
            if err_str:
                return err_str
            # If no error message
            raise ValueError
        except ValueError:
            return error.text

    @staticmethod
    def epoch_seconds(d: datetime = None) -> int:
        """
        Return the number of seconds for given date. If no date, return current.

        Args:
            d (datetime): timestamp
        Returns:
             int: timestamp in epoch
        """
        if not d:
            d = ServiceDeskPlusClient._get_utcnow()
        return int((d - ServiceDeskPlusClient._get_utcfromtimestamp(0)).total_seconds())

    @staticmethod
    def _get_utcnow() -> datetime:
        return datetime.utcnow()

    @staticmethod
    def _get_utcfromtimestamp(_time) -> datetime:
        return datetime.utcfromtimestamp(_time)

    @staticmethod
    def get_encrypted(content: str, key: str) -> str:
        """
        Encrypts content with encryption key.
        Args:
            content: Content to encrypt
            key: encryption key from oproxy

        Returns:
            timestamp: Encrypted content
        """

        def create_nonce():
            return os.urandom(12)

        def encrypt(string, enc_key):
            """
            Encrypts string input with encryption key.
            Args:
                string: String to encrypt
                enc_key: Encryption key

            Returns:
                bytes: Encrypted value
            """
            # String to bytes
            try:
                enc_key = base64.b64decode(enc_key)
            except Exception as err:
                return_error(f"Error in Microsoft authorization: {str(err)}"
                             f" Please check authentication related parameters.", error=traceback.format_exc())

            # Create key
            aes_gcm = AESGCM(enc_key)
            # Create nonce
            nonce = create_nonce()
            # Create ciphered data
            data = string.encode()
            ct = aes_gcm.encrypt(nonce, data, None)
            return base64.b64encode(nonce + ct)

        now = ServiceDeskPlusClient.epoch_seconds()
        encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
        return encrypted

    @staticmethod
    def _add_info_headers() -> Dict[str, str]:
        # pylint: disable=no-member
        headers = {}
        try:
            calling_context = demisto.callingContext.get('context', {})  # type: ignore[attr-defined]
            brand_name = calling_context.get('IntegrationBrand', '')
            instance_name = calling_context.get('IntegrationInstance', '')
            headers['X-Content-Version'] = CONTENT_RELEASE_VERSION
            headers['X-Content-Name'] = brand_name or instance_name or 'Name not found'
            if hasattr(demisto, 'demistoVersion'):
                demisto_version = demisto.demistoVersion()
                headers['X-Content-Server-Version'] = '{}-{}'.format(demisto_version.get('version'),
                                                                     demisto_version.get("buildNumber"))
        except Exception as e:
            demisto.error('Failed getting integration info: {}'.format(str(e)))

        return headers
