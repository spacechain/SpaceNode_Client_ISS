from .tools import TrustedCoinException, ErrorConnectingServer

from electrum.network import Network
from electrum import version, constants
from electrum.logging import Logger
from urllib.parse import urljoin
from aiohttp import ClientResponse


class TrustedCoinCosignerClient(Logger):
    def __init__(self, user_agent=None):
        self.debug = False
        self.user_agent = user_agent
        Logger.__init__(self)

    async def handle_response(self, resp: ClientResponse):
        if resp.status != 200:
            try:
                r = await resp.json()
                message = r['message']
            except:
                message = await resp.text()

            raise TrustedCoinException(message, resp.status)
        try:
            return await resp.json()
        except:
            return await resp.text()

    #
    def send_request(self, method, relative_url, data=None, *, timeout=None, server_address=None):
        network = Network.get_instance()
        if not network:
            raise ErrorConnectingServer('You are offline.')
        url = urljoin(server_address, relative_url)
        if self.debug:
            self.logger.info(f'<-- {method} {url} {data}')
        headers = {}
        if self.user_agent:
            headers['user-agent'] = self.user_agent

        try:
            if method == 'get':
                response = Network.send_http_on_proxy(method, url,
                                                      params=data,
                                                      headers=headers,
                                                      on_finish=self.handle_response,
                                                      timeout=timeout)
            elif method == 'post':
                response = Network.send_http_on_proxy(method, url,
                                                      json=data,
                                                      headers=headers,
                                                      on_finish=self.handle_response,
                                                      timeout=timeout)
            else:
                assert False
        except TrustedCoinException:
            raise
        except Exception as e:
            raise ErrorConnectingServer(e)
        else:
            if self.debug:
                self.logger.info(f'--> {response}')
            return response

    def get_terms_of_service(self, server_address=None, billing_plan='electrum-per-tx-otp', ):
        """
        获取价格
        :param server_address:
        :param billing_plan: the plan to return the terms for
        """
        payload = {'billing_plan': billing_plan, 'is_test': int(constants.net.TESTNET)}
        return self.send_request('get', 'terms', payload, timeout=600, server_address=server_address)

    def create(self, server_address, xpub1, xpub2, email, type_of_service):

        """
        创建钱包
        :param server_address:
        :param type_of_service:
        :param xpub1:
        :param xpub2:
        :param email:
        :return:
        """
        payload = {
            'email_address': email,
            'first_xpub': xpub1,
            'secondary_xpub': xpub2,
            'is_test': int(constants.net.TESTNET),
            'type_of_service': type_of_service
        }

        return self.send_request('post', 'create_wallet', payload, timeout=600, server_address=server_address)

    def sign(self, server_address, short_id, raw_tx, otp):
        """

        :param server_address:
        :param short_id:
        :param raw_tx:
        :param otp:
        :return:
        """

        payload = {
            'short_id': short_id,
            'raw_tx': raw_tx,
            'otp': otp,
            'is_test': int(constants.net.TESTNET)

        }
        return self.send_request('post', 'sign', payload, timeout=600, server_address=server_address)

    def auth(self, server_address, short_id, otp):
        """
        身份验证
        :param server_address:
        :param short_id:
        :param otp:
        :return:
        """
        payload = {
            'short_id': short_id,
            'otp': otp,
            'is_test': int(constants.net.TESTNET)

        }
        return self.send_request('get', 'check_code', payload, timeout=600, server_address=server_address)

    def get_billing(self, server_address, short_id):
        """
        获取账单信息
        :param server_address:
        :param short_id:
        :return:
        """
        payload = {
            'short_id': short_id

        }
        return self.send_request('get', 'get_billing', payload, timeout=600, server_address=server_address)


tc_requests = TrustedCoinCosignerClient(user_agent="Electrum/" + version.ELECTRUM_VERSION)
