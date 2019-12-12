from electrum.wallet import Multisig_Wallet, Deterministic_Wallet
from electrum.transaction import TxOutput
from electrum.bitcoin import TYPE_ADDRESS
from electrum.util import NotEnoughFunds, UserFacingException
from .tc_requests import tc_requests
from electrum.i18n import _

from .tools import TrustedCoinException, get_user_id, make_billing_address


class Wallet_TC(Multisig_Wallet):
    wallet_type = 'tc'

    def __init__(self, storage):
        self.m, self.n = 2, 3
        Deterministic_Wallet.__init__(self, storage)
        self.is_billing = False
        self.billing_info = None
        self._load_billing_addresses()

    def _load_billing_addresses(self):
        billing_addresses = {
            'legacy': self.storage.get('trustedcoin_billing_addresses', {}),
            'segwit': self.storage.get('trustedcoin_billing_addresses_segwit', {})
        }
        self._billing_addresses = {}  # type: Dict[str, Dict[int, str]]  # addr_type -> index -> addr
        self._billing_addresses_set = set()  # set of addrs
        for addr_type, d in list(billing_addresses.items()):
            self._billing_addresses[addr_type] = {}
            # convert keys from str to int
            for index, addr in d.items():
                self._billing_addresses[addr_type][int(index)] = addr
                self._billing_addresses_set.add(addr)

    def make_unsigned_transaction(self, coins, outputs, config, fixed_fee=None,
                                  change_addr=None, is_sweep=False):

        """
        创建未签名交易
        :param coins:
        :param outputs:
        :param config:
        :param fixed_fee:
        :param change_addr:
        :param is_sweep:
        :return:
        """
        mk_tx = lambda o: Multisig_Wallet.make_unsigned_transaction(
            self, coins, o, config, fixed_fee, change_addr)
        fee = self.extra_fee(config) if not is_sweep else 0
        if fee:
            address = self.billing_info['billing_address_segwit']
            fee_output = TxOutput(TYPE_ADDRESS, address, fee)
            try:
                tx = mk_tx(outputs + [fee_output])
            except NotEnoughFunds:
                # TrustedCoin won't charge if the total inputs is
                # lower than their fee
                tx = mk_tx(outputs)
                if tx.input_value() >= fee:
                    raise
                self.logger.info("not charging for this tx")
        else:
            tx = mk_tx(outputs)
        return tx

    def extra_fee(self, config):

        """
        计算额外费用
        :param config:
        :return:
        """

        if self.can_sign_without_server():
            return 0
        if self.billing_info is None:
            self.plugin.start_request_thread(self)
            return 0
        if self.billing_info.get('tx_remaining'):
            return 0
        if self.is_billing:
            return 0
        n = self.num_prepay(config)
        price = int(self.price_per_tx[n])
        if price > 100000 * n:
            raise Exception('too high trustedcoin fee ({} for {} txns)'.format(price, n))
        return price

    def can_sign_without_server(self):
        return not self.keystores['x2/'].is_watching_only()

    def num_prepay(self, config):
        default = self.min_prepay()
        n = config.get('trustedcoin_prepay', default)
        if n not in self.price_per_tx:
            n = default
        return n

    def min_prepay(self):
        return min(self.price_per_tx.keys())

    def is_billing_address(self, addr: str) -> bool:
        return addr in self._billing_addresses_set

    def get_user_id(self):
        return get_user_id(self.storage)

    def add_new_billing_address(self, billing_index: int, address: str, addr_type: str):
        billing_addresses_of_this_type = self._billing_addresses[addr_type]
        saved_addr = billing_addresses_of_this_type.get(billing_index)
        if saved_addr is not None:
            if saved_addr == address:
                return  # already saved this address
            else:
                raise Exception('trustedcoin billing address inconsistency.. '
                                'for index {}, already saved {}, now got {}'
                                .format(billing_index, saved_addr, address))
        # do we have all prior indices? (are we synced?)
        largest_index_we_have = max(billing_addresses_of_this_type) if billing_addresses_of_this_type else -1
        if largest_index_we_have + 1 < billing_index:  # need to sync
            for i in range(largest_index_we_have + 1, billing_index):
                addr = make_billing_address(self, i, addr_type=addr_type)
                billing_addresses_of_this_type[i] = addr
                self._billing_addresses_set.add(addr)
        # save this address; and persist to disk
        billing_addresses_of_this_type[billing_index] = address
        self._billing_addresses_set.add(address)
        self._billing_addresses[addr_type] = billing_addresses_of_this_type
        self.storage.put('trustedcoin_billing_addresses', self._billing_addresses['legacy'])
        self.storage.put('trustedcoin_billing_addresses_segwit', self._billing_addresses['segwit'])
        # FIXME this often runs in a daemon thread, where storage.write will fail
        self.storage.write()

    def on_otp(self, tx, otp):
        if not otp:
            self.logger.info("sign_transaction: no auth code")
            return
        otp = int(otp)
        long_user_id, short_id = self.get_user_id()
        raw_tx = tx.serialize()
        try:
            server_address = self.storage.get('server_address')
            r = tc_requests.sign(server_address, short_id, raw_tx, otp)
        except TrustedCoinException as e:
            if e.status_code == 400:  # invalid OTP
                raise UserFacingException(_(e.server_message)) from e
            else:
                raise

        self.logger.info("twofactor: is complete", tx.is_complete())
        # reset billing_info
        self.billing_info = None
        self.plugin.start_request_thread(self)

        raise UserFacingException(_(r.get('transaction')))
