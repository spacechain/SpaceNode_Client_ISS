from .tc_wallet import Wallet_TC
from .tc_requests import tc_requests
from .tools import ErrorConnectingServer, TrustedCoinException, get_user_id, make_billing_address, Decrypt

import socket

from electrum import keystore
from electrum.bitcoin import TYPE_ADDRESS
from electrum.base_wizard import BaseWizard
from electrum.plugin import BasePlugin, hook
from electrum.i18n import _
from electrum.mnemonic import is_any_tc_seed_type, Mnemonic, seed_type
from electrum.bip32 import BIP32Node, xpub_type
from electrum.storage import STO_EV_USER_PW

DISCLAIMER = [
    _("Two-factor authentication is a service provided by TC. "
      "To use it, you must have a separate device with Google Authenticator."),
    _("This service uses a multi-signature wallet, where you own 2 of 3 keys.  "
      "The third key is stored on a remote server that signs transactions on "
      "your behalf. A small fee will be charged on each transaction that uses the "
      "remote server."),
    _("Note that your coins are not locked in this service.  You may withdraw "
      "your funds at any time and at no cost, without the remote server, by "
      "using the 'restore wallet' option with your wallet seed."),
]


class TCPlugin(BasePlugin):
    wallet_class = Wallet_TC
    disclaimer_msg = DISCLAIMER

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.wallet_class.plugin = self
        self.requesting = False

    def is_available(self):
        return True

    def is_enabled(self):
        return True

    def can_user_disable(self):
        return False

    @hook
    def tc_sign_wrapper(self, wallet, tx, on_success, on_failure):
        if not isinstance(wallet, self.wallet_class):
            return
        if tx.is_complete():
            return
        if wallet.can_sign_without_server():
            return
        if not wallet.keystores['x3/'].get_tx_derivations(tx):
            self.logger.info("twofactor: xpub3 not needed")
            return

        def wrapper(tx):
            self.prompt_user_for_otp(wallet, tx, on_success, on_failure)

        return wrapper

    @hook
    def get_tx_extra_fee(self, wallet, tx):
        if type(wallet) != Wallet_TC:
            return
        for o in tx.outputs():
            if o.type == TYPE_ADDRESS and wallet.is_billing_address(o.address):
                return o.address, o.value

    def finish_requesting(func):
        def f(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            finally:
                self.requesting = False

        return f

    @finish_requesting
    def request_billing_info(self, wallet: 'Wallet_tc', *, suppress_connection_error=True):

        if wallet.can_sign_without_server():
            return
        self.logger.info("request billing info")
        try:
            # todo wallet.get_user_id()[1]  ==  short_id
            # billing_info = tc_requests.get(wallet.get_user_id()[1])
            # billing_info = {'billing_plan': 'electrum-per-tx-otp',
            #                 'billing_address': 'n3X7wpKn3GzyvxEsVV6LKz2fWQtgXQdzA2', 'network': 'testnet',
            #                 'tx_remaining': 20, 'billing_index': 1,
            #                 'billing_address_segwit': 'tb1q79dd94xk475vukt3h2d99gdsqgdk9cgaxzmlpz',
            #                 'price_per_tx': [[1, 50000], [20, 100000], [100, 250000]],
            #                 'id': '1e42f483163b15b696cb7021a586018beebc8c15f2f0c4db740095e27606d979'}
            # 第一次收费时的参数
            # billing_info = {'billing_plan': 'electrum-per-tx-otp',
            #                 'billing_address': 'mhArEhjwVxfLoRNU1S3UVRRQSaTLTsPGF1', 'network': 'testnet',
            #                 'tx_remaining': 0, 'billing_index': 0,
            #                 'billing_address_segwit': 'tb1qzg3wqfy45j44vvaj0k0xkr7rc0l64xj9k2avmg',
            #                 'price_per_tx': [[1, 50000], [20, 100000], [100, 250000]],
            #                 'id': '64acb16fa4e8ad05520e73e1d599fda5dba83a8024796bb69bf9ea90a0b55293'}
            server_address = wallet.storage.get('server_address')
            billing_info = tc_requests.get_billing(server_address, wallet.get_user_id()[1])

        except ErrorConnectingServer as e:
            if suppress_connection_error:
                self.logger.info(str(e))
                return
            raise

        billing_index = billing_info['billing_index']
        # add segwit billing address; this will be used for actual billing
        billing_address = make_billing_address(wallet, billing_index, addr_type='segwit')
        if billing_address != billing_info['billing_address_segwit']:
            raise Exception(f'unexpected trustedcoin billing address: '
                            f'calculated {billing_address}, received {billing_info["billing_address_segwit"]}')
        wallet.add_new_billing_address(billing_index, billing_address, addr_type='segwit')
        # also add legacy billing address; only used for detecting past payments in GUI
        billing_address = make_billing_address(wallet, billing_index, addr_type='legacy')
        wallet.add_new_billing_address(billing_index, billing_address, addr_type='legacy')

        wallet.billing_info = billing_info
        wallet.price_per_tx = dict(billing_info['price_per_tx'])
        wallet.price_per_tx.pop(1, None)
        return True

    def start_request_thread(self, wallet):
        from threading import Thread
        if self.requesting is False:
            self.requesting = True
            t = Thread(target=self.request_billing_info, args=(wallet,))
            t.setDaemon(True)
            t.start()
            return t

    def make_seed(self, seed_type):
        if not is_any_tc_seed_type(seed_type):
            raise Exception(f'unexpected seed type: {seed_type}')

        return Mnemonic('english').make_seed(seed_type=seed_type, num_bits=128)

    @hook
    def do_clear(self, window):
        window.wallet.is_billing = False

    def show_disclaimer(self, wizard: BaseWizard):
        """
        声明
        :param wizard:
        :return:
        """
        wizard.set_icon('tc.jpeg')
        wizard.reset_stack()
        wizard.confirm_dialog(title='Disclaimer', message='\n\n'.join(self.disclaimer_msg),
                              run_next=lambda x: wizard.run('choose_seed'))

    @staticmethod
    def is_valid_seed(seed):
        t = seed_type(seed)
        return is_any_tc_seed_type(t)

    @hook
    def get_action(self, storage):

        if storage.get('wallet_type') != 'tc':
            return
        if not storage.get('x1/'):
            # 展示协议
            return self, 'show_disclaimer'
        if not storage.get('x2/'):
            return self, 'show_disclaimer'
        if not storage.get('x3/'):
            return self, 'accept_terms_of_use'

    def choose_seed(self, wizard):
        """
        选择种子
        :param wizard:
        :return:
        """

        title = _('Create or restore')
        message = _('Do you want to create a new seed, or to restore a wallet using an existing seed?')
        choices = [
            ('choose_seed_type', _('Create a new seed')),
            ('restore_wallet', _('I already have a seed')),
        ]
        wizard.choice_dialog(title=title, message=message, choices=choices, run_next=wizard.run)

    def choose_seed_type(self, wizard):
        choices = [
            ('create_tc_segwit_seed', _('Segwit TC')),
            # ('create_tc_seed', _('Legacy TC')),
        ]
        wizard.choose_seed_type(choices=choices)

    def create_tc_segwit_seed(self, wizard):
        self.create_seed(wizard, 'tc_segwit')

    def create_tc_seed(self, wizard):
        self.create_seed(wizard, 'tc')

    def create_seed(self, wizard, seed_type):
        seed = self.make_seed(seed_type)
        f = lambda x: wizard.request_passphrase(seed, x)
        wizard.show_seed_dialog(run_next=f, seed_text=seed)

    def create_keystore(self, wizard, seed, passphrase):
        xprv1, xpub1, xprv2, xpub2 = self.xkeys_from_seed(seed, passphrase)
        # 创建钱包所需的公钥
        k1 = keystore.from_xprv(xprv1)
        k2 = keystore.from_xpub(xpub2)
        wizard.request_password(run_next=lambda pw, encrypt: self.on_password(wizard, pw, encrypt, k1, k2))
        # k1.update_password(None, '')
        # wizard.data['x1/'] = k1.dump()
        # wizard.data['x2/'] = k2.dump()
        # wizard.pw_args = password, encrypt_storage, STO_EV_USER_PW
        # self.go_online_dialog(wizard)

    def on_password(self, wizard, password, encrypt_storage, k1, k2):
        k1.update_password(None, password)
        wizard.data['x1/'] = k1.dump()
        wizard.data['x2/'] = k2.dump()
        wizard.pw_args = password, encrypt_storage, STO_EV_USER_PW
        self.go_online_dialog(wizard)

    @classmethod
    def xkeys_from_seed(self, seed, passphrase):
        t = seed_type(seed)
        if not is_any_tc_seed_type(t):
            raise Exception(f'unexpected seed type: {t}')
        words = seed.split()
        n = len(words)

        if n >= 20:
            # note: pre-2.7 2fa seeds were typically 24-25 words, however they
            # could probabilistically be arbitrarily shorter due to a bug. (see #3611)
            # the probability of it being < 20 words is about 2^(-(256+12-19*11)) = 2^(-59)
            if passphrase != '':
                raise Exception('old 2fa seed cannot have passphrase')
            xprv1, xpub1 = self.get_xkeys(' '.join(words[0:12]), t, '', "m/")
            xprv2, xpub2 = self.get_xkeys(' '.join(words[12:]), t, '', "m/")
        elif not t == 'tc' or n == 12:
            xprv1, xpub1 = self.get_xkeys(seed, t, passphrase, "m/0'/")
            xprv2, xpub2 = self.get_xkeys(seed, t, passphrase, "m/1'/")
        else:
            raise Exception('unrecognized seed length: {} words'.format(n))
        return xprv1, xpub1, xprv2, xpub2

    @classmethod
    def get_xkeys(self, seed, t, passphrase, derivation):
        assert is_any_tc_seed_type(t)

        xtype = 'standard' if t == 'tc' else 'p2wsh'
        bip32_seed = Mnemonic.mnemonic_to_seed(seed, passphrase)
        rootnode = BIP32Node.from_rootseed(bip32_seed, xtype=xtype)
        child_node = rootnode.subkey_at_private_derivation(derivation)
        return child_node.to_xprv(), child_node.to_xpub()

    @staticmethod
    def is_valid_seed(seed):
        t = seed_type(seed)
        return is_any_tc_seed_type(t)

    def create_remote_key(self, email, wizard):
        """
        创建钱包1
        :param email:
        :param wizard:
        :return:
        """
        xpub1 = wizard.data['x1/']['xpub']
        xpub2 = wizard.data['x2/']['xpub']
        server_address = wizard.data['server_address']
        type_of_service = wizard.data['type_of_service']

        # Generate third key deterministically.
        long_user_id, short_id = get_user_id(wizard.data)

        # secret must be sent by the server
        try:
            # 创建钱包
            r = tc_requests.create(server_address, xpub1, xpub2, email, type_of_service)

        except (socket.error, ErrorConnectingServer):
            wizard.show_message('Server not reachable, aborting')
            wizard.terminate()
            return
        except TrustedCoinException as e:
            wizard.show_message(str(e))
            return

        if r is None:
            otp_secret = None
        else:
            otp_secret = r.get('otp_secret')
            otp_secret = otp_secret[-5:] + otp_secret[:-5]
            print('=======otp_secret======', otp_secret)

            if not otp_secret:
                wizard.show_message(_('Error'))
                return
            xpub3 = r.get('sat_xpub')
            xpub3 = xpub3[-5:] + xpub3[:-5]
            print('=======xpub3======', xpub3)

        self.request_otp_dialog(wizard, short_id, otp_secret, xpub3)

    def check_otp(self, wizard, short_id, otp_secret, xpub3, otp, reset):

        if otp:
            self.do_auth(wizard, short_id, otp, xpub3)
        elif reset:
            wizard.opt_bip39 = False
            wizard.opt_ext = True
            f = lambda seed, is_bip39, is_ext: wizard.run('on_reset_seed', short_id, seed, is_ext, xpub3)
            wizard.restore_seed_dialog(run_next=f, test=self.is_valid_seed)

    def do_auth(self, wizard, short_id, otp, xpub3):

        try:
            # 检查otp
            server_address = wizard.data['server_address']
            tc_requests.auth(server_address, short_id, otp)
        except TrustedCoinException as e:
            if e.status_code == 400:  # invalid OTP
                wizard.show_message(_(e.server_message))
                # ask again for otp
                self.request_otp_dialog(wizard, short_id, None, xpub3)

            else:
                wizard.show_message(str(e))
                wizard.terminate()
        except Exception as e:
            wizard.show_message(str(e))
            wizard.terminate()
        else:
            k3 = keystore.from_xpub(xpub3)
            wizard.data['x3/'] = k3.dump()
            wizard.data['use_trustedcoin'] = True
            wizard.terminate()

    def on_reset_seed(self, wizard, short_id, seed, is_ext, xpub3):
        f = lambda passphrase: wizard.run('on_reset_auth', short_id, seed, passphrase, xpub3)
        wizard.passphrase_dialog(run_next=f) if is_ext else f('')

    def on_password(self, wizard, password, encrypt_storage, k1, k2):
        k1.update_password(None, password)
        wizard.data['x1/'] = k1.dump()
        wizard.data['x2/'] = k2.dump()
        wizard.pw_args = password, encrypt_storage, STO_EV_USER_PW
        self.go_online_dialog(wizard)

    def restore_wallet(self, wizard):
        wizard.opt_bip39 = False
        wizard.opt_ext = True
        f = lambda seed, is_bip39, is_ext: wizard.run('on_restore_seed', seed, is_ext)
        wizard.restore_seed_dialog(run_next=f, test=self.is_valid_seed)

    def on_restore_seed(self, wizard, seed, is_ext):
        f = lambda x: self.restore_choice(wizard, seed, x)
        wizard.passphrase_dialog(run_next=f) if is_ext else f('')

    def restore_choice(self, wizard: BaseWizard, seed, passphrase):
        wizard.set_icon('tc.jpeg')
        wizard.reset_stack()
        title = _('Restore 2FA wallet')
        msg = ' '.join([
            'You are going to restore a wallet protected with two-factor authentication.',
            'Do you want to keep using two-factor authentication with this wallet,',
            'or do you want to disable it, and have two master private keys in your wallet?'
        ])
        choices = [('keep', 'Keep'), ('disable', 'Disable')]
        f = lambda x: self.on_choice(wizard, seed, passphrase, x)
        wizard.choice_dialog(choices=choices, message=msg, title=title, run_next=f)

    def on_choice(self, wizard, seed, passphrase, x):
        if x == 'disable':
            f = lambda pw, encrypt: wizard.run('on_restore_pw', seed, passphrase, pw, encrypt)
            wizard.request_password(run_next=f)
        else:
            self.create_keystore(wizard, seed, passphrase)

    # def on_restore_pw(self, wizard, seed, passphrase, password, encrypt_storage):
    #     xprv1, xpub1, xprv2, xpub2 = self.xkeys_from_seed(seed, passphrase)
    #     k1 = keystore.from_xprv(xprv1)
    #     k2 = keystore.from_xprv(xprv2)
    #     k1.add_seed(seed)
    #     k1.update_password(None, password)
    #     k2.update_password(None, password)
    #     wizard.data['x1/'] = k1.dump()
    #     wizard.data['x2/'] = k2.dump()
    #     long_user_id, short_id = get_user_id(wizard.data)
    #     xtype = xpub_type(xpub1)
    #     xpub3 = make_xpub(get_signing_xpub(xtype), long_user_id)
    #     k3 = keystore.from_xpub(xpub3)
    #     wizard.data['x3/'] = k3.dump()
    #     wizard.pw_args = password, encrypt_storage, STO_EV_USER_PW
    #     wizard.terminate()

    # def on_reset_auth(self, wizard, short_id, seed, passphrase, xpub3):
    #     # todo 忘记OTP
    #     xprv1, xpub1, xprv2, xpub2 = self.xkeys_from_seed(seed, passphrase)
    #     if (wizard.data['x1/']['xpub'] != xpub1 or
    #             wizard.data['x2/']['xpub'] != xpub2):
    #         wizard.show_message(_('Incorrect seed'))
    #         return
    #     r = server.get_challenge(short_id)
    #     challenge = r.get('challenge')
    #     message = 'TRUSTEDCOIN CHALLENGE: ' + challenge
    #
    #     def f(xprv):
    #         rootnode = BIP32Node.from_xkey(xprv)
    #         key = rootnode.subkey_at_private_derivation((0, 0)).eckey
    #         sig = key.sign_message(message, True)
    #         return base64.b64encode(sig).decode()
    #
    #     signatures = [f(x) for x in [xprv1, xprv2]]
    #     r = server.reset_auth(short_id, challenge, signatures)
    #     new_secret = r.get('otp_secret')
    #     if not new_secret:
    #         wizard.show_message(_('Request rejected by server'))
    #         return
    #     self.request_otp_dialog(wizard, short_id, new_secret, xpub3)
