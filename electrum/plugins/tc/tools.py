import hashlib
from typing import Union
from electrum import bip32, ecc, constants, bitcoin
from electrum.crypto import sha256
from electrum.bip32 import BIP32Node

from PyQt5.QtWidgets import QTextEdit
from PyQt5.QtCore import QObject, pyqtSignal
from electrum.i18n import _

from electrum.gui.qt.util import WaitingDialog


class ErrorConnectingServer(Exception):
    def __init__(self, reason: Union[str, Exception] = None):
        self.reason = reason


class TrustedCoinException(Exception):
    def __init__(self, message, status_code=0):
        Exception.__init__(self, message)
        self.status_code = status_code
        self.server_message = message


def get_user_id(storage):
    def make_long_id(xpub_hot, xpub_cold):
        return sha256(''.join(sorted([xpub_hot, xpub_cold])))

    xpub1 = storage.get('x1/')['xpub']
    xpub2 = storage.get('x2/')['xpub']
    # 二进制 long_id: b"\x1e\x11-'\xbf\xb45\x0e;;\xc9-\x84\xb6\x84XD_\xbbK\xc4u\x1b\xbf\xac\x13\xfd\x18\xf2WX,"
    long_id = make_long_id(xpub1, xpub2)

    # 返回摘要，作为十六进制数据字符串值 2ac74a10ba47c9e942d97bb06c58eadf73daba5fb741e3888da0e711fb1b2c82
    short_id = hashlib.sha256(long_id).hexdigest()
    return long_id, short_id


def make_xpub(xpub, s) -> str:
    rootnode = BIP32Node.from_xkey(xpub)

    child_pubkey, child_chaincode = bip32._CKD_pub(
        parent_pubkey=rootnode.eckey.get_public_key_bytes(compressed=True),
        parent_chaincode=rootnode.chaincode,
        child_index=s)

    child_node = BIP32Node(xtype=rootnode.xtype,
                           eckey=ecc.ECPubkey(child_pubkey),
                           chaincode=child_chaincode)

    return child_node.to_xpub()


def get_signing_xpub(xtype):
    if not constants.net.TESTNET:
        # todo 从服务器获取卫星工钥  没测试
        xpub = "xpub661MyMwAqRbcGnMkaTx2594P9EDuiEqMq25PM2aeG6UmwzaohgA6uDmNsvSUV8ubqwA3Wpste1hg69XHgjUuCD5HLcEp2QPzyV1HMrPppsL"
    else:
        xpub = "tpubD6NzVbkrYhZ4XdmyJQcCPjQfg6RXVUzGFhPjZ7uvRC8JLcS7Hw1i7UTpyhp9grHpak4TyK2hzBJrujDVLXQ6qB5tNpVx9rC6ixijUXadnmY"
    if xtype not in ('standard', 'p2wsh'):
        raise NotImplementedError('xtype: {}'.format(xtype))
    if xtype == 'standard':
        return xpub
    node = BIP32Node.from_xkey(xpub)
    return node._replace(xtype=xtype).to_xpub()


def make_billing_address(wallet, num, addr_type):
    long_id, short_id = wallet.get_user_id()
    xpub = make_xpub(get_billing_xpub(), long_id)
    usernode = BIP32Node.from_xkey(xpub)
    child_node = usernode.subkey_at_public_derivation([num])
    pubkey = child_node.eckey.get_public_key_bytes(compressed=True)
    if addr_type == 'legacy':
        return bitcoin.public_key_to_p2pkh(pubkey)
    elif addr_type == 'segwit':
        return bitcoin.public_key_to_p2wpkh(pubkey)
    else:
        raise ValueError(f'unexpected billing type: {addr_type}')


def get_billing_xpub():
    """
    收费钱包的公钥
    :return:
    """
    if constants.net.TESTNET:
        # return "vpub5URjNwJV7u8qcGuUnp1deD6ttNrbUD2FskPhDMT5tBxEWWXTQom7SgXUMQM2tx1ujAi7zTiqgNVPdu68tSWoP2CMwkGekco4pAQFLfJAEX2"
        return "tpubD6NzVbkrYhZ4YsUnPYBtM1hy5hDo6m8q5jDPWBDhFXuizj6tFS7sD9kqPA7Cya3JBdxiwMZmTRd1axjtfKiSN59pUWEQbfCJ6bzP5rZSd8D"
    else:
        return "xpub661MyMwAqRbcH4XFkPVnQcG1jL6otSAAePud1yA2ZrKdBq15G7mqUFj9H7ijTGJTA7C7yKjsXcjarMRGvgV71iYzbhFJGUSjAsftdACRQLq"


from electrum.logging import Logger


class TOS(QTextEdit):
    tos_signal = pyqtSignal()
    error_signal = pyqtSignal(object)


class HandlerTwoFactor(QObject, Logger):

    def __init__(self, plugin, window):
        super().__init__()
        self.plugin = plugin
        self.window = window

    def prompt_user_for_otp(self, wallet, tx, on_success, on_failure):
        if not isinstance(wallet, self.plugin.wallet_class):
            return
        if wallet.can_sign_without_server():
            return
        if not wallet.keystores['x3/'].get_tx_derivations(tx):
            self.logger.info("twofactor: xpub3 not needed")
            return
        window = self.window.top_level_window()
        auth_code = self.plugin.auth_dialog(window)
        WaitingDialog(parent=window,
                      message=_('Waiting for TrustedCoin server to sign transaction...'),
                      task=lambda: wallet.on_otp(tx, auth_code),
                      on_success=lambda *args: on_success(tx),
                      on_error=on_failure)


def _move_leter(letter, n):
    """
    把字母变为字母表后n位的字母,z后面接a
    :param letter: 小写字母
    :param n: 要移动的字母
    :return: 移动的结果
    """
    return chr((ord(letter) - ord('a') + n) % 26 + ord('a'))


def Decrypt(k, c):
    """
    移位密码解密函数D
    :param k: 秘钥k,每个字母在字母表中移动k位
    :param c: 密文c
    :return: 明文p
    """
    letter_list = list(c.lower())
    p = ''.join([_move_leter(x, -k) for x in letter_list])
    return p
