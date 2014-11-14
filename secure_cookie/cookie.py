import base64
from datetime import datetime
import hashlib
import hmac
import logging
from urlparse import urlparse

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter

__author__ = 'broken'

__all__ = [
    'SecureCookieException',
    'SecureCookieMaxLengthException',
    'SecureCookieExpiredException',
    'SecureCookieMinAgeException',
    'SecureCookie',
]


class SecureCookieException(Exception):
    pass


class SecureCookieMaxLengthException(Exception):
    pass


class SecureCookieExpiredException(Exception):
    pass


class SecureCookieMinAgeException(Exception):
    pass


class SecureCookie(object):
    hash_key = None
    block_key = None
    defaults = dict(
        max_age=86400 * 30,
        max_length=4096,
        min_age=0
    )

    def __init__(self, name, hash_key=None, block_key=None, **kwds):
        assert name, 'A SecureCookie must have a name'
        self.name = name
        self.hash_key = hash_key
        self.block_key = block_key
        self.block_size = 16

        self.options = dict([(key, kwds.get(key, value)) for key, value in self.defaults.iteritems()])

    @staticmethod
    def __decode_base64(base64_str):
        return base64.urlsafe_b64decode(base64_str)

    @staticmethod
    def __encode_base64(base64_str):
        return base64.urlsafe_b64encode(base64_str)

    @staticmethod
    def __to_timestamp(dt, epoch=datetime(1970, 1, 1)):
        td = dt - epoch
        # return td.total_seconds()
        return int((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 1e6)

    def __decrypt(self, enc):
        iv = enc[:self.block_size]
        counter = Counter.new(self.block_size*8, initial_value=long(iv.encode('hex'), 16))

        cipher = AES.new(self.block_key, AES.MODE_CTR, iv, counter=counter)
        return cipher.decrypt(enc[self.block_size:])

    def __encrypt(self, raw):
        iv = Random.new().read(self.block_size)
        counter = Counter.new(self.block_size*8, initial_value=long(iv.encode('hex'), 16))

        cipher = AES.new(self.block_key, AES.MODE_CTR, iv, counter=counter)
        return '%s%s' % (iv, cipher.encrypt(raw))

    def __new_hmac(self, b):
        return hmac.new(self.hash_key, msg=b, digestmod=hashlib.sha256).digest()

    def decode(self, value):
        b64 = self.__decode_base64(value)
        parts = b64.split('|', 2)
        b = '|'.join([self.name] + parts[:len(parts) - 1])

        if len(parts) < 3:
            raise SecureCookieException('Invalid cookie')

        # Verify hmac
        hmac_str = self.__new_hmac(b).encode('hex')
        p2 = parts[2].encode('hex')
        if not hmac_str == p2:
            raise SecureCookieException('verify hmac failed, the value is not valid')

        now = datetime.utcnow()
        t1 = int(parts[0])
        t2 = self.__to_timestamp(now)

        max_age = self.options['max_age']
        min_age = self.options['min_age']

        if min_age != 0 and t1 > (t2 - min_age):
            raise SecureCookieMinAgeException('timestamp is too new')

        if max_age != 0 and t1 < (t2 - max_age):
            raise SecureCookieExpiredException('expired timestamp')

        b = self.__decode_base64(parts[1])

        if self.block_key:
            return self.__decrypt(b)

        return b

    def encode(self, value):
        parts = [None, None, None]

        now = datetime.utcnow()
        parts[0] = str(self.__to_timestamp(now))

        b = value

        if self.block_key:
            b = self.__encrypt(value)

        parts[1] = self.__encode_base64(b)

        # HMAC
        b = '|'.join([self.name] + parts[:len(parts) - 1])
        parts[2] = self.__new_hmac(b)

        if not all(parts):
            raise SecureCookieException('not all parts where filled')

        b = self.__encode_base64('|'.join(parts))
        if self.options.get('max_length', 0) > 0 and len(b) > self.options['max_length']:
            raise SecureCookieMaxLengthException('value length (%i) exceeds max_length (%i)' % (len(b), self.options['max_length']))

        return b

    def set_cookie_args(self, req, host=None, path=None):
        if host:
            uri = urlparse(host)
            domain = uri.hostname
            scheme = uri.scheme
        else:
            assert hasattr(req, 'domain'), 'Missing attr domain on %r' % req
            assert hasattr(req, 'scheme'), 'Missing attr scheme on %r' % req

            domain = req.domain
            scheme = req.scheme

        return {
            'max_age':     self.defaults['max_age'],
            'domain':      domain,
            'path':        path if path else '/',
            'secure':      True if scheme == 'https' else False,
            'httponly':    False,
        }