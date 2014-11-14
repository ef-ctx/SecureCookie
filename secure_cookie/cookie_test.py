import unittest
from .cookie import SecureCookie, SecureCookieException, SecureCookieMaxLengthException, \
    SecureCookieMinAgeException, SecureCookieExpiredException

__author__ = 'broken'

TEST_HASHKEY = b'6vH34egsus5RXb68GeI4Cgj09TY78Sd1'
TEST_BLOCKKEY = b'6vH34egsus5RXb68GeI4Cgj09TY78Sd1'


class TestSecureCookie(unittest.TestCase):
    def test_verify_hmac(self):
        cookie_value = 'MTQxNDUxNDQ3MXxoMUJ6aER0RjA2cFFNZnFjT1U0eU1Kd3lPaVJBSGNPTnIxOUhwT1pmVFBZVG56RHkxeXQtVHN2eDl0Q2l5dUxfbGZkUnz2Kl9N5GD6yCn1WYP-D5XhpKbowfzqsdQzZMlkdKaWzg=='
        cookie_name = 'glowing-cookie'

        cookie = SecureCookie(cookie_name, hash_key=TEST_HASHKEY, block_key=TEST_BLOCKKEY)

        self.assertIsNotNone(cookie.decode(cookie_value))

    def test_decrypt_value(self):
        cookie_value = 'MTQxNDU4NTAwNHxBS0xjb1NxMXBiWVNuY21zZnpVTUd5SFlHX01lenNzTEZJNkU3UDBtelVhbS1iZF93WEx6dVVlME5wdWktamM9fBCJmVuW8yTRpRrFEsTWDPgiMx47QauAN_SDXIbchbYd'
        # cookie_value = 'MTQxNDYwMTk4MXxOQmVGeS1LT0tKbzNEX0g2QVVTeDRCRXZoQUZnYzFWRkl3UEdKcDlnOG9RckZxdFgtd0o5VWkzZXytO2QzX4kgK6MZw2PG3PSXAz_JsPiEs2t8xUrLPKZa0Q=='
        cookie_name = 'glowing-cookie'

        cookie = SecureCookie(cookie_name, hash_key=TEST_HASHKEY, block_key=TEST_BLOCKKEY)
        dst = cookie.decode(cookie_value)

        self.assertEqual(dst, 'super secret data in the cookie')

    def test_round_trip_without_encrypt(self):
        cookie_name = 'glowing-cookie'

        cookie = SecureCookie(cookie_name, hash_key=TEST_HASHKEY)

        cookie_value = cookie.encode('super secret data in the a awesome cookie')
        dst = cookie.decode(cookie_value)

        self.assertEqual(dst, 'super secret data in the a awesome cookie')

    def test_round_trip(self):
        cookie_name = 'glowing-cookie'

        cookie = SecureCookie(cookie_name, hash_key=TEST_HASHKEY, block_key=TEST_BLOCKKEY)

        cookie_value = cookie.encode('super secret data in the cookie')
        dst = cookie.decode(cookie_value)

        self.assertEqual(dst, 'super secret data in the cookie')

    def test_honor_max_length(self):
        cookie_name = 'glowing-cookie'

        cookie = SecureCookie(cookie_name, hash_key=TEST_HASHKEY, max_length=1)

        with self.assertRaises(SecureCookieMaxLengthException):
            cookie.encode('super secret data in the a awesome cookie')

    def test_honor_max_age(self):
        cookie_name = 'glowing-cookie'

        cookie = SecureCookie(cookie_name, hash_key=TEST_HASHKEY, max_age=-100)
        cookie_value = cookie.encode('super secret data in the a awesome cookie')

        with self.assertRaises(SecureCookieExpiredException):
            cookie.decode(cookie_value)

    def test_honor_min_age(self):
        cookie_name = 'glowing-cookie'

        cookie = SecureCookie(cookie_name, hash_key=TEST_HASHKEY, min_age=100)
        cookie_value = cookie.encode('super secret data in the a awesome cookie')

        with self.assertRaises(SecureCookieMinAgeException):
            cookie.decode(cookie_value)
