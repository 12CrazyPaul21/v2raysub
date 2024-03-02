import unittest

from v2raysub import protocol


SS_URL = 'ss://YWVzLTEyOC1nY206NjYwMWZiOTBlOWIz@127.0.0.1:443#%E4%B8%AD%E5%9B%BD%E8%8A%82%E7%82%B91'
SS_BASE64_URL = 'ss://WVdWekxURXlPQzFuWTIwNk5qWXdNV1ppT1RCbE9XSXpAMTI3LjAuMC4xOjQ0MyMlRTQlQjglQUQlRTUlOUIlQkQlRTglOEElODIlRTclODIlQjkx'
TROJAN_URL = 'trojan://1ab005c7-f5bf-30d2-2b4c-240b3b721c5f@127.0.0.1:16663?security=tls&sni=www.test.com&type=tcp&flow=xtls-rprx-vision-udp443&alpn=h2%2Chttp%2F1.1&fp=safari&headerType=none&host=www.test1.com%2Cwww.test2.com&path=%2Froot&encryption=ss%3Bchacha20-ietf-poly1305%3Bpassword#%E4%B8%AD%E5%9B%BD%E8%8A%82%E7%82%B91'
TROJAN_BASE64_URL = 'trojan://MWFiMDA1YzctZjViZi0zMGQyLTJiNGMtMjQwYjNiNzIxYzVmQDEyNy4wLjAuMToxNjY2Mz9zZWN1cml0eT10bHMmc25pPXd3dy50ZXN0LmNvbSZ0eXBlPXRjcCZmbG93PXh0bHMtcnByeC12aXNpb24tdWRwNDQzJmFscG49aDIlMkNodHRwJTJGMS4xJmZwPXNhZmFyaSZoZWFkZXJUeXBlPW5vbmUmaG9zdD13d3cudGVzdDEuY29tJTJDd3d3LnRlc3QyLmNvbSZwYXRoPSUyRnJvb3QmZW5jcnlwdGlvbj1zcyUzQmNoYWNoYTIwLWlldGYtcG9seTEzMDUlM0JwYXNzd29yZCMlRTQlQjglQUQlRTUlOUIlQkQlRTglOEElODIlRTclODIlQjkx'
VMESS_URL = 'vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIuS4reWbveiKgueCuSAyIiwNCiAgImFkZCI6ICIxMjcuMC4wLjEiLA0KICAicG9ydCI6ICI0NDMiLA0KICAiaWQiOiAiYTNiMGQ4MzAtMDZkNC00ZmE2LWEyNTktNTdjYWJiMTAyOTJmIiwNCiAgImFpZCI6ICIxMjMiLA0KICAic2N5IjogImFlcy0xMjgtZ2NtIiwNCiAgIm5ldCI6ICJ0Y3AiLA0KICAidHlwZSI6ICJodHRwIiwNCiAgImhvc3QiOiAid3d3LmZha2UuY29tIiwNCiAgInBhdGgiOiAiL0Bmb3J3YXJkdjJyYXkiLA0KICAidGxzIjogInRscyIsDQogICJzbmkiOiAidGVzdC5jb20iLA0KICAiYWxwbiI6ICJoMixodHRwLzEuMSIsDQogICJmcCI6ICJjaHJvbWUiDQp9'


class TestProtocolParse(unittest.TestCase):    
    @unittest.skip('custom')
    def test_parse_http(self):
        result = protocol.parse('https://<<< custom >>>')
        self.assertIsNotNone(result)
        self.assertEqual(1, result['success'])
        self.assertNotEqual(0, len(result['subscribe_list']))

    def test_parse_shadowsocks(self):
        result = protocol.parse(SS_URL)
        self.assertIsNotNone(result)
        self.assertEqual(1, result['success'])
        self.assertEqual('127.0.0.1', result['server'])
        self.assertEqual('443', result['port'])
        self.assertEqual('6601fb90e9b3', result['identify'])
        self.assertEqual('aes-128-gcm', result['method'])

        result = protocol.parse(SS_BASE64_URL)
        self.assertIsNotNone(result)
        self.assertEqual(1, result['success'])
        self.assertEqual('127.0.0.1', result['server'])
        self.assertEqual('443', result['port'])
        self.assertEqual('6601fb90e9b3', result['identify'])
        self.assertEqual('aes-128-gcm', result['method'])

    def test_parse_trojan(self):
        result = protocol.parse(TROJAN_URL)
        self.assertIsNotNone(result)
        self.assertEqual(1, result['success'])
        self.assertEqual('127.0.0.1', result['server'])
        self.assertEqual('16663', result['port'])
        self.assertEqual('1ab005c7-f5bf-30d2-2b4c-240b3b721c5f', result['identify'])

        result = protocol.parse(TROJAN_BASE64_URL)
        self.assertIsNotNone(result)
        self.assertEqual(1, result['success'])
        self.assertEqual('127.0.0.1', result['server'])
        self.assertEqual('16663', result['port'])
        self.assertEqual('1ab005c7-f5bf-30d2-2b4c-240b3b721c5f', result['identify'])

    def test_parse_vmess(self):
        result = protocol.parse(VMESS_URL)
        self.assertIsNotNone(result)
        self.assertEqual(1, result['success'])
        self.assertEqual('127.0.0.1', result['server'])
        self.assertEqual('443', result['port'])
        self.assertEqual('a3b0d830-06d4-4fa6-a259-57cabb10292f', result['identify'])
        self.assertEqual('aes-128-gcm', result['method'])