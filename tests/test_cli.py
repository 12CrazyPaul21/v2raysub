import os
import shutil
import platform
import http.server
import threading
import unittest
import base64
import json

from prompt_toolkit.input.defaults import create_pipe_input
from prompt_toolkit.application import create_app_session
from prompt_toolkit.output import DummyOutput

from click.testing import CliRunner

from v2raysub import cli as v2submain


SS_URL = 'ss://YWVzLTEyOC1nY206NjYwMWZiOTBlOWIz@127.0.0.1:443#%E4%B8%AD%E5%9B%BD%E8%8A%82%E7%82%B91'
SS_BASE64_URL = 'ss://WVdWekxURXlPQzFuWTIwNk5qWXdNV1ppT1RCbE9XSXpAMTI3LjAuMC4xOjQ0MyMlRTQlQjglQUQlRTUlOUIlQkQlRTglOEElODIlRTclODIlQjkx'
TROJAN_URL = 'trojan://1ab005c7-f5bf-30d2-2b4c-240b3b721c5f@127.0.0.1:16663?security=tls&sni=www.test.com&type=tcp&flow=xtls-rprx-vision-udp443&alpn=h2%2Chttp%2F1.1&fp=safari&headerType=none&host=www.test1.com%2Cwww.test2.com&path=%2Froot&encryption=ss%3Bchacha20-ietf-poly1305%3Bpassword#%E4%B8%AD%E5%9B%BD%E8%8A%82%E7%82%B91'
TROJAN_BASE64_URL = 'trojan://MWFiMDA1YzctZjViZi0zMGQyLTJiNGMtMjQwYjNiNzIxYzVmQDEyNy4wLjAuMToxNjY2Mz9zZWN1cml0eT10bHMmc25pPXd3dy50ZXN0LmNvbSZ0eXBlPXRjcCZmbG93PXh0bHMtcnByeC12aXNpb24tdWRwNDQzJmFscG49aDIlMkNodHRwJTJGMS4xJmZwPXNhZmFyaSZoZWFkZXJUeXBlPW5vbmUmaG9zdD13d3cudGVzdDEuY29tJTJDd3d3LnRlc3QyLmNvbSZwYXRoPSUyRnJvb3QmZW5jcnlwdGlvbj1zcyUzQmNoYWNoYTIwLWlldGYtcG9seTEzMDUlM0JwYXNzd29yZCMlRTQlQjglQUQlRTUlOUIlQkQlRTglOEElODIlRTclODIlQjkx'
VMESS_URL = 'vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIuS4reWbveiKgueCuSAyIiwNCiAgImFkZCI6ICIxMjcuMC4wLjEiLA0KICAicG9ydCI6ICI0NDMiLA0KICAiaWQiOiAiYTNiMGQ4MzAtMDZkNC00ZmE2LWEyNTktNTdjYWJiMTAyOTJmIiwNCiAgImFpZCI6ICIxMjMiLA0KICAic2N5IjogImFlcy0xMjgtZ2NtIiwNCiAgIm5ldCI6ICJ0Y3AiLA0KICAidHlwZSI6ICJodHRwIiwNCiAgImhvc3QiOiAid3d3LmZha2UuY29tIiwNCiAgInBhdGgiOiAiL0Bmb3J3YXJkdjJyYXkiLA0KICAidGxzIjogInRscyIsDQogICJzbmkiOiAidGVzdC5jb20iLA0KICAiYWxwbiI6ICJoMixodHRwLzEuMSIsDQogICJmcCI6ICJjaHJvbWUiDQp9'


class FakeRequestHandler(http.server.SimpleHTTPRequestHandler):
    visited = 0

    def do_GET(self):
        response = f'{SS_URL}\n{SS_BASE64_URL}\n{TROJAN_URL}\n'
        if FakeRequestHandler.visited >= 2:
            response = f'{response}{TROJAN_BASE64_URL}\n'
        if FakeRequestHandler.visited >= 3:
            response = f'{response}{VMESS_URL}\n'

        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(base64.b64encode(response.encode('utf-8')))

        FakeRequestHandler.visited += 1


class TestCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fake_home = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'fake_home')
        cls.fake_app_dir = os.path.join(cls.fake_home, '.v2sub')
        cls.runner = CliRunner()
        cls.env = {}

        if platform.system() == 'Windows':
            cls.env['USERPROFILE'] = cls.fake_home
        else:
            cls.env['HOME'] = cls.fake_home

        os.makedirs(cls.fake_home, exist_ok=True)
        if os.path.exists(cls.fake_app_dir):
            shutil.rmtree(cls.fake_app_dir)

        cls.server = http.server.HTTPServer(('127.0.0.1', 9080), FakeRequestHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server_thread.join()
        shutil.rmtree(cls.fake_home)

    def test_case_1(self):
        """ config group commands before base config init """

        result = self.runner.invoke(v2submain.cli, ['config', 'edit'], env=self.env)
        self.assertEqual(result.exit_code, 1)
        self.assertIn('base_config.json not exists', result.output)

        result = self.runner.invoke(v2submain.cli, ['config', 'lan', 'allow'], env=self.env)
        self.assertEqual(result.exit_code, 1)
        self.assertIn('base_config.json not exists', result.output)

        result = self.runner.invoke(v2submain.cli, ['config', 'lan', 'disallow'], env=self.env)
        self.assertEqual(result.exit_code, 1)
        self.assertIn('base_config.json not exists', result.output)

        if platform.system() in ['Windows', 'Darwin']:
            with create_pipe_input() as pipe_input:
                pipe_input.send_text('\n')
                with create_app_session(input=pipe_input, output=DummyOutput()):
                    result = self.runner.invoke(v2submain.cli, ['config', 'proxy', 'enable'], env=self.env)
                    self.assertEqual(result.exit_code, 1)
                    self.assertIn('node_config.json not exists', result.output)
            with create_pipe_input() as pipe_input:
                pipe_input.send_text('j\n')
                with create_app_session(input=pipe_input, output=DummyOutput()):
                    result = self.runner.invoke(v2submain.cli, ['config', 'proxy', 'enable'], env=self.env)
                    self.assertEqual(result.exit_code, 1)
                    self.assertIn('node_service_config.json not exists', result.output)

    def test_case_2(self):
        """ subscribe group commands before base config init """

        result = self.runner.invoke(v2submain.cli, ['subscribe', 'parse', SS_URL], env=self.env)
        self.assertEqual(result.exit_code, 0)
        self.assertIn('protocol: shadowsocks', result.output)
        self.assertIn('server: 127.0.0.1', result.output)
        self.assertIn('port: 443', result.output)

        result = self.runner.invoke(v2submain.cli, ['subscribe', 'parse', 'http://127.0.0.1:9080/subscribe_list'], env=self.env)
        self.assertEqual(result.exit_code, 0)
        self.assertIn(SS_URL, result.output)
        self.assertIn(SS_BASE64_URL, result.output)
        self.assertIn(TROJAN_URL, result.output)

        result = self.runner.invoke(v2submain.cli, ['subscribe', 'add', SS_URL], env=self.env)
        self.assertEqual(result.exit_code, 1)
        self.assertIn('base_config.json not exists', result.output)

        result = self.runner.invoke(v2submain.cli, ['subscribe', 'update'], env=self.env)
        self.assertEqual(result.exit_code, 1)
        self.assertIn('base_config.json not exists', result.output)

        result = self.runner.invoke(v2submain.cli, ['subscribe', 'update', '--all'], env=self.env)
        self.assertEqual(result.exit_code, 1)
        self.assertIn('base_config.json not exists', result.output)

        result = self.runner.invoke(v2submain.cli, ['subscribe', 'delete'], env=self.env)
        self.assertEqual(result.exit_code, 1)
        self.assertIn('base_config.json not exists', result.output)

        result = self.runner.invoke(v2submain.cli, ['subscribe', 'delete', '--all'], env=self.env)
        self.assertEqual(result.exit_code, 1)
        self.assertIn('base_config.json not exists', result.output)

    def test_case_3(self):
        """ node group commands before base config init """

        result = self.runner.invoke(v2submain.cli, ['node', 'select'], env=self.env)
        self.assertEqual(result.exit_code, 1)
        self.assertIn('base_config.json not exists', result.output)

        result = self.runner.invoke(v2submain.cli, ['node', 'start'], env=self.env)
        self.assertEqual(result.exit_code, 1)
        self.assertTrue('install v2ray' in result.output or 'v2sub node select' in result.output)

        result = self.runner.invoke(v2submain.cli, ['node', 'stop'], env=self.env)
        self.assertEqual(result.exit_code, 1)
        self.assertIn('v2ray is not running', result.output)

        result = self.runner.invoke(v2submain.cli, ['node', 'restart'], env=self.env)
        self.assertEqual(result.exit_code, 1)
        self.assertTrue('install v2ray' in result.output or 'v2sub node select' in result.output)

        result = self.runner.invoke(v2submain.cli, ['node', 'status'], env=self.env)
        self.assertEqual(result.exit_code, 1)
        self.assertIn('base_config.json not exists', result.output)

    def test_case_4(self):
        """ service group commands before base config init """

        result = self.runner.invoke(v2submain.cli, ['service', 'select'], env=self.env)
        self.assertEqual(result.exit_code, 1)
        self.assertIn('base_config.json not exists', result.output)

        # result = self.runner.invoke(v2submain.cli, ['service', 'install'], env=self.env)
        # self.assertEqual(result.exit_code, 1)
        # self.assertTrue('install v2ray' in result.output or 'v2sub service select' in result.output)

        # result = self.runner.invoke(v2submain.cli, ['service', 'uninstall'], env=self.env)
        # self.assertEqual(result.exit_code, 1)
        # self.assertIn('v2sub service is not installed', result.output)

        # result = self.runner.invoke(v2submain.cli, ['service', 'status'], env=self.env)
        # self.assertEqual(result.exit_code, 1)
        # self.assertIn('v2sub service is not installed', result.output)

        # result = self.runner.invoke(v2submain.cli, ['service', 'start'], env=self.env)
        # self.assertEqual(result.exit_code, 1)
        # self.assertIn('v2sub service is not installed', result.output)

        # result = self.runner.invoke(v2submain.cli, ['service', 'stop'], env=self.env)
        # self.assertEqual(result.exit_code, 1)
        # self.assertIn('v2sub service is not installed', result.output)

        # result = self.runner.invoke(v2submain.cli, ['service', 'restart'], env=self.env)
        # self.assertEqual(result.exit_code, 1)
        # self.assertIn('v2sub service is not installed', result.output)

    def test_case_5(self):
        """ init base config """

        with create_pipe_input() as pipe_input:
            pipe_input.send_text('\n\n\n\n\n\n')
            with create_app_session(input=pipe_input, output=DummyOutput()):
                result = self.runner.invoke(v2submain.cli, ['init'], env=self.env)
                self.assertEqual(result.exit_code, 0)

    def test_case_6(self):
        """ config group commands after base config init """

        with create_pipe_input() as pipe_input:
            pipe_input.send_text('\n')
            with create_app_session(input=pipe_input, output=DummyOutput()):
                result = self.runner.invoke(v2submain.cli, ['config', 'lan', 'allow'], env=self.env)
                self.assertEqual(result.exit_code, 0)
                self.assertIn('write to', result.output)

        with open(os.path.join(self.fake_app_dir, 'base_config.json')) as file:
            content = file.read()
            self.assertIn('0.0.0.0', content)
            self.assertNotIn('127.0.0.1', content)

        with create_pipe_input() as pipe_input:
            pipe_input.send_text('\n')
            with create_app_session(input=pipe_input, output=DummyOutput()):
                result = self.runner.invoke(v2submain.cli, ['config', 'lan', 'disallow'], env=self.env)
                self.assertEqual(result.exit_code, 0)
                self.assertIn('write to', result.output)

        with open(os.path.join(self.fake_app_dir, 'base_config.json')) as file:
            content = file.read()
            self.assertIn('127.0.0.1', content)
            self.assertNotIn('0.0.0.0', content)

    def test_case_7(self):
        """ subscribe group commands after base config init """

        result = self.runner.invoke(v2submain.cli, ['subscribe', 'delete'], env=self.env)
        self.assertEqual(result.exit_code, 1)
        self.assertIn('subscribe list is empty', result.output)

        result = self.runner.invoke(v2submain.cli, ['subscribe', 'delete', '--all'], env=self.env)
        self.assertEqual(result.exit_code, 1)
        self.assertIn('subscribe list is empty', result.output)

        result = self.runner.invoke(v2submain.cli, ['subscribe', 'add', SS_URL], env=self.env)
        self.assertEqual(result.exit_code, 0)

        with create_pipe_input() as pipe_input:
            pipe_input.send_text('test_group\n')
            with create_app_session(input=pipe_input, output=DummyOutput()):
                result = self.runner.invoke(v2submain.cli, ['subscribe', 'add', 'http://127.0.0.1:9080/subscribe_list'], env=self.env)
                self.assertEqual(result.exit_code, 0)

        result = self.runner.invoke(v2submain.cli, ['subscribe', 'update'], env=self.env)
        self.assertEqual(result.exit_code, 0)

        result = self.runner.invoke(v2submain.cli, ['subscribe', 'update', '--all'], env=self.env)
        self.assertEqual(result.exit_code, 0)

        with open(os.path.join(self.fake_app_dir, 'subscribes.json'), 'r', encoding='utf-8') as file:
            obj = json.loads(file.read())
            self.assertEqual(len(obj['anonymous']), 1)
            self.assertEqual(len(obj['groups']['test_group']['nodes']), 5)

        result = self.runner.invoke(v2submain.cli, ['subscribe', 'delete', '--all'], env=self.env)
        self.assertEqual(result.exit_code, 0)

        with open(os.path.join(self.fake_app_dir, 'subscribes.json'), 'r', encoding='utf-8') as file:
            obj = json.loads(file.read())
            self.assertEqual(len(obj['anonymous']), 0)
            self.assertEqual(len(obj['groups']), 0)

        result = self.runner.invoke(v2submain.cli, ['subscribe', 'add', SS_URL], env=self.env)
        self.assertEqual(result.exit_code, 0)

        with create_pipe_input() as pipe_input:
            pipe_input.send_text('test_group\n')
            with create_app_session(input=pipe_input, output=DummyOutput()):
                result = self.runner.invoke(v2submain.cli, ['subscribe', 'add', 'http://127.0.0.1:9080/subscribe_list'], env=self.env)
                self.assertEqual(result.exit_code, 0)

    def test_case_8(self):
        """ node select and config """

        with create_pipe_input() as pipe_input:
            pipe_input.send_text('j\n\n')
            with create_app_session(input=pipe_input, output=DummyOutput()):
                result = self.runner.invoke(v2submain.cli, ['node', 'select'], env=self.env)
                self.assertEqual(result.exit_code, 0)

        with open(os.path.join(self.fake_app_dir, 'node_config.json'), 'r', encoding='utf-8') as file:
            obj = json.loads(file.read())
            self.assertEqual(obj['outbounds'][0]['protocol'], 'shadowsocks')

        with create_pipe_input() as pipe_input:
            pipe_input.send_text('j\n')
            with create_app_session(input=pipe_input, output=DummyOutput()):
                result = self.runner.invoke(v2submain.cli, ['config', 'lan', 'allow'], env=self.env)
                self.assertEqual(result.exit_code, 0)
                self.assertIn('write to', result.output)

        with open(os.path.join(self.fake_app_dir, 'node_config.json')) as file:
            obj = json.loads(file.read())
            self.assertEqual('0.0.0.0', obj['inbounds'][0]['listen'])
            self.assertEqual('0.0.0.0', obj['inbounds'][1]['listen'])

        with create_pipe_input() as pipe_input:
            pipe_input.send_text('\n')
            with create_app_session(input=pipe_input, output=DummyOutput()):
                result = self.runner.invoke(v2submain.cli, ['config', 'lan', 'disallow'], env=self.env)
                self.assertEqual(result.exit_code, 0)
                self.assertIn('write to', result.output)

        with open(os.path.join(self.fake_app_dir, 'node_config.json')) as file:
            obj = json.loads(file.read())
            self.assertEqual('127.0.0.1', obj['inbounds'][0]['listen'])
            self.assertEqual('127.0.0.1', obj['inbounds'][1]['listen'])

        # with create_pipe_input() as pipe_input:
        #     pipe_input.send_text('j\n\n\n')
        #     with create_app_session(input=pipe_input, output=DummyOutput()):
        #         result = self.runner.invoke(v2submain.cli, ['service', 'select'], env=self.env)
        #         self.assertEqual(result.exit_code, 0)

        # with open(os.path.join(self.fake_app_dir, 'node_service_config.json'), 'r', encoding='utf-8') as file:
        #     obj = json.loads(file.read())
        #     self.assertEqual(obj['outbounds'][0]['protocol'], 'shadowsocks')