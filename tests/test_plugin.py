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


FAKE_URLs = [
    'hh://password@localhost:5432?tls=1#fake1',
]


class FakeRequestHandler(http.server.SimpleHTTPRequestHandler):
    visited = 0

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(base64.b64encode('\n'.join(FAKE_URLs).encode('utf-8')))


def generate_scripts(plugin_dir):
    with open(os.path.join(plugin_dir, 'invalid_plugin.py'), 'w', encoding='utf-8') as file:
        file.write('invalid python script')

    with open(os.path.join(plugin_dir, 'add_new_command.py'), 'w', encoding='utf-8') as file:
        file.write('''import sys

from v2raysub import cli

@cli.cli.command("monkey")
def monkey():
    print('monkey monkey')
    sys.exit(0)
''')

    with open(os.path.join(plugin_dir, 'hh_scheme.py'), 'w', encoding='utf-8') as file:
        file.write('''
import re

from urllib.parse import urlparse, unquote, ParseResult

from v2raysub import protocol, util


def parse_hh(url: ParseResult) -> object:
    result = {'success': 0}

    url = urlparse(f'hh://{protocol.regular_content(url)}')
    pattern = r'^(?P<password>.+)@(?P<server>.+):(?P<port>\d+)$'

    match = re.match(pattern, url.netloc)
    if match is None:
        result['reason'] = 'invalid hoohoo params'
        return result

    result['success'] = 1
    result['protocol'] = 'hoohoo'
    result['remark'] = unquote(url.fragment)
    result['server'] = match['server']
    result['port'] = match['port']
    result['identify'] = match['password']
    result['method'] = 'chacha20'
    result['options'] = util.parse_query_string(url.query)

    return result


def generate_hoohoo_outbound(config, node, node_info, node_options) -> object:
    config['settings']['servers'] = [{
        'address': node_info['server'],
        'method': node_info['method'],
        'ota': False,
        'password': node_info['identify'],
        'port': int(node_info['port'])
    }]
    config['streamSettings'] = {
        "network": "tcp"
    }

    if node_options.get('tls', '0') == '1':
        config['streamSettings']['security'] = 'tls'

    return config


def init_plugin(app):
    protocol.register_parser('hh', parse_hh)
    protocol.register_generator('hoohoo', generate_hoohoo_outbound)

''')


class TestPlugin(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fake_home = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'fake_home_plugin_test')
        cls.fake_app_dir = os.path.join(cls.fake_home, '.v2sub')
        cls.fake_plugins_dir = os.path.join(cls.fake_app_dir, 'plugins')
        cls.runner = CliRunner()
        cls.env = {}

        if platform.system() == 'Windows':
            cls.env['USERPROFILE'] = cls.fake_home
        else:
            cls.env['HOME'] = cls.fake_home

        os.makedirs(cls.fake_home, exist_ok=True)
        if os.path.exists(cls.fake_app_dir):
            shutil.rmtree(cls.fake_app_dir)
        os.makedirs(cls.fake_plugins_dir, exist_ok=True)

        generate_scripts(cls.fake_plugins_dir)

        with create_pipe_input() as pipe_input:
            pipe_input.send_text('\n\n\n\n\n\n')
            with create_app_session(input=pipe_input, output=DummyOutput()):
                cls.runner.invoke(v2submain.cli, ['init'], env=cls.env)

        cls.server = http.server.HTTPServer(('127.0.0.1', 9081), FakeRequestHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server_thread.join()
        shutil.rmtree(cls.fake_home)
        v2submain.App.inited = False

    def test_plugin_list(self):
        result = self.runner.invoke(v2submain.cli, ['plugins'], env=self.env)
        self.assertEqual(result.exit_code, 0)
        self.assertIn('add_new_command: ', result.output)
        self.assertIn('hh_scheme: ', result.output)
        self.assertNotIn('invalid_plugin: ', result.output)

    def test_add_new_command(self):
        result = self.runner.invoke(v2submain.cli, ['monkey'], env=self.env)
        self.assertEqual(result.exit_code, 0)
        self.assertIn('monkey monkey', result.output)

    def test_parse_fake_scheme(self):
        result = self.runner.invoke(
            v2submain.cli,
            ['subscribe', 'parse', 'http://127.0.0.1:9081/subscribe'],
            env=self.env
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn(FAKE_URLs[0], result.output)

        result = self.runner.invoke(v2submain.cli, ['subscribe', 'parse', FAKE_URLs[0]], env=self.env)
        self.assertEqual(result.exit_code, 0)
        self.assertIn('protocol: hoohoo', result.output)
        self.assertIn('alias: fake1', result.output)
        self.assertIn('port: 5432', result.output)
        self.assertIn('method: chacha20', result.output)

    def test_add_fake_subscribe(self):
        result = self.runner.invoke(v2submain.cli, ['subscribe', 'add', FAKE_URLs[0]], env=self.env)
        self.assertEqual(result.exit_code, 0)

        with create_pipe_input() as pipe_input:
            pipe_input.send_text('fake_group\n')
            with create_app_session(input=pipe_input, output=DummyOutput()):
                result = self.runner.invoke(
                    v2submain.cli,
                    ['subscribe', 'add', 'http://127.0.0.1:9081/subscribe'],
                    env=self.env
                )
                self.assertEqual(result.exit_code, 0)

        with create_pipe_input() as pipe_input:
            pipe_input.send_text('jj\n\n\n')
            with create_app_session(input=pipe_input, output=DummyOutput()):
                result = self.runner.invoke(v2submain.cli, ['node', 'select'], env=self.env)
                self.assertEqual(result.exit_code, 0)

        with open(os.path.join(self.fake_app_dir, 'node_config.json'), 'r', encoding='utf-8') as file:
            obj = json.loads(file.read())
            self.assertEqual(obj['outbounds'][0]['protocol'], 'hoohoo')