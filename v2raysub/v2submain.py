import os
import sys
import logging
import click
import functools
import platform
import subprocess
import psutil
import json
import time
import shutil

from . import __version__ as v2sub_version
from . import protocol
from . import util
from . import config
from . import service

from .util import Input


class AppDecorator:
    @staticmethod
    def base_config_exists():
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                return util.file_exists(
                    App,
                    'base_config_path',
                    'please execute command: v2sub init'
                )(func)(*args, **kwargs)
            return wrapper
        return decorator

    @staticmethod
    def open_subscribe_config():
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    App.subscribe_config.open(App.subscribe_list_path)
                except BaseException as e:
                    logging.error(f'open {App.subscribe_list_path} failed: {e}')
                    sys.exit(1)
                return func(*args, **kwargs)
            return wrapper
        return decorator

    @staticmethod
    def v2sub_service_installed():
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                if not service.is_installed(App.v2sub_service_name):
                    print('v2sub service is not installed')
                    sys.exit(1)

                return func(*args, **kwargs)
            return wrapper
        return decorator


class App:

    system = ''
    home_dir = ''
    app_dir = ''
    service_dir = ''
    base_config_path = ''
    node_config_path = ''
    node_service_config_path = ''
    pid_path = ''
    proxychains_conf_path = ''
    v2sub_service_name = ''
    v2sub_service_path = ''
    subscribe_list_path = ''

    subscribe_config: config.SubscribeConfig = None

    @staticmethod
    def init():
        App.system = platform.system()
        App.home_dir = os.path.expanduser('~')
        App.app_dir = os.path.join(App.home_dir, '.v2sub')
        App.service_dir = os.path.join(App.app_dir, 'service')
        App.base_config_path = os.path.join(App.app_dir, 'base_config.json')
        App.node_config_path = os.path.join(App.app_dir, 'node_config.json')
        App.node_service_config_path = os.path.join(App.service_dir, 'node_service_config.json')
        App.pid_path = os.path.join(App.app_dir, 'pid')
        App.proxychains_conf_path = os.path.join(App.app_dir, 'proxychains.conf')
        if App.system == 'Linux':
            App.v2sub_service_name = 'v2sub'
            App.v2sub_service_path = os.path.join(App.service_dir, 'v2sub.service')
        elif App.system == 'Darwin':
            App.v2sub_service_name = 'com.v2sub.service'
            App.v2sub_service_path = os.path.join(App.service_dir, 'com.v2sub.service.plist')
        else:
            App.v2sub_service_name = 'v2sub'
            App.v2sub_service_path = os.path.join(App.service_dir, 'v2sub_service.exe')
        App.subscribe_list_path = os.path.join(App.app_dir, 'subscribes.json')
        App.subscribe_config = config.SubscribeConfig()

        if App.system == 'Windows':
            v2ray_installed_path = os.path.join(App.app_dir, "v2ray")
            proxychains_installed_path = os.path.join(App.app_dir, "proxychains")
            os.environ['PATH'] = f'{v2ray_installed_path};{proxychains_installed_path};{os.environ.get("PATH", "")}'

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter('%(message)s'))

        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        logger.addHandler(console_handler)

    @staticmethod
    def generate_config() -> int:
        print('init your base v2ray config:')
        if not config.generate_v2ray_base_config(
            App.app_dir,
            App.base_config_path,
            Input.select('loglevel:', choices=['debug', 'info', 'warning', 'error', 'none'], default='warning'),
            Input.ask_port('inbound socks port:', default='23338'),
            Input.ask_port('inbound http port:', default='23339'),
            Input.ask_port('inbound socks port(service mode):', default='22338'),
            Input.ask_port('inbound http port(service mode):', default='22339'),
            Input.select(
                'listen(0.0.0.0 allow lan connection, but need to manually add firewall rules):',
                choices=['127.0.0.1', '0.0.0.0'], default='127.0.0.1'
            )
        ):
            return 1

        print(f'write to {App.base_config_path}')
        return 0

    @staticmethod
    def parse_url(url: str) -> int:
        result = protocol.parse(url)
        if result['success'] == 0:
            logging.error(f'parse failed: {result["reason"]}')
            return 1

        if 'subscribe_list' in result:
            for item in result['subscribe_list']:
                print(item)
            return 0

        print(f'protocol: {result["protocol"]}')
        print(f'alias: {result["remark"]}')
        print(f'server: {result["server"]}')
        print(f'port: {result["port"]}')
        print(f'identify: {result["identify"]}')

        if result['method']:
            print(f'method: {result["method"]}')

        if result['options']:
            print('options:')
            for k, v in result['options'].items():
                print(f' - {k}: {v}')

        return 0

    @staticmethod
    def subscribe(url: str) -> int:
        result = protocol.parse(url)
        if result['success'] == 0:
            logging.error(f'parse failed: {result["reason"]}')
            return 1

        try:
            if 'subscribe_list' not in result:
                App.subscribe_config.add_anonymous(url, result)
            else:
                App.subscribe_config.add_group(Input.ask_text('new subscribe name:'), url, result)
        except BaseException as e:
            logging.error(f'subscribe failed: {e}')
            sys.exit(1)

        return 0

    @staticmethod
    def update_subscribe(is_update_all: bool) -> int:
        if App.subscribe_config.group_count() == 0:
            print('subscribe group is empty')
            return 1

        try:
            if is_update_all or App.subscribe_config.group_count() == 1:
                App.subscribe_config.update_all()
            else:
                selected = Input.select_with_cancel('update subscribe group: ', App.subscribe_config.groups())
                if selected:
                    App.subscribe_config.update(selected)
        except BaseException as e:
            logging.error(f'update subscribe failed: {e}')
            sys.exit(1)

        return 0

    @staticmethod
    def delete_subscribe(is_delete_all: bool) -> int:
        anonymous_nodes = App.subscribe_config.anonymous_names()
        groups = App.subscribe_config.groups()

        if len(anonymous_nodes) == 0 and len(groups) == 0:
            print('subscribe list is empty')
            return 1

        if is_delete_all:
            sub_type = 'all'
        elif len(anonymous_nodes) != 0 and len(groups) != 0:
            sub_type = Input.select_with_cancel('choose subscribe type: ', ['anonymous', 'groups'])
        elif len(anonymous_nodes) != 0:
            sub_type = 'anonymous'
        else:
            sub_type = 'groups'

        try:
            if sub_type == 'all':
                App.subscribe_config.clean()
            elif sub_type == 'anonymous':
                name = Input.select_with_cancel('choose anonymous node: ', anonymous_nodes)
                if name:
                    App.subscribe_config.delete_anonymous_node(name)
            elif sub_type == 'groups':
                name = Input.select_with_cancel('choose group: ', groups)
                if name:
                    App.subscribe_config.delete_group(name)
        except BaseException as e:
            logging.error(f'delete subscribe failed: {e}')
            sys.exit(1)

        return 0

    @staticmethod
    def _select_sublist_node(group_name):
        if not group_name:
            return None

        nodes = App.subscribe_config.group_node_names(group_name)
        if not nodes:
            return None

        return Input.select_with_cancel(f'choose {group_name} node: ', nodes)

    @staticmethod
    def select_node(service_mode=False) -> int:
        curr_selected = App.subscribe_config.selected(service_mode)
        if curr_selected:
            print('current select node:')
            print(f'  node name: {curr_selected["name"]}')
            print(
                '  subscribe list name: '
                + ('anonymous' if len(curr_selected['group_name']) == 0 else curr_selected['group_name'])
            )
            print(f'  node info: {curr_selected["node"]}')

        anonymous_nodes = App.subscribe_config.anonymous_names()
        groups = App.subscribe_config.groups()

        if len(anonymous_nodes) == 0 and len(groups) == 0:
            print('subscribe list is empty')
            return 1

        if len(anonymous_nodes) != 0 and len(groups) != 0:
            sub = Input.select_with_cancel('choose subscribe type: ', ['anonymous', 'groups'])
            if not sub:
                return 1
        elif len(anonymous_nodes) != 0:
            sub = 'anonymous'
        else:
            sub = 'groups'

        if sub == 'anonymous':
            sub = ''
            name = Input.select_with_cancel('choose anonymous node: ', anonymous_nodes)
        else:
            sub = Input.select_with_cancel('choose group list: ', groups)
            name = App._select_sublist_node(sub)

        if not name:
            return 1

        try:
            if service_mode:
                os.makedirs(App.service_dir, exist_ok=True)
                config_path = App.node_service_config_path
            else:
                config_path = App.node_config_path

            node = App.subscribe_config.select(sub, name, service_mode)
            config.generate_node_config(
                config_path,
                App.base_config_path,
                config.generate_outbound_config(node),
                service_mode
            )
        except BaseException as e:
            logging.error(f'select node failed: {e}')
            sys.exit(1)

        return 0

    @staticmethod
    def show_temporarily_effect_tips(service_mode=False):
        http_inbound = App.load_node_config(service_mode, 'http')
        if not http_inbound:
            return

        print('tips: execute the following commands can temporarily take effect on some programs')

        http_listen = http_inbound['listen']
        http_port = http_inbound['port']
        if http_listen == '0.0.0.0':
            http_listen = '127.0.0.1'

        http_proxy = f"http_proxy='http://{http_listen}:{http_port}'"
        https_proxy = f"https_proxy='http://{http_listen}:{http_port}'"

        if App.system == 'Windows':
            print('powershell:')
            print(f'$env:{http_proxy}')
            print(f'$env:{https_proxy}')
            print('cmd:')
            print(f"set http_proxy=http://{http_listen}:{http_port}")
            print(f"set https_proxy=http://{http_listen}:{http_port}")
            print('cygwin or mingw64:')
            print(f'export {http_proxy}')
            print(f'export {https_proxy}')
        else:
            print(f'export {http_proxy}')
            print(f'export {https_proxy}')

    @staticmethod
    def show_add_allow_lan_firewall_rule_tips(node_config):
        ports = []

        for inbound in node_config['config'].get('inbounds', []):
            if 'tag' not in inbound or 'port' not in inbound:
                continue
            ports.append({
                'tag': inbound['tag'],
                'port': inbound['port'],
                'service_mode': 0
            })
            if 'service_mode_port' in inbound:
                ports.append({
                    'tag': inbound['tag'],
                    'port': inbound['service_mode_port'],
                    'service_mode': 1
                })

        if len(ports) == 0:
            return

        print(
            'tips: for safety, you can manually add firewall ruels like '
            'the following commands(administrator/root)'
        )

        v2ray_bin = util.find_bin('v2ray')

        for port in ports:
            rule_name = f'v2sub {"service " if port["service_mode"] == 0 else ""}{port["tag"]} inbound lan allow'

            if App.system == 'Windows':
                print(
                    f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=allow '
                    f'protocol=TCP localport={port["port"]} program="{v2ray_bin}"'
                )
            elif App.system == 'Linux':
                if util.find_bin('firewall-cmd'):
                    print(f'sudo firewall-cmd --zone=public --add-port={port["port"]}/tcp --permanent # {rule_name}')
                elif util.find_bin('ufw'):
                    print(f'sudo ufw allow {port["port"]}/tcp # {rule_name}')
                else:
                    # iptables
                    print(f'sudo iptables -A INPUT -p tcp --dport {port["port"]} -j ACCEPT # {rule_name}')

        if App.system == 'Linux':
            if util.find_bin('firewall-cmd'):
                print('sudo firewall-cmd --reload')
            elif util.find_bin('ufw'):
                print('sudo ufw enable')
                print('sudo ufw reload')
            else:
                # iptables
                print('sudo netfilter-persistent save')
        elif App.system == 'Darwin':
            if os.system(f'file {v2ray_bin} | grep "shell script"') == 0:
                real_bin = util.check_cmd_output('cat /usr/local/bin/v2ray | sed -rn \'s/.*exec \"([^\"]*)\".*/\\1/p\'')
                if real_bin:
                    v2ray_bin = real_bin
            print(f'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add {v2ray_bin}')
            print(f'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp {v2ray_bin}')

    @staticmethod
    def run_v2ray() -> int:
        try:
            if App.system == 'Windows':
                import win32process
                import win32con

                flag = win32process.CREATE_NEW_CONSOLE
                si = win32process.STARTUPINFO()

                si.dwFlags = win32process.STARTF_USESHOWWINDOW
                si.wShowWindow = win32con.SW_HIDE

                args = [util.find_bin('v2ray'), 'run', '-c', App.node_config_path]
                process_info = win32process.CreateProcess(None, ' '.join(args), None, None, 0, flag, None, None, si)
                os.system(f'echo {process_info[2]} > {App.pid_path}')
            elif App.system == 'Linux':
                import multiprocessing

                def _daemon():
                    process = subprocess.Popen(
                        [util.find_bin('v2ray'), 'run', '-c', App.node_config_path],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    os.system(f'echo {process.pid} > {App.pid_path}')

                process = multiprocessing.Process(target=_daemon, daemon=True)
                process.start()
                process.join()
            elif App.system == 'Darwin':
                process = subprocess.Popen(
                    [util.find_bin('v2ray'), 'run', '-c', App.node_config_path],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                os.system(f'echo {process.pid} > {App.pid_path}')
            else:
                logging.error(f'{App.system} unsupported')
                sys.exit(1)

            print(f'v2ray run success, pid: {util.read_line(App.pid_path)}')
        except SystemExit:
            raise
        except BaseException as e:
            logging.error(f'run v2ray failed: {e}')
            sys.exit(1)

        App.show_temporarily_effect_tips(False)
        return 0

    @staticmethod
    def stop_v2ray(restart_mode=False) -> int:
        try:
            process = psutil.Process(int(util.read_line(App.pid_path)))
            process.terminate()
            os.remove(App.pid_path)
        except BaseException as e:
            logging.error(f'stop v2ray failed: {e}')
            sys.exit(1)

        if not restart_mode and App.system in ['Windows', 'Darwin']:
            App.check_proxy_need_disable('normal node')

        return 0

    @staticmethod
    def v2ray_status() -> int:
        if not util.check_is_running(App.pid_path, 'v2ray'):
            print('v2ray status: stopped')
            return 1
        else:
            print('v2ray status: running')

        node_config = App.load_node_config(service_mode=False)
        for inbound in node_config.get('inbounds', []):
            if 'tag' in inbound and 'listen' in inbound and 'port' in inbound:
                print(f'{inbound["tag"]} proxy: {inbound["listen"]}:{inbound["port"]}')

        curr_selected = App.subscribe_config.selected(service_mode=False)
        if curr_selected:
            print('current select node:')
            print(f'  node name: {curr_selected["name"]}')
            print(
                '  subscribe list name: '
                + ('anonymous' if len(curr_selected['group_name']) == 0 else curr_selected['group_name'])
            )
            print(f'  node info: {curr_selected["node"]}')

        return 0

    @staticmethod
    def install_windows_service() -> int:
        try:
            if not os.path.exists(App.v2sub_service_path):
                service.compile_windows_v2sub_service(App.service_dir)
        except BaseException as e:
            logging.error(f'compile v2sub service failed: {e}')
            sys.exit(1)

        install_cmd = f'{App.v2sub_service_path} install'

        v2ray_bin = util.find_bin('v2ray')
        config_cmd = 'sc.exe config v2sub '
        config_cmd += f'binpath="{App.v2sub_service_path} {v2ray_bin} {App.node_service_config_path}" '
        config_cmd += 'start="delayed-auto"'

        util.runas_admin([
            install_cmd,
            config_cmd,
            'sc.exe start v2sub'
        ])

        time.sleep(1)
        if service.is_installed('v2sub'):
            print('install v2sub service success')

        return 0

    @staticmethod
    def install_mac_service() -> int:
        service_installed_path = os.path.join(App.home_dir, "Library/LaunchAgents")
        service_conf_dir = f'{service_installed_path}/{App.v2sub_service_name}.d'

        try:
            service.generate_mac_v2sub_service(App.v2sub_service_path, service_conf_dir)
        except Exception as e:
            logging.error(f'generate v2sub service failed: {e}')
            sys.exit(1)

        os.makedirs(service_installed_path, exist_ok=True)

        retval = util.run_cmds([
            f'cp -f {App.v2sub_service_path} {service_installed_path}',
            f'mkdir -p {service_conf_dir}',
            f'cp -f {App.node_service_config_path} {service_conf_dir}',
            f'launchctl load {service_installed_path}/{App.v2sub_service_name}.plist',
            f'launchctl start {App.v2sub_service_name}',
        ])

        print(f'install v2sub service {"success" if retval == 0 else "failed"}')
        return retval

    @staticmethod
    def install_linux_service() -> int:
        try:
            service.generate_linux_v2sub_service(App.v2sub_service_path)
        except Exception as e:
            logging.error(f'generate v2sub service failed: {e}')
            sys.exit(1)

        retval = util.run_cmds([
            f'sudo cp -f {App.v2sub_service_path} /etc/systemd/system/v2sub.service',
            'sudo chmod 644 /etc/systemd/system/v2sub.service',
            'sudo systemctl daemon-reload',
            'sudo systemctl enable v2sub',
            'sudo mkdir -p /etc/systemd/system/v2sub.service.d',
            'sudo chmod -R 655 /etc/systemd/system/v2sub.service.d',
            'sudo mkdir -p /var/log/v2sub; sudo chmod -R 777 /var/log/v2sub',
            'sudo chmod -R 655 /etc/systemd/system/v2sub.service.d',
            f'sudo cp -f {App.node_service_config_path} /etc/systemd/system/v2sub.service.d',
            'sudo chmod 644 /etc/systemd/system/v2sub.service.d/node_service_config.json',
            'sudo systemctl start v2sub',
        ])

        print(f'install v2sub service {"success" if retval == 0 else "failed"}')
        return retval

    @staticmethod
    def load_base_config() -> dict:
        node_config = {}

        try:
            with open(App.base_config_path, 'r', encoding='utf-8') as file:
                node_config = json.loads(file.read())
        except Exception as e:
            node_config = {}
            logging.error(f'read {App.base_config_path} failed: {e}')

        return node_config

    @staticmethod
    def load_node_config(service_mode=False, only_inbound_tag=None) -> dict:
        node_config = {}
        node_config_path = App.node_service_config_path if service_mode else App.node_config_path

        try:
            with open(node_config_path, 'r', encoding='utf-8') as file:
                node_config = json.loads(file.read())
        except Exception as e:
            node_config = {}
            logging.error(f'read {node_config_path} failed: {e}')

        if only_inbound_tag:
            inbound_config = None
            for inbound in node_config.get('inbounds', []):
                if 'tag' in inbound and 'listen' in inbound and 'port' in inbound:
                    if inbound['tag'] == only_inbound_tag:
                        inbound_config = inbound
                        break
            return inbound_config

        return node_config

    @staticmethod
    def load_all_config() -> list:
        config_list = [{
            'name': 'base config',
            'path': App.base_config_path,
            'config': App.load_base_config()
        }]

        if os.path.exists(App.node_config_path):
            config_list.append({
                'name': 'normal node',
                'path': App.node_config_path,
                'config': App.load_node_config(False)
            })

        if os.path.exists(App.node_service_config_path):
            config_list.append({
                'name': 'service',
                'path': App.node_service_config_path,
                'config': App.load_node_config(True)
            })

        return config_list

    @staticmethod
    def reflush_config(node_config):
        with open(node_config['path'], 'w', encoding='utf-8') as file:
            file.write(json.dumps(node_config['config'], indent=2, ensure_ascii=False))

        if node_config['name'] == 'normal node':
            if not util.check_is_running(App.pid_path, 'v2ray'):
                return

            App.stop_v2ray(True)
            time.sleep(0.5)
            App.run_v2ray()
        elif node_config['name'] == 'service':
            if App.system == 'Linux' and os.path.exists('/etc/systemd/system/v2sub.service.d/node_service_config.json'):
                os.system(f'sudo cp -f {node_config["path"]} /etc/systemd/system/v2sub.service.d')
                os.system('sudo chmod 644 /etc/systemd/system/v2sub.service.d/node_service_config.json')

            if service.is_running(App.v2sub_service_name):
                if App.system == 'Windows':
                    util.runas_admin([
                        'sc.exe stop v2sub',
                        'timeout /t 2',
                        'sc.exe start v2sub'
                    ])
                else:
                    service.stop_service(App.v2sub_service_name)
                    time.sleep(0.5)
                    service.start_service(App.v2sub_service_name)

    @staticmethod
    def ask_for_lan_allow_command_target(allowed=False):
        config_list = App.load_all_config()
        ask_list = []

        for item in config_list:
            if not item['config'] or len(item['config'].get('inbounds', [])) == 0:
                continue
            for inbound in item['config']['inbounds']:
                if allowed:
                    if inbound.get('listen', '') == '0.0.0.0':
                        ask_list.append(item)
                        break
                else:
                    if inbound.get('listen', '') != '0.0.0.0':
                        ask_list.append(item)
                        break

        if len(ask_list) == 0:
            return None

        selected = Input.select_with_cancel('choose your config:', [item['name'] for item in ask_list])
        if not selected:
            return None

        return list(filter(lambda item: item['name'] == selected, ask_list))[0]

    @staticmethod
    def ask_for_proxy_config_type() -> str:
        mode = Input.select_with_cancel('choose your proxy config:', ['normal node', 'service'])
        if not mode:
            sys.exit(0)

        service_mode = (mode == 'service')
        node_config_path = App.node_service_config_path if service_mode else App.node_config_path

        if not os.path.exists(node_config_path):
            logging.error(f'{node_config_path} not exists')

            tips = "v2sub service select" if service_mode else "v2sub node select"
            print(f'please select a node first, execute: {tips}')

            sys.exit(1)

        return mode

    @staticmethod
    def generate_proxychains_conf() -> int:
        """
        Linux only
        """

        mode = App.ask_for_proxy_config_type()
        service_mode = (mode == 'service')

        socks_config = App.load_node_config(service_mode=service_mode, only_inbound_tag='socks')
        if not socks_config:
            logging.error(f'dont have socks inbound setting in {mode} config')
            sys.exit(1)

        server = socks_config['listen']
        port = socks_config['port']

        if server == '0.0.0.0':
            server = '127.0.0.1'

        if App.system != 'Linux' or not os.path.exists('/etc/proxychains.conf'):
            with open(App.proxychains_conf_path, 'w') as file:
                file.write(f'''strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 {server} {port}
''')
        else:
            regular_server = server.replace('.', '\\.')
            awk_script_path = os.path.join(App.app_dir, 'proxychains.conf.awk')
            with open(awk_script_path, 'w') as file:
                file.write(f'''#!/usr/bin/awk -f

BEGIN {{ section_exists = 0; been = 0; record = "socks5 {server} {port}"; }}

/^\\[ProxyList\\]$/,(!/^\\[ProxyList\\]$/ && (/^\\[.*\\]$/ || 0)) {{
    section_exists = 1

    if (match($0, /^\\s*socks[45]\\s+.*$/)) {{
        if (!match($0, /^\\s*socks[45]\\s+{regular_server}\\s+{port}/)) {{
            $0 = "#"$0
        }} else {{
            been = 1
        }}
    }}

    if (been == 0 && match($0, /^\\[.*\\]$/) && !match($0, /^\\[ProxyList\\]$/)) {{
        been = 1
        print record"\\n"
    }}
}}

{{ print $0 }}

END {{
    if (section_exists == 0) {{
        print "[ProxyList]"
        print record"\\n"
    }} else if (been == 0) {{
        print record"\\n"
    }}
}}
''')
            os.system(f'awk -f {awk_script_path} /etc/proxychains.conf > {App.proxychains_conf_path}')

    @staticmethod
    def enable_windows_proxy_setting(mode: str) -> int:
        service_mode = (mode == 'service')
        node_http_config = App.load_node_config(service_mode=service_mode, only_inbound_tag='http')

        if not node_http_config:
            logging.error(f'dont have http inbound setting in {mode} config')
            return 1

        http_listen = node_http_config["listen"]
        if http_listen == '0.0.0.0':
            http_listen = '127.0.0.1'

        proxy_server = f'{http_listen}:{node_http_config["port"]}'
        util.enable_ie_proxy_setting(proxy_server)

        os.system(f'echo {mode} > {os.path.join(App.app_dir, ".proxy_enabled")}')

        print(f'enable proxy: {proxy_server}')
        return 0

    @staticmethod
    def enable_mac_proxy_setting(mode: str) -> int:
        service_mode = (mode == 'service')
        node_http_config = App.load_node_config(service_mode=service_mode, only_inbound_tag='http')
        node_socks_config = App.load_node_config(service_mode=service_mode, only_inbound_tag='socks')

        if not node_http_config and not node_socks_config:
            logging.error(f'dont have http/socks inbound setting in {mode} config')
            return 1

        nis = util.get_mac_active_network_interfaces()
        if len(nis) == 0:
            print('not found valid network interfaces')
            return 0

        nic = Input.select_with_cancel('choose your network interface:', nis)
        if not nic:
            return 0

        cmds = []

        if node_http_config:
            http_listen = node_http_config["listen"]
            if http_listen == '0.0.0.0':
                http_listen = '127.0.0.1'

            arg = f'{http_listen} {node_http_config["port"]}'
            cmds.extend([
                f'networksetup -setwebproxy \"{nic}\" {arg}',
                f'networksetup -setsecurewebproxy \"{nic}\" {arg}',
                f'networksetup -setwebproxystate \"{nic}\" on',
                f'networksetup -setsecurewebproxystate \"{nic}\" on'
            ])

        if node_socks_config:
            socks_listen = node_socks_config["listen"]
            if socks_listen == '0.0.0.0':
                socks_listen = '127.0.0.1'

            arg = f'{socks_listen} {node_socks_config["port"]}'
            cmds.extend([
                f'networksetup -setsocksfirewallproxy \"{nic}\" {arg}',
                f'networksetup -setsocksfirewallproxystate \"{nic}\" on'
            ])

        util.run_cmds(cmds)

        os.system(f'echo {mode} > {os.path.join(App.app_dir, ".proxy_enabled")}')
        os.system(f'echo {nic} > {os.path.join(App.app_dir, ".mac_proxy_enabled_nic")}')

        print(f'enable proxy interface: {nic}')
        return 0

    @staticmethod
    def disable_mac_proxy_setting():
        nic_flag = os.path.join(App.app_dir, ".mac_proxy_enabled_nic")
        if not os.path.exists(nic_flag):
            return

        nic = util.read_line(nic_flag, '')
        if not nic:
            return

        util.run_cmds([
            f'networksetup -setwebproxystate \"{nic}\" off',
            f'networksetup -setsecurewebproxystate \"{nic}\" off',
            f'networksetup -setsocksfirewallproxystate \"{nic}\" off'
        ])

        os.remove(nic_flag)

    @staticmethod
    def check_proxy_need_disable(mode):
        flag = os.path.join(App.app_dir, ".proxy_enabled")
        if not os.path.exists(flag):
            return

        enabled_mode = util.read_line(flag)
        if enabled_mode != mode:
            return

        if App.system == 'Windows':
            util.disable_ie_proxy_setting()
        elif App.system == 'Darwin':
            App.disable_mac_proxy_setting()

        os.remove(flag)


@click.group(help='v2ray subscribe', cls=util.ClickGroup)
@click.version_option(version=v2sub_version)
def cli():
    App.init()


@cli.group('install', help='install tools', cls=util.ClickGroup)
@click.option('--proxy', default=None, help='proxy for request(format: server:port)')
def install_group(proxy: str):
    if proxy:
        util.config_request_proxy(proxy)

    os.makedirs(App.app_dir, exist_ok=True)


@install_group.command('v2ray', help=f'install v2ray{"(need root)" if platform.system() == "Linux" else ""}')
def install_v2ray():
    if util.find_bin('v2ray'):
        print('v2ray already installed')
        sys.exit(0)

    if App.system == 'Windows':
        asset_name = f'v2ray-windows-{"64" if util.is_64bit_os() else "32"}.zip'

        print(f'request {asset_name} browser_download_url...')
        asset = util.github_api_get_releases_latest_asset_url(
            'v2fly',
            'v2ray-core',
            asset_name
        )
        if not asset:
            logging.error(f'request {asset_name} failed')
            sys.exit(1)

        zip_file = os.path.join(App.app_dir, asset_name)
        v2ray_dest = os.path.join(App.app_dir, 'v2ray')

        try:
            print(f'download {asset["url"]} [{asset["size"]} Bytes]...')
            util.download(asset["url"], zip_file)
        except Exception as e:
            logging.error(f'download failed: {e}')
            sys.exit(1)

        try:
            print(f'unzip {asset_name} to {v2ray_dest}...')
            util.unzip(zip_file, v2ray_dest)
        except Exception as e:
            logging.error(f'unzip failed: {e}')
            sys.exit(1)
    elif App.system == 'Linux':
        if util.remote_bash_script(
            'https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh', True
        ) == 0:
            util.remote_bash_script(
                'https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-dat-release.sh', True
            )
    elif App.system == 'Darwin':
        os.system('brew install v2ray')
    else:
        logging.error(f'{App.system} system not supported')
        sys.exit(1)

    if util.find_bin('v2ray'):
        print('v2ray installed')
    else:
        logging.error('v2ray install failed')
        sys.exit(1)

    sys.exit(0)


@install_group.command('proxychains',
                       help=f'install proxychains{"(need root)" if platform.system() == "Linux" else ""}')
def install_proxychains():
    if util.find_bin('proxychains') or util.find_bin('proxychains4'):
        print('proxychains already installed')
        sys.exit(0)

    if App.system == 'Windows':
        print('request shunf4/proxychains-windows repo assets...')
        assets = util.github_api_get_releases_latest_assets(
            'shunf4',
            'proxychains-windows'
        )
        if len(assets) == 0:
            logging.error('request failed')
            sys.exit(1)

        proxychains_asset = None
        arch_name = "win32_x64" if util.is_64bit_os() else "win32_x86"

        for asset in assets:
            if asset.get('name', '').endswith(f'{arch_name}.zip'):
                proxychains_asset = asset
                break

        if not proxychains_asset:
            logging.error('request asset url failed')
            sys.exit(1)

        zip_file = os.path.join(App.app_dir, proxychains_asset['name'])
        proxychains_dest = os.path.join(App.app_dir, 'proxychains')

        try:
            print(f'download {proxychains_asset["browser_download_url"]} [{proxychains_asset["size"]} Bytes]...')
            util.download(proxychains_asset["browser_download_url"], zip_file)
        except Exception as e:
            logging.error(f'download failed: {e}')
            sys.exit(1)

        try:
            print(f'unzip {proxychains_asset["name"]} to {proxychains_dest}...')
            util.unzip(zip_file, proxychains_dest)
        except Exception as e:
            logging.error(f'unzip failed: {e}')
            sys.exit(1)

        proxychains_exe_path = os.path.join(proxychains_dest, 'proxychains.exe')
        if os.path.exists(proxychains_exe_path):
            os.remove(proxychains_exe_path)

        os.rename(
            os.path.join(proxychains_dest, f'proxychains_{arch_name}.exe'),
            os.path.join(proxychains_exe_path)
        )

        util.add_path_env(proxychains_dest)
    elif App.system == 'Linux':
        pm = util.find_pm()
        if not pm:
            logging.error('package manager unsupported, please install manually')
            sys.exit(1)
        if not util.install_package(pm, ['proxychains-ng', 'proxychains']):
            logging.error('install failed, please install manually')
            sys.exit(1)
    elif App.system == 'Darwin':
        os.system('brew install proxychains-ng')
    else:
        logging.error(f'{App.system} system not supported')
        sys.exit(1)

    if util.find_bin('proxychains') or util.find_bin('proxychains4'):
        print('proxychains installed')
        if App.system == 'Windows':
            print('please restart shell')
        elif App.system == 'Darwin':
            print('tips: check your SIP status(csrutil status)')
    else:
        logging.error('proxychains install failed')
        sys.exit(1)

    sys.exit(0)


@cli.command('init', help='generate base config')
def init_command():
    if os.path.exists(App.base_config_path):
        logging.error(f'{App.base_config_path} is already exists')
        sys.exit(1)

    try:
        os.makedirs(App.app_dir, exist_ok=True)
    except Exception as e:
        logging.error(f'make app dir failed: {e}')
        sys.exit(1)

    sys.exit(App.generate_config())


@cli.group('config', cls=util.ClickGroup)
def config_group():
    """
    modify config
    """
    pass


@config_group.command('edit')
@AppDecorator.base_config_exists()
def edit_command():
    """
    edit config in editor\n
    see https://www.v2ray.com/chapter_02/01_overview.html
    """

    config_list = {
        os.path.basename(App.base_config_path): App.base_config_path
    }

    if os.path.exists(App.node_config_path):
        config_list[os.path.basename(App.node_config_path)] = App.node_config_path
    if os.path.exists(App.node_service_config_path):
        config_list[os.path.basename(App.node_service_config_path)] = App.node_service_config_path

    if len(config_list) == 1:
        sys.exit(util.call_editor(App.base_config_path))

    config_name = Input.select_with_cancel('choose your config', list(config_list.keys()))
    if not config_name:
        sys.exit(0)

    retval = util.call_editor(config_list[config_name])
    if config_name == 'base_config.json':
        sys.exit(retval)

    if App.system == 'Windows':
        print('restart your v2sub resource manually after modification')
        sys.exit(retval)

    if config_name == 'node_service_config.json':
        if App.system == 'Linux' and os.path.exists('/etc/systemd/system/v2sub.service.d/node_service_config.json'):
            os.system(f'sudo cp -f {config_list[config_name]} /etc/systemd/system/v2sub.service.d')
            os.system('sudo chmod 644 /etc/systemd/system/v2sub.service.d/node_service_config.json')
        if service.is_running(App.v2sub_service_name):
            service.stop_service(App.v2sub_service_name)
            time.sleep(0.5)
            service.start_service(App.v2sub_service_name)
            sys.exit(0)
    elif util.check_is_running(App.pid_path, 'v2ray'):
        App.stop_v2ray(True)
        time.sleep(0.5)
        sys.exit(App.run_v2ray())

    sys.exit(retval)


@config_group.command('lan', cls=util.ClickGroup)
def lan_group():
    """
    allow or disallow lan connection
    """
    pass


@lan_group.command('allow', help='allow lan')
@AppDecorator.base_config_exists()
def allow_lan_command():
    selected = App.ask_for_lan_allow_command_target(False)
    if not selected:
        sys.exit(1)

    for inbound in selected['config'].get('inbounds', []):
        inbound['listen'] = '0.0.0.0'
        if selected['name'] == 'base config':
            inbound['service_mode_listen'] = '0.0.0.0'

    try:
        App.reflush_config(selected)
        print(f'write to {selected["path"]}')
    except BaseException as e:
        logging.error(f'reflush config failed: {e}')
        sys.exit(1)

    App.show_add_allow_lan_firewall_rule_tips(selected)

    sys.exit(0)


@lan_group.command('disallow', help='disallow lan')
def disallow_lan_command():
    selected = App.ask_for_lan_allow_command_target(True)
    if not selected:
        sys.exit(1)

    for inbound in selected['config'].get('inbounds', []):
        inbound['listen'] = '127.0.0.1'
        if selected['name'] == 'base config':
            inbound['service_mode_listen'] = '127.0.0.1'
    try:
        App.reflush_config(selected)
        print(f'write to {selected["path"]}')
    except BaseException as e:
        logging.error(f'reflush config failed: {e}')
        sys.exit(1)

    sys.exit(0)


if platform.system() == 'Windows' or platform.system() == 'Darwin':
    PROXY_GROUP_OWNER = "IE" if platform.system() == "Windows" else "network interface"

    @config_group.group('proxy', help=f'configure {PROXY_GROUP_OWNER} proxy setting', cls=util.ClickGroup)
    def proxy_group():
        """
        proxy command group, only for Windows and Mac
        """
        pass

    @proxy_group.command('enable', help=f'enabled {PROXY_GROUP_OWNER} proxy setting')
    def enable_proxy_command():
        mode = App.ask_for_proxy_config_type()

        if App.system == 'Windows':
            sys.exit(App.enable_windows_proxy_setting(mode))
        elif App.system == 'Darwin':
            sys.exit(App.enable_mac_proxy_setting(mode))

        sys.exit(0)

    @proxy_group.command('disable', help=f'disable {PROXY_GROUP_OWNER} proxy setting')
    def disable_proxy_command():
        if App.system == 'Windows':
            util.disable_ie_proxy_setting()
        elif App.system == 'Darwin':
            App.disable_mac_proxy_setting()

        flag = os.path.join(App.app_dir, ".proxy_enabled")
        if os.path.exists(flag):
            os.remove(flag)

        sys.exit(0)


@cli.group('subscribe', help='subscribe manage', cls=util.ClickGroup)
@click.option('--proxy', default=None, help='proxy for request(format: server:port)')
def subscribe_group(proxy: str):
    """
    subscribe command group
    """

    if proxy:
        util.config_request_proxy(proxy)


@subscribe_group.command('parse', help='parse subscribe list or independent node')
@click.argument('url', type=click.STRING)
def parse_url(url: str):
    sys.exit(App.parse_url(url))


@subscribe_group.command('add', help='add subscribe')
@click.argument('url', type=click.STRING)
@AppDecorator.base_config_exists()
@AppDecorator.open_subscribe_config()
def add_subscribe_command(url):
    sys.exit(App.subscribe(url))


@subscribe_group.command('update', help='update subscribe')
@click.option('--all', is_flag=True, help='update all subscribes')
@AppDecorator.base_config_exists()
@AppDecorator.open_subscribe_config()
def update_subscribe_command(all):
    sys.exit(App.update_subscribe(all))


@subscribe_group.command('delete', help='delete subscribe')
@click.option('--all', is_flag=True, help='delete all subscribes')
@AppDecorator.base_config_exists()
@AppDecorator.open_subscribe_config()
def delete_subscribe_command(all):
    sys.exit(App.delete_subscribe(all))


@cli.group('node', help='node manage', cls=util.ClickGroup)
def node_group():
    """
    node command group
    """
    pass


@node_group.command('select', help='select node')
@AppDecorator.base_config_exists()
@AppDecorator.open_subscribe_config()
def select_node_command():
    if not util.check_is_running(App.pid_path, 'v2ray'):
        sys.exit(App.select_node(False))

    if App.select_node(False) == 0:
        App.stop_v2ray(True)
        time.sleep(0.5)
        sys.exit(App.run_v2ray())

    sys.exit(1)


@node_group.command('start', help='run v2ray')
def start_node_command():
    if util.check_is_running(App.pid_path, 'v2ray'):
        print('v2ray is already running, please stop it first')
        sys.exit(1)

    if util.find_bin('v2ray') == '':
        print('please install v2ray and add the path to the PATH environment first')
        print('see https://www.v2fly.org/guide/install.html or try to execute: v2sub install v2ray')
        sys.exit(1)

    if not os.path.exists(App.node_config_path):
        logging.error('please select a node first: v2sub node select')
        sys.exit(1)

    sys.exit(App.run_v2ray())


@node_group.command('stop', help='stop v2ray')
def stop_node_command():
    if not util.check_is_running(App.pid_path, 'v2ray'):
        print('v2ray is not running')
        sys.exit(1)

    sys.exit(App.stop_v2ray())


@node_group.command('status', help='check v2ray running status')
@AppDecorator.base_config_exists()
@AppDecorator.open_subscribe_config()
def node_status_command():
    sys.exit(App.v2ray_status())


@cli.group('service', help='service manage', cls=util.ClickGroup)
def service_group():
    """
    service command group
    """

    if App.system == 'Linux' and os.system('command -v systemctl > /dev/null') != 0:
        logging.error('only support systemd')
        sys.exit(1)


@service_group.command('select', help='select node')
@AppDecorator.base_config_exists()
@AppDecorator.open_subscribe_config()
def select_service_mode_node_command():
    if not service.is_installed(App.v2sub_service_name):
        sys.exit(App.select_node(True))

    is_running = service.is_running(App.v2sub_service_name)

    if App.select_node(True) != 0:
        sys.exit(1)

    if App.system == 'Windows':
        if is_running:
            util.runas_admin([
                'sc.exe stop v2sub',
                'timeout /t 2',
                'sc.exe start v2sub'
            ])
        sys.exit(0)

    if is_running:
        service.stop_service(App.v2sub_service_name)

    if App.system == 'Linux':
        os.system(f'sudo cp -f {App.node_service_config_path} /etc/systemd/system/v2sub.service.d')
        os.system('sudo chmod 644 /etc/systemd/system/v2sub.service.d/node_service_config.json')
    elif App.system == 'Darwin':
        service_conf_dir = os.path.join(App.home_dir, f"Library/LaunchAgents/{App.v2sub_service_name}.d")
        os.system(f'cp -f {App.node_service_config_path} {service_conf_dir}')

    if is_running:
        time.sleep(0.5)
        service.start_service(App.v2sub_service_name)

    sys.exit(0)


@service_group.command('install', help='install v2sub service')
def service_install_command():
    if service.is_installed(App.v2sub_service_name):
        print('v2sub service already install')
        sys.exit(1)

    if util.find_bin('v2ray') == '':
        print('please install v2ray and add the path to the PATH environment first')
        print('see https://www.v2fly.org/guide/install.html or try to execute: v2sub install v2ray')
        sys.exit(1)

    if not os.path.exists(App.node_service_config_path):
        logging.error(f'{App.node_service_config_path} not exists')
        print('please select a node first, execute: v2sub service select')
        sys.exit(1)

    if App.system == 'Windows':
        retval = App.install_windows_service()
    elif App.system == 'Darwin':
        retval = App.install_mac_service()
    else:
        retval = App.install_linux_service()

    if retval == 0:
        App.show_temporarily_effect_tips(True)

    sys.exit(retval)


@service_group.command('uninstall', help='uninstall v2sub service')
@AppDecorator.v2sub_service_installed()
def service_uninstall_command():
    if App.system == 'Windows':
        App.check_proxy_need_disable('service')
        util.runas_admin([
            'sc.exe stop v2sub',
            'sc.exe delete v2sub'
        ])
    elif App.system == 'Darwin':
        service_installed_path = os.path.join(App.home_dir, "Library/LaunchAgents")
        service_plist_path = f'{service_installed_path}/{App.v2sub_service_name}.plist'
        os.system(f'launchctl stop {App.v2sub_service_name}')
        os.system(f'launchctl unload {service_plist_path}')
        os.system(f'rm -rf {service_plist_path}')
        os.system(f'rm -rf {service_installed_path}/{App.v2sub_service_name}.d')
    else:
        App.check_proxy_need_disable('service')
        os.system('sudo systemctl stop v2sub')
        os.system('sudo systemctl disable v2sub')
        os.system('sudo systemctl daemon-reload')
        os.system('sudo rm -rf /etc/systemd/system/v2sub.service.d')
        os.system('sudo rm -rf /var/log/v2sub')
        os.system('sudo rm -f /etc/systemd/system/v2sub.service')

    sys.exit(0)


@service_group.command('status', help='v2sub service status')
@AppDecorator.v2sub_service_installed()
def service_status_command():
    service.service_status(App.v2sub_service_name)
    sys.exit(0)


@service_group.command('start', help='start v2sub service')
@AppDecorator.v2sub_service_installed()
def start_service_command():
    service.start_service(App.v2sub_service_name)
    App.show_temporarily_effect_tips(True)
    sys.exit(0)


@service_group.command('stop', help='stop v2sub service')
@AppDecorator.v2sub_service_installed()
def stop_service_command():
    App.check_proxy_need_disable('service')
    service.stop_service(App.v2sub_service_name)
    sys.exit(0)


@cli.group('proxychains', cls=util.ClickGroup)
def proxychains_group():
    """
    proxychains helper

    tips: if proxychains doesn't work on MAC, you need to run the following command
in Recovery mode to disable SIP(System Integrity Protection)\n
    \t\t\t csrutil disable\n

    @see https://github.com/rofl0r/proxychains-ng/issues/78
    """

    if util.find_bin('proxychains') == '' and util.find_bin('proxychains4') == '':
        print('please install proxychains and add the path to the PATH environment first')
        print('try to execute: v2sub install proxychains ')
        sys.exit(1)


if platform.system() == 'Linux':
    """
    only for linux
    """

    @proxychains_group.command('apply', help='apply socks5 config to proxychains (need root)')
    def apply_proxychains_command():
        try:
            App.generate_proxychains_conf()
            os.system(f'sudo cp -f {App.proxychains_conf_path} /etc/proxychains.conf')
        except SystemExit:
            raise
        except BaseException as e:
            logging.error(f'apply proxychains config failed: {e}')
            sys.exit(1)

        sys.exit(0)


@proxychains_group.command('alias', help='add alias for proxychains')
@click.option('--force', is_flag=True, help='force substitution')
@click.option('--delete', default=None, help='delete alias')
def add_proxychains_alias_command(force, delete):
    proxychains_bin = util.find_bin('proxychains') or util.find_bin('proxychains4')

    if delete:
        delete_conf = os.path.join(App.app_dir, f'alias_{delete}_proxychains.conf')

        if os.path.exists(delete_conf):
            os.remove(delete_conf)

        if App.system == 'Windows':
            delete_bat = os.path.join(os.path.dirname(proxychains_bin), f'{delete}.bat')
            if os.path.exists(delete_bat):
                os.remove(delete_bat)
        else:
            try:
                profile = util.shell_profile_path()
            except BaseException as e:
                logging.error(f'find shell profile failed: {e}')
                sys.exit(1)
            if os.path.exists(profile):
                os.system(f'sed \'/^alias vproxy.*/ d\' -i {profile}')

        sys.exit(0)

    try:
        App.generate_proxychains_conf()
        alias_name = Input.ask_text('what\'s your alias name:')
        if not alias_name:
            sys.exit(0)

        alias_name = alias_name.lstrip().rstrip()
        alias_conf = os.path.join(App.app_dir, f'alias_{alias_name}_proxychains.conf')

        if not force and os.path.exists(alias_conf):
            logging.error(f'{alias_conf} already exists')
            sys.exit(1)

        shutil.copy(App.proxychains_conf_path, alias_conf)
        print(f'generate alias proxychains config in {alias_conf}')

        alias_cmd = f'{proxychains_bin} -q -f {alias_conf}'
        print(f'{alias_name} alias: {alias_cmd}')

        if App.system == 'Windows':
            alias_bat = os.path.join(os.path.dirname(proxychains_bin), f'{alias_name}.bat')
            os.system(f'echo @echo off > {alias_bat}')
            os.system(f'echo {alias_cmd} %* >> {alias_bat}')
            print('please restart shell')
        else:
            alias_item = f"alias {alias_name}='{alias_cmd}'"
            profile = util.shell_profile_path()
            if not os.path.exists(profile) or os.system(f'cat {profile} | grep \"{alias_item}\"') != 0:
                os.system(f'echo \"{alias_item}\" >> {profile}')
            print(f'please execute source {profile} to take effect')
    except SystemExit:
        raise
    except BaseException as e:
        logging.error(f'generate proxychains config failed: {e}')
        sys.exit(1)

    if App.system == 'Darwin':
        print('tips: check your SIP status(csrutil status)')

    sys.exit(0)


def main():
    cli(prog_name='v2sub')


if __name__ == '__main__':
    main()