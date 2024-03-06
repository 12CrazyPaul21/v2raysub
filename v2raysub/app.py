import os
import sys
import logging
import platform
import json
import time

from . import protocol
from . import util
from . import config
from . import service

from .util import Input


class AppDecorator:
    @staticmethod
    def base_config_exists():
        if not os.path.exists(App.base_config_path):
            logging.error(f'{App.base_config_path} not exists')
            print('please execute command: v2sub init')
            sys.exit(1)

    @staticmethod
    def node_config_exists():
        if not os.path.exists(App.node_config_path):
            logging.error(f'{App.node_config_path} not exists')
            print('please select a node first: v2sub node select')
            sys.exit(1)

    @staticmethod
    def node_service_config_exists():
        if not os.path.exists(App.node_service_config_path):
            logging.error(f'{App.node_service_config_path} not exists')
            print('please select a node first: v2sub service select')
            sys.exit(1)

    @staticmethod
    def open_subscribe_config():
        try:
            App.subscribe_config.open(App.subscribe_list_path)
        except BaseException as e:
            logging.error(f'open {App.subscribe_list_path} failed: {e}')
            sys.exit(1)

    @staticmethod
    def v2ray_bin_installed():
        if util.find_bin('v2ray') == '':
            print('please install v2ray and add the path to the PATH environment first')
            print('see https://www.v2fly.org/guide/install.html or try to execute: v2sub install v2ray')
            sys.exit(1)

    @staticmethod
    def v2ray_running_state(is_running=True):
        state = util.check_is_running(App.pid_path, 'v2ray')

        if not state and is_running:
            print('v2ray is not running')
            sys.exit(1)

        if state and not is_running:
            print('v2ray is already running, please stop it first')
            sys.exit(1)

    @staticmethod
    def v2sub_service_installed(is_installed=True):
        flag = service.is_installed(App.v2sub_service_name)

        if not flag and is_installed:
            print('v2sub service is not installed')
            sys.exit(1)

        if flag and not is_installed:
            print('v2sub service already install')
            sys.exit(1)

    @staticmethod
    def v2sub_running_state(is_running=True):
        state = service.is_running(App.v2sub_service_name)

        if not state and is_running:
            print('v2sub service is not running')
            sys.exit(1)

        if state and not is_running:
            print('v2sub service is already running, please stop it first')
            sys.exit(1)


class AppPrompt:
    @staticmethod
    def select_subscribe_group_item(group_name):
        if not group_name:
            return None

        nodes = App.subscribe_config.group_node_names(group_name)
        if not nodes:
            return None

        return Input.select_with_cancel(f'choose {group_name} node: ', nodes)

    @staticmethod
    def select_subscribe_item(entire_group=True):
        anonymous_nodes = App.subscribe_config.anonymous_names()
        groups = App.subscribe_config.groups()

        if len(anonymous_nodes) == 0 and len(groups) == 0:
            return None, 1

        if len(anonymous_nodes) != 0 and len(groups) != 0:
            sub = Input.select_with_cancel('choose subscribe type: ', ['anonymous', 'groups'])
            if not sub:
                return None, 1
        elif len(anonymous_nodes) != 0:
            sub = 'anonymous'
        else:
            sub = 'groups'

        if sub == 'anonymous':
            sub = ''
            name = Input.select_with_cancel('choose anonymous node: ', anonymous_nodes)
        else:
            sub = Input.select_with_cancel('choose group list: ', groups)
            name = '' if entire_group else AppPrompt.select_subscribe_group_item(sub)

        if sub is None or name is None:
            return None, 1

        return {'group': sub, 'name': name}, 0

    @staticmethod
    def select_config_file():
        config_list = {
            'base config': App.base_config_path
        }

        if os.path.exists(App.node_config_path):
            config_list['normal node'] = App.node_config_path
        if os.path.exists(App.node_service_config_path):
            config_list['service'] = App.node_service_config_path

        if len(config_list) == 1:
            return {
                'name': 'base config',
                'path': App.base_config_path
            }

        config_name = Input.select_with_cancel('choose your config', list(config_list.keys()))
        if not config_name:
            return None

        return {
            'name': config_name,
            'path': config_list[config_name]
        }

    @staticmethod
    def select_proxy_config_type() -> str:
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
    def select_lan_allow_target(allowed=False):
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
        if len(v2ray_bin) == 0:
            v2ray_bin = 'v2ray'
            if App.system == 'Windows':
                v2ray_bin += '.exe'

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
            if os.path.exists(v2ray_bin) and os.system(f'file {v2ray_bin} | grep "shell script"') == 0:
                real_bin = util.check_cmd_output('cat /usr/local/bin/v2ray | sed -rn \'s/.*exec \"([^\"]*)\".*/\\1/p\'')
                if real_bin:
                    v2ray_bin = real_bin
            print(f'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add {v2ray_bin}')
            print(f'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp {v2ray_bin}')
            print('sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off')
            print('sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on')

    @staticmethod
    def show_subscribe_node_info(group, name, node_info):
        print(f'  node name: {name}')
        if group:
            print(f'  subscribe group name: {group}')
            print(f'  subscribe group url: {App.subscribe_config.get_group_url(group)}')
        print(f'  node info: {node_info}')


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
    def generate_base_config() -> int:
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
        if 'config' in node_config:
            with open(node_config['path'], 'w', encoding='utf-8') as file:
                file.write(json.dumps(node_config['config'], indent=2, ensure_ascii=False))

        if node_config['name'] == 'normal node':
            App.restart_server(False, False)
        elif node_config['name'] == 'service':
            if service.is_installed(App.v2sub_service_name):
                if App.system == 'Linux':
                    os.system(f'sudo cp -f {node_config["path"]} /etc/systemd/system/v2sub.service.d')
                    os.system('sudo chmod 644 /etc/systemd/system/v2sub.service.d/node_service_config.json')
                elif App.system == 'Darwin':
                    service_conf_dir = os.path.join(App.home_dir, f"Library/LaunchAgents/{App.v2sub_service_name}.d")
                    os.system(f'cp -f {node_config["path"]} {service_conf_dir}')
                App.restart_server(True, False)

    @staticmethod
    def add_subscribe(url: str) -> int:
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
            logging.error(f'add subscribe failed: {e}')
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
        if App.subscribe_config.is_empty():
            print('subscribe list is empty')
            return 1

        if is_delete_all:
            App.subscribe_config.clean()
            return 0

        result, err = AppPrompt.select_subscribe_item(entire_group=True)
        if err != 0:
            return err

        try:
            if result['group'] == '':
                App.subscribe_config.delete_anonymous_node(result['name'])
            else:
                App.subscribe_config.delete_group(result['group'])
        except BaseException as e:
            logging.error(f'delete subscribe failed: {e}')
            sys.exit(1)

        return 0

    @staticmethod
    def select_node(service_mode=False) -> int:
        curr_selected = App.subscribe_config.selected(service_mode)
        if curr_selected:
            print('current select node:')
            AppPrompt.show_subscribe_node_info(
                curr_selected['group_name'],
                curr_selected['name'],
                curr_selected["node"]
            )

        if App.subscribe_config.is_empty():
            print('subscribe list is empty')
            return 1

        result, err = AppPrompt.select_subscribe_item(entire_group=False)
        if err != 0:
            return err

        try:
            if service_mode:
                os.makedirs(App.service_dir, exist_ok=True)
                config_path = App.node_service_config_path
            else:
                config_path = App.node_config_path

            node = App.subscribe_config.select(result['group'], result['name'], service_mode)
            config.generate_node_config(
                config_path,
                App.base_config_path,
                protocol.generate_v2ray_outbound(node),
                service_mode
            )
        except BaseException as e:
            logging.error(f'select node failed: {e}')
            sys.exit(1)

        return 0

    @staticmethod
    def start_server(service_mode=False) -> int:
        try:
            if service_mode:
                service.start_service(App.v2sub_service_name)
                time.sleep(0.5)
                if not service.is_running(App.v2sub_service_name):
                    sys.exit(1)
                print(f'{App.v2sub_service_name} service run success')
            else:
                util.runas_daemon(
                    [util.find_bin('v2ray'), 'run', '-c', App.node_config_path],
                    App.pid_path
                )
                pid = util.read_line(App.pid_path)
                print(f'v2ray run success, pid: {pid}')
        except SystemExit:
            raise
        except BaseException as e:
            logging.error(f'run {App.v2sub_service_name if service_mode else "v2ray"} failed: {e}')
            sys.exit(1)

        AppPrompt.show_temporarily_effect_tips(service_mode)
        return 0

    @staticmethod
    def stop_server(service_mode=False, restart_mode=False) -> int:
        if service_mode:
            if service.is_running(App.v2sub_service_name):
                service.stop_service(App.v2sub_service_name)
        else:
            if util.check_is_running(App.pid_path, 'v2ray'):
                util.kill_daemon(App.pid_path)

        if not restart_mode and App.system in ['Windows', 'Darwin']:
            App.check_proxy_need_disable('service' if service_mode else 'normal node')

        return 0

    @staticmethod
    def restart_server(service_mode=False, forced=False) -> int:
        if not service_mode:
            proc_status = util.check_is_running(App.pid_path, 'v2ray')

            if proc_status:
                App.stop_server(False, True)
                time.sleep(0.5)

            if forced or proc_status:
                return App.start_server(False)

            return 0

        service_status = service.is_running(App.v2sub_service_name)
        if forced or service_status:
            if App.system == 'Windows':
                cmds = []

                if service_status:
                    cmds.append('sc.exe stop v2sub')
                    cmds.append('timeout /t 2')

                cmds.append('sc.exe start v2sub')

                util.runas_admin(cmds)
                AppPrompt.show_temporarily_effect_tips(service_mode)
            else:
                if service_status:
                    App.stop_server(True, True)
                    time.sleep(0.5)
                return App.start_server(True)

        return 0

    @staticmethod
    def server_status(service_mode=False) -> int:
        if service_mode:
            if not service.is_running(App.v2sub_service_name):
                print('v2sub service status : stopped')
                return 1
            else:
                service.service_status(App.v2sub_service_name)
                print('v2sub service status: running')
        else:
            if not util.check_is_running(App.pid_path, 'v2ray'):
                print('v2ray status: stopped')
                return 1
            else:
                print('v2ray status: running')

        node_config = App.load_node_config(service_mode)
        for inbound in node_config.get('inbounds', []):
            if 'tag' in inbound and 'listen' in inbound and 'port' in inbound:
                print(f'{inbound["tag"]} proxy: {inbound["listen"]}:{inbound["port"]}')

        curr_selected = App.subscribe_config.selected(service_mode)
        if curr_selected:
            print('current select node:')
            AppPrompt.show_subscribe_node_info(
                curr_selected['group_name'],
                curr_selected['name'],
                curr_selected["node"]
            )

        return 0

    @staticmethod
    def _install_windows_service() -> int:
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
    def _install_mac_service() -> int:
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
    def _install_linux_service() -> int:
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
    def install_v2sub_service() -> int:
        if App.system == 'Windows':
            retval = App._install_windows_service()
        elif App.system == 'Darwin':
            retval = App._install_mac_service()
        else:
            retval = App._install_linux_service()

        if retval == 0:
            AppPrompt.show_temporarily_effect_tips(True)

        return retval

    @staticmethod
    def uninstall_v2sub_service() -> int:
        if App.system == 'Windows':
            App.check_proxy_need_disable('service')
            util.runas_admin([
                'sc.exe stop v2sub',
                'sc.exe delete v2sub'
            ])
        elif App.system == 'Darwin':
            App.check_proxy_need_disable('service')
            service_installed_path = os.path.join(App.home_dir, "Library/LaunchAgents")
            service_plist_path = f'{service_installed_path}/{App.v2sub_service_name}.plist'
            os.system(f'launchctl stop {App.v2sub_service_name}')
            os.system(f'launchctl unload {service_plist_path}')
            os.system(f'rm -rf {service_plist_path}')
            os.system(f'rm -rf {service_installed_path}/{App.v2sub_service_name}.d')
        else:
            os.system('sudo systemctl stop v2sub')
            os.system('sudo systemctl disable v2sub')
            os.system('sudo systemctl daemon-reload')
            os.system('sudo rm -rf /etc/systemd/system/v2sub.service.d')
            os.system('sudo rm -rf /var/log/v2sub')
            os.system('sudo rm -f /etc/systemd/system/v2sub.service')

        return 0

    @staticmethod
    def toogle_allow_lan(allowed: bool) -> int:
        selected = AppPrompt.select_lan_allow_target(not allowed)
        if not selected:
            return 1

        listen = '0.0.0.0' if allowed else '127.0.0.1'
        for inbound in selected['config'].get('inbounds', []):
            inbound['listen'] = listen
            if selected['name'] == 'base config':
                inbound['service_mode_listen'] = listen

        try:
            App.reflush_config(selected)
            print(f'write to {selected["path"]}')
        except SystemExit:
            raise
        except BaseException as e:
            logging.error(f'reflush config failed: {e}')
            sys.exit(1)

        if allowed:
            AppPrompt.show_add_allow_lan_firewall_rule_tips(selected)

        return 0

    @staticmethod
    def _enable_windows_proxy_setting(mode: str) -> int:
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
    def _enable_mac_proxy_setting(mode: str) -> int:
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
    def _disable_mac_proxy_setting():
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
    def enable_system_proxy_setting() -> int:
        mode = AppPrompt.select_proxy_config_type()

        if App.system == 'Windows':
            return App._enable_windows_proxy_setting(mode)
        elif App.system == 'Darwin':
            return App._enable_mac_proxy_setting(mode)

        return 0

    @staticmethod
    def disable_system_proxy_setting() -> int:
        if App.system == 'Windows':
            util.disable_ie_proxy_setting()
        elif App.system == 'Darwin':
            App._disable_mac_proxy_setting()

        flag = os.path.join(App.app_dir, ".proxy_enabled")
        if os.path.exists(flag):
            os.remove(flag)

        return 0

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
            App._disable_mac_proxy_setting()

        os.remove(flag)

    @staticmethod
    def generate_proxychains_conf() -> int:
        mode = AppPrompt.select_proxy_config_type()
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
