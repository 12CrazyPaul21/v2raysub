import os
import sys
import logging
import click
import platform
import shutil

from . import __version__ as v2sub_version
from . import util

from .protocol import parse as protocol_parse
from .util import Input
from .app import AppDecorator, AppPrompt, App


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
        install_v2ray_master = 'https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master'
        if util.remote_bash_script(f'{install_v2ray_master}/install-release.sh', True) == 0:
            util.remote_bash_script(f'{install_v2ray_master}/install-dat-release.sh', True)
    elif App.system == 'Darwin':
        os.system('brew install v2ray')
    else:
        logging.error(f'{App.system} system unsupported')
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

    sys.exit(App.generate_base_config())


@cli.group('config', cls=util.ClickGroup)
def config_group():
    """
    modify config
    """
    pass


@config_group.command('edit')
@util.make_decorator(AppDecorator.base_config_exists)
def edit_command():
    """
    edit config in editor\n
    see https://www.v2ray.com/chapter_02/01_overview.html
    """

    config = AppPrompt.select_config_file()
    if not config:
        sys.exit(1)

    retval = util.call_editor(config['path'])
    if config['name'] == 'base config':
        sys.exit(retval)

    if App.system == 'Windows':
        print('restart your v2sub resource manually after modification')
        sys.exit(retval)

    try:
        App.reflush_config(config)
    except SystemExit:
        raise
    except BaseException as e:
        logging.error(f'reflush config failed: {e}')
        sys.exit(1)

    sys.exit(0)


@config_group.command('lan', cls=util.ClickGroup)
def lan_group():
    """
    allow or disallow lan connection
    """
    pass


@lan_group.command('allow', help='allow lan')
@util.make_decorator(AppDecorator.base_config_exists)
def allow_lan_command():
    sys.exit(App.toogle_allow_lan(True))


@lan_group.command('disallow', help='disallow lan')
@util.make_decorator(AppDecorator.base_config_exists)
def disallow_lan_command():
    sys.exit(App.toogle_allow_lan(False))


if platform.system() == 'Windows' or platform.system() == 'Darwin':
    PROXY_GROUP_OWNER = "windows internet" if platform.system() == "Windows" else "network interface"

    @config_group.group('proxy', help=f'configure {PROXY_GROUP_OWNER} proxy setting', cls=util.ClickGroup)
    def proxy_group():
        """
        proxy command group, only for Windows and Mac
        """
        pass

    @proxy_group.command('enable', help=f'enabled {PROXY_GROUP_OWNER} proxy setting')
    def enable_proxy_command():
        sys.exit(App.enable_system_proxy_setting())

    @proxy_group.command('disable', help=f'disable {PROXY_GROUP_OWNER} proxy setting')
    def disable_proxy_command():
        sys.exit(App.disable_system_proxy_setting())


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
def parse_subscribe_command(url: str):
    result = protocol_parse(url)
    if result['success'] == 0:
        logging.error(f'parse failed: {result["reason"]}')
        sys.exit(1)

    if 'subscribe_list' in result:
        for item in result['subscribe_list']:
            print(item)
        sys.exit(0)

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

    sys.exit(0)


@subscribe_group.command('add', help='add subscribe')
@click.argument('url', type=click.STRING)
@util.make_decorator(AppDecorator.base_config_exists)
@util.make_decorator(AppDecorator.open_subscribe_config)
def add_subscribe_command(url):
    sys.exit(App.add_subscribe(url))


@subscribe_group.command('update', help='update subscribe')
@click.option('--all', is_flag=True, help='update all subscribes')
@util.make_decorator(AppDecorator.base_config_exists)
@util.make_decorator(AppDecorator.open_subscribe_config)
def update_subscribe_command(all):
    sys.exit(App.update_subscribe(all))


@subscribe_group.command('delete', help='delete subscribe')
@click.option('--all', is_flag=True, help='delete all subscribes')
@util.make_decorator(AppDecorator.base_config_exists)
@util.make_decorator(AppDecorator.open_subscribe_config)
def delete_subscribe_command(all):
    sys.exit(App.delete_subscribe(all))


@cli.group('node', help='node manage', cls=util.ClickGroup)
def node_group():
    """
    node command group
    """
    pass


@node_group.command('select', help='select node')
@util.make_decorator(AppDecorator.base_config_exists)
@util.make_decorator(AppDecorator.open_subscribe_config)
def select_node_command():
    if App.select_node(False) != 0:
        sys.exit(1)

    sys.exit(App.restart_server(False, False))


@node_group.command('start', help='run v2ray')
@util.make_decorator(AppDecorator.v2ray_bin_installed)
@util.make_decorator(AppDecorator.node_config_exists)
@util.make_decorator(AppDecorator.v2ray_running_state, False)
def start_node_command():
    sys.exit(App.start_server(False))


@node_group.command('stop', help='stop v2ray')
@util.make_decorator(AppDecorator.v2ray_running_state, True)
def stop_node_command():
    sys.exit(App.stop_server(False, False))


@node_group.command('restart', help='restart v2ray')
@util.make_decorator(AppDecorator.v2ray_bin_installed)
@util.make_decorator(AppDecorator.node_config_exists)
def restart_node_command():
    sys.exit(App.restart_server(False, True))


@node_group.command('status', help='check v2ray running status')
@util.make_decorator(AppDecorator.base_config_exists)
@util.make_decorator(AppDecorator.node_config_exists)
@util.make_decorator(AppDecorator.open_subscribe_config)
def node_status_command():
    sys.exit(App.server_status(False))


@cli.group('service', help='service manage', cls=util.ClickGroup)
def service_group():
    """
    service command group
    """

    if App.system == 'Linux' and os.system('command -v systemctl > /dev/null') != 0:
        logging.error('only support systemd')
        sys.exit(1)


@service_group.command('select', help='select node')
@util.make_decorator(AppDecorator.base_config_exists)
@util.make_decorator(AppDecorator.open_subscribe_config)
def select_service_node_command():
    if App.select_node(True) != 0:
        sys.exit(1)

    try:
        App.reflush_config({
            'name': 'service',
            'path': App.node_service_config_path
        })
    except SystemExit:
        raise
    except Exception as e:
        logging.error(f'reflush service config failed: {e}')
        sys.exit(1)

    sys.exit(0)


@service_group.command('install', help='install v2sub service')
@util.make_decorator(AppDecorator.v2sub_service_installed, False)
@util.make_decorator(AppDecorator.v2ray_bin_installed)
@util.make_decorator(AppDecorator.node_service_config_exists)
def install_service_command():
    sys.exit(App.install_v2sub_service())


@service_group.command('uninstall', help='uninstall v2sub service')
@util.make_decorator(AppDecorator.v2sub_service_installed)
def uninstall_service_command():
    sys.exit(App.uninstall_v2sub_service())


@service_group.command('start', help='start v2sub service')
@util.make_decorator(AppDecorator.v2sub_service_installed)
@util.make_decorator(AppDecorator.v2sub_running_state, False)
def start_service_command():
    sys.exit(App.start_server(True))


@service_group.command('stop', help='stop v2sub service')
@util.make_decorator(AppDecorator.v2sub_service_installed)
@util.make_decorator(AppDecorator.v2sub_running_state, True)
def stop_service_command():
    sys.exit(App.stop_server(True))


@service_group.command('restart', help='restart v2sub service')
@util.make_decorator(AppDecorator.v2sub_service_installed)
def restart_service_command():
    sys.exit(App.restart_server(True, True))


@service_group.command('status', help='v2sub service status')
@util.make_decorator(AppDecorator.v2sub_service_installed)
@util.make_decorator(AppDecorator.node_service_config_exists)
@util.make_decorator(AppDecorator.open_subscribe_config)
def service_status_command():
    sys.exit(App.server_status(True))


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

    @proxychains_group.command('apply', help='apply socks5 config to /etc/proxychains.conf (need root)')
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
def proxychains_alias_command(force, delete):
    proxychains_bin = util.find_bin('proxychains') or util.find_bin('proxychains4')

    if delete:
        delete_conf = os.path.join(App.app_dir, f'alias_{delete}_proxychains.conf')

        if os.path.exists(delete_conf):
            os.remove(delete_conf)

        if App.system == 'Windows':
            delete_bat = os.path.join(os.path.dirname(proxychains_bin), f'{delete}.bat')
            if os.path.exists(delete_bat):
                os.remove(delete_bat)
            print('please restart shell')
        else:
            try:
                profile = util.shell_profile_path()
            except BaseException as e:
                logging.error(f'find shell profile failed: {e}')
                sys.exit(1)

            if os.path.exists(profile):
                if App.system == 'Darwin':
                    os.system(f'sed -i \'\' \'/^alias {delete}=.*/ d\' {profile}')
                else:
                    os.system(f'sed \'/^alias {delete}=.*/ d\' -i {profile}')

            print(f'please execute source {profile} to take effect')

        sys.exit(0)

    try:
        App.generate_proxychains_conf()
        alias_name = Input.ask_text('what\'s your alias name:')
        if not alias_name:
            sys.exit(1)

        alias_name = alias_name.lstrip().rstrip()
        alias_conf = os.path.join(App.app_dir, f'alias_{alias_name}_proxychains.conf')

        if not force and os.path.exists(alias_conf):
            logging.error(f'{alias_conf} already exists')
            sys.exit(1)

        shutil.copy(App.proxychains_conf_path, alias_conf)
        print(f'generate alias proxychains config to {alias_conf}')

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
            if not os.path.exists(profile) or os.system(f'cat {profile} | grep -E \"^{alias_item}\"') != 0:
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