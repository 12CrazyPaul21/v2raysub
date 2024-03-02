import os
import sys
import re
import base64
import questionary
import functools
import logging
import click
import collections
import copy
import subprocess
import psutil
import platform
import ctypes
import requests
import tqdm
import zipfile

from typing import Sequence, Union, List
from questionary import Validator, ValidationError
from urllib.parse import parse_qs


REQUEST_PROXIES = {}


class ClickGroup(click.Group):
    def __init__(self, name=None, commands=None, **attrs):
        super(ClickGroup, self).__init__(name, commands, **attrs)
        self.commands = commands or collections.OrderedDict()

    def list_commands(self, ctx):
        return self.commands


class PortValidator(Validator):
    def validate(self, document) -> bool:
        error = ValidationError(
            cursor_position=len(document.text),
            message='invalid port number'
        )

        try:
            port = int(document.text)
            if port < 1 or port > 65535:
                raise error
        except ValueError:
            raise error

        return True


class Input:
    @staticmethod
    def select(message: str, choices: Sequence[str], default: str = None) -> str:
        return questionary.select(
            message=message,
            choices=choices,
            default=default,
            use_jk_keys=True,
            show_selected=False,
            qmark='',
            instruction=' ',
            style=questionary.Style([('selected', 'noreverse')])
        ).ask()

    @staticmethod
    def select_with_cancel(message: str, choices: Sequence[str], default: str = None):
        choices = copy.deepcopy(choices)
        choices.append(questionary.Choice('<Cancel>', value='@<__inner_input_cancel__>@'))

        selected = questionary.select(
            message=message,
            choices=choices,
            default=default,
            use_jk_keys=True,
            show_selected=False,
            qmark='',
            instruction=' ',
            style=questionary.Style([('selected', 'noreverse')])
        ).ask()

        if selected == '@<__inner_input_cancel__>@':
            return None

        return selected

    @staticmethod
    def ask_port(message: str, default: str = None) -> str:
        return questionary.text(message, default=default, qmark='', validate=PortValidator()).ask()

    @staticmethod
    def ask_text(message: str) -> str:
        return questionary.text(message, qmark='', validate=lambda s: len(s) != 0).ask()


def request_get(url) -> requests.Response:
    global REQUEST_PROXIES
    return requests.get(url, timeout=5, proxies=REQUEST_PROXIES)


def config_request_proxy(proxy_server):
    global REQUEST_PROXIES

    REQUEST_PROXIES = {
        'http': proxy_server,
        'https': proxy_server
    }

    os.environ['http_proxy'] = f'http://{proxy_server}'
    os.environ['https_proxy'] = f'http://{proxy_server}'


def download(asset_url, asset_path, chunk_size=512):
    global REQUEST_PROXIES

    progress_bar = None

    try:
        with requests.get(asset_url, stream=True, proxies=REQUEST_PROXIES) as response:
            total_size = int(response.headers.get('Content-Length', 0))
            progress_bar = tqdm.tqdm(total=total_size, unit='B', unit_scale=True)
            with open(asset_path, 'wb') as file:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    file.write(chunk)
                    file.flush()
                    progress_bar.update(len(chunk))
            progress_bar.close()
    except Exception as e:
        if progress_bar:
            progress_bar.close()
        raise e


def github_api_get_releases_latest_assets(owner: str, repo: str):
    try:
        response = request_get(f'https://api.github.com/repos/{owner}/{repo}/releases/latest')
        if response.status_code != 200:
            raise ValueError(f'status code: {response.status_code}, response: {response.text}')
        assets = response.json().get('assets', [])
    except Exception as e:
        assets = []
        logging.error(f'request {owner}/{repo} assets failed: {e}')

    return assets


def github_api_get_releases_latest_asset_url(owner: str, repo: str, asset_name: str):
    assets = github_api_get_releases_latest_assets(owner, repo)
    if len(assets) == 0:
        return None

    asset = list(filter(lambda item: item.get('name', '') == asset_name, assets))[0:]
    if len(asset) == 0:
        return None

    return {
        'url': asset[0].get('browser_download_url', ''),
        'size': asset[0].get('size', 0)
    }


def unzip(zip_file, dest):
    os.makedirs(dest, exist_ok=True)

    with zipfile.ZipFile(zip_file, 'r') as zfile:
        zfile.extractall(dest)


def is_base64(text: str) -> bool:
    base64_pattern = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$'

    stext = text + '=' * ((4 - len(text) % 4) % 4)
    if re.match(base64_pattern, stext) is not None:
        return True

    stext = stext.replace('-', '+').replace('_', '/')
    return re.match(base64_pattern, stext) is not None


def decode_base64(text: str) -> str:
    return base64.b64decode(
        (text + '=' * ((4 - len(text) % 4) % 4)).replace('-', '+').replace('_', '/')
    ).decode('utf-8')


def parse_query_string(query: str) -> object:
    return {
        key: value[0] if len(value) == 1 else value for key, value in parse_qs(query).items()
    }


def is_64bit_os():
    return platform.architecture()[0] == '64bit'


def find_bin(bin_name) -> str:
    if platform.system() == 'Windows':
        _, ext = os.path.splitext(bin_name)
        if ext == '':
            bin_name = f'{bin_name}.exe'

    for path in os.environ["PATH"].split(os.pathsep):
        bin_path = os.path.join(path, bin_name)
        if os.path.exists(bin_path):
            return bin_path

    return ""


def find_pm():
    for pm in ['dnf', 'apt-get', 'yum']:
        if find_bin(pm):
            return pm
    return None


def install_package(pm, optional):
    for name in optional:
        if os.system(f'{pm} search {name} | grep {name} > /dev/null') == 0:
            if os.system(f'sudo {pm} install {name}') == 0:
                return True
    return False


def call_editor(file_path) -> int:
    result = 0

    try:
        if sys.platform == 'win32':
            subprocess.Popen(['notepad.exe', file_path])
        else:
            for editor in ['nano', 'vim', 'vi']:
                if find_bin(editor):
                    os.system(f'{editor} {file_path}')
                    break
    except Exception as e:
        result = 1
        logging.error(f'call_editor failed: {e}')

    return result


def get_program_name_with_pid(pid) -> str:
    name = ''

    try:
        process = psutil.Process(int(pid))
        if process.is_running():
            process_name = process.name()
            name = os.path.splitext(os.path.basename(process_name))[0]
    except psutil.NoSuchProcess:
        name = ''

    return name


def check_is_running(pid_path: str, program_name: str) -> bool:
    if not os.path.exists(pid_path):
        return False

    if os.path.getsize(pid_path) == 0:
        os.remove(pid_path)
        return False

    with open(pid_path, 'r') as file:
        pid = int(file.read().rstrip())

    if get_program_name_with_pid(pid).lower() != program_name.lower():
        os.remove(pid_path)
        return False

    return True


def run_cmds(cmds) -> int:
    for cmd in cmds:
        print(cmd)
        retval = os.system(cmd)
        if retval != 0:
            return retval
    return 0


def read_line(file_path, default='') -> str:
    if not os.path.exists(file_path):
        return ''

    content = default

    try:
        with open(file_path, 'r') as file:
            content = file.readline()
        if len(content) != 0:
            content = content.lstrip().rstrip()
    except Exception as e:
        content = default
        logging.debug(f'read file failed: {e}')

    return content


if platform.system() == 'Windows':
    def disable_ie_proxy_setting():
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            0,
            winreg.KEY_WRITE
        )
        winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)

    def enable_ie_proxy_setting(proxy_server):
        proxy_override = 'localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;'
        proxy_override += '172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;'
        proxy_override += '172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*'

        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            0,
            winreg.KEY_WRITE
        )
        winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, proxy_server)
        winreg.SetValueEx(key, 'ProxyOverride', 0, winreg.REG_SZ, proxy_override)
        winreg.CloseKey(key)

    def runas_admin(args: Union[str | List[str]]):
        if isinstance(args, list):
            args = ' && '.join(args)

        if ctypes.windll.shell32.IsUserAnAdmin():
            os.system(args)
        else:
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                'c:\\windows\\system32\\cmd.exe',
                ' '.join(['/C', args]),
                None,
                0
            )

    def add_path_env(path):
        import winreg
        import win32con
        import win32gui

        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment', 0, winreg.KEY_ALL_ACCESS)
        curr_path, _ = winreg.QueryValueEx(key, 'Path')
        if not curr_path.endswith(path) and f'{path};' not in curr_path:
            winreg.SetValueEx(key, 'Path', 0, winreg.REG_SZ, f'{curr_path};{path}')
        winreg.CloseKey(key)
        win32gui.SendMessageTimeout(
            win32con.HWND_BROADCAST,
            win32con.WM_SETTINGCHANGE,
            0, 'Environment',
            win32con.SMTO_ABORTIFHUNG, 1000
        )

        os.environ['PATH'] = f'{os.environ.get("PATH", "")};{path}'

    def is_in_powershell() -> bool:
        retval = False

        try:
            retval = psutil.Process(os.getppid()).name().lower().endswith('powershell.exe')
        except Exception as e:
            logging.debug(f'get parent process name failed: {e}')
            retval = False

        return retval

else:
    def remote_bash_script(script_url, need_root):
        global REQUEST_PROXIES

        proxy_server = None
        for _, v in REQUEST_PROXIES.items():
            proxy_server = v
            break

        curl_cmd = f'curl -L {script_url}'
        if proxy_server:
            curl_cmd += f' --proxy {proxy_server}'

        return os.system(f'{"sudo " if need_root else ""}bash -c \"$({curl_cmd})\"')

    def shell_profile_path():
        if 'SHELL' not in os.environ:
            raise SystemError('unknown shell type')

        for shell, profile in {
            '/sh': '~/.profile',
            '/bash': '~/.bashrc',
            '/zsh': '~/.zshrc',
            '/csh': '~/.cshrc',
            '/ksh': '~/.kshrc'
        }.items():
            if os.environ['SHELL'].endswith(shell):
                return profile

        raise SystemError('unknown shell type')

    def check_cmd_output(cmd):
        try:
            output = subprocess.check_output([
                os.environ['SHELL'],
                '-c',
                cmd
            ]).decode('utf-8').lstrip().rstrip()
        except Exception as e:
            output = ''
            logging.debug(f'check cmd output failed: {e}')

        return output

if platform.system() == 'Darwin':
    def get_mac_active_network_interfaces():
        try:
            output = subprocess.check_output([
                os.environ['SHELL'],
                '-c',
                "set -o pipefail && networksetup -listnetworkserviceorder | grep -v -e '(\\*)'"
                " -e '(Hardware Port:' -e '^\\$' | awk '{$1=\"\"; print $0}'"
            ])
            interfaces = [
                ni.lstrip().rstrip() for ni in filter(
                    lambda ni: len(ni) != 0, output.decode('utf-8').lstrip().rstrip().split('\n')
                )
            ]
        except subprocess.CalledProcessError as e:
            interfaces = []
            logging.error(f'call networksetup failed: {e}')
        except Exception as e:
            interfaces = []
            logging.error(f'get mac network interfaces failed: {e}')

        return interfaces


def file_exists(obj, var, tips=''):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            path = getattr(obj, var, '')
            if not os.path.exists(path):
                logging.error(f'{path} not exists')
                if len(tips) != 0:
                    print(tips)
                sys.exit(1)
            return func(*args, **kwargs)
        return wrapper
    return decorator


def file_not_exists(obj, var, tips=''):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            path = getattr(obj, var, '')
            if os.path.exists(path):
                logging.error(f'{path} is already exists')
                if len(tips) != 0:
                    print(tips)
                sys.exit(1)
            return func(*args, **kwargs)
        return wrapper
    return decorator