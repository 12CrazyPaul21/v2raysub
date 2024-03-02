import os
import platform

from . import util


V2SUB_SERVICE_SCRIPT = '''import os
import sys
import time
import subprocess

import win32serviceutil
import win32service
import servicemanager


class V2SubService(win32serviceutil.ServiceFramework):
    _svc_name_ = 'v2sub'
    _svc_display_name_ = 'V2Sub'
    _svc_description_ = "v2ray subscribe service"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)

        self._is_running = False
        self._v2ray_bin = ''
        self._config_path = ''

    def setup(self):
        if len(sys.argv) != 3:
            servicemanager.LogErrorMsg(
                'invalid args, v2ray and config path is needed'
            )
            return False

        self._v2ray_bin = sys.argv[1]
        self._config_path = sys.argv[2]

        if not os.path.exists(self._v2ray_bin):
            servicemanager.LogErrorMsg(f'{self._v2ray_bin} not exists')
            return False

        if not os.path.exists(self._config_path):
            servicemanager.LogErrorMsg(f'{self._config_path} not exists')
            return False

        servicemanager.LogInfoMsg(
            f'v2ray path: {self._v2ray_bin}\\nconfig path: {self._config_path}'
        )

        return True

    def failed(self, msg):
        self._is_running = False
        servicemanager.LogErrorMsg(msg)
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)

    def main(self):
        self._is_running = True

        process = subprocess.Popen(
            [self._v2ray_bin, 'run', '-c', self._config_path]
        )
        if process.poll() is not None:
            self.failed(
                f'v2ray start failed: {process.returncode}'
            )
            return

        while self._is_running and process.poll() is None:
            time.sleep(1)

        if self._is_running:
            self.failed(
                f'v2ray failed: {process.returncode}'
            )
            return

        self._is_running = False
        process.terminate()
        process.wait()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._is_running = False

    def SvcDoRun(self):
        self.ReportServiceStatus(win32service.SERVICE_START_PENDING)
        if self.setup():
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            self.main()
        else:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] in ['install', 'remove']:
        sys.exit(win32serviceutil.HandleCommandLine(V2SubService))
    else:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(V2SubService)
        servicemanager.StartServiceCtrlDispatcher()
'''


def compile_windows_v2sub_service(service_folder):
    if not util.find_bin('pyinstaller'):
        raise RuntimeError('please install pyinstaller and add the path to the PATH environment first')

    os.makedirs(service_folder, exist_ok=True)
    script_path = os.path.join(service_folder, 'v2sub_service.py')
    with open(script_path, 'w') as file:
        file.write(V2SUB_SERVICE_SCRIPT)

    tmpdir = os.path.join(service_folder, 'tmp')
    workdir = os.path.join(service_folder, 'build')
    cmd = f'pyinstaller --runtime-tmpdir=\"{tmpdir}\" --workpath=\"{workdir}\" --specpath=\"{service_folder}\" '
    cmd += f'--distpath=\"{service_folder}\" --onefile --hidden-import win32timezone \"{script_path}\"'

    print(cmd)
    retval = os.system(cmd)

    if retval != 0:
        raise RuntimeError(f'{retval}')


def generate_mac_v2sub_service(service_path, service_conf_dir):
    # https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html
    with open(service_path, 'w') as file:
        v2ray_bin = util.find_bin('v2ray')
        file.write(f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.v2sub.service</string>
    <key>ProgramArguments</key>
    <array>
        <string>{v2ray_bin}</string>
        <string>run</string>
        <string>-c</string>
        <string>{service_conf_dir}/node_service_config.json</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
''')


def generate_linux_v2sub_service(service_path):
    with open(service_path, 'w') as file:
        # see https://www.v2fly.org/
        v2ray_bin = util.find_bin('v2ray')
        file.write(f'''[Unit]
Description=V2RaySub Service
Documentation=https://www.v2fly.org/
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart={v2ray_bin} run -config /etc/systemd/system/v2sub.service.d/node_service_config.json
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target''')


def is_installed(service_name) -> bool:
    if platform.system() == 'Windows':
        return os.system(f'sc.exe query {service_name} > NUL') == 0
    elif platform.system() == 'Darwin':
        return os.system(f'launchctl list | grep {service_name} > /dev/null') == 0
    else:
        return os.path.exists(f'/etc/systemd/system/{service_name}.service')


def is_running(service_name) -> bool:
    if platform.system() == 'Windows':
        return os.system(f'sc.exe query {service_name} | findstr /i \"RUNNING\" > nul') == 0
    elif platform.system() == 'Darwin':
        return os.system(
            f'launchctl list | awk \'$3=="{service_name}" {{ print $1 }}\' | grep -E "^[0-9].*$" > /dev/null'
        ) == 0
    else:
        return os.system(f'systemctl is-active {service_name} > /dev/null') == 0


def start_service(service_name):
    if platform.system() == 'Windows':
        util.runas_admin(f'sc.exe start {service_name}')
    elif platform.system() == 'Darwin':
        os.system(f'launchctl start {service_name}')
    else:
        os.system(f'sudo systemctl start {service_name}')


def stop_service(service_name):
    if platform.system() == 'Windows':
        util.runas_admin(f'sc.exe stop {service_name}')
    elif platform.system() == 'Darwin':
        os.system(f'launchctl stop {service_name}')
    else:
        os.system(f'sudo systemctl stop {service_name}')


def service_status(service_name):
    if platform.system() == 'Windows':
        os.system(f'sc.exe query {service_name}')
    elif platform.system() == 'Darwin':
        os.system(f'launchctl print gui/$(id -u)/{service_name}')
    else:
        os.system(f'systemctl status {service_name}')
