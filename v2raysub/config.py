import json
import os
import logging
import copy
import platform

from . import protocol


class SubscribeConfig:
    def __init__(self):
        self._path = ''
        self._obj = {}
        self._is_open = False
        self._is_dirty = False

    def __del__(self):
        if self._is_open:
            try:
                self.close()
            except Exception as e:
                logging.error(f'close SubscribeConfig failed : {e}')

    def is_open(self) -> bool:
        return self._is_open

    def open(self, path):
        if self._is_open:
            return

        self._path = path

        if not os.path.exists(self._path):
            self._obj = {'anonymous': [], 'groups': {}}
            self.dump()
            return

        self.read()

    def close(self):
        if self._is_dirty:
            self.dump()

        self._path = ''
        self._is_open = False
        self._obj = {}
        self._is_dirty = False

    def read(self):
        with open(self._path, 'r', encoding='utf-8') as file:
            self._obj = json.loads(file.read())

        if 'anonymous' not in self._obj:
            self._obj['anonymous'] = []
            self._is_dirty = True

        if 'groups' not in self._obj:
            self._obj['groups'] = {}
            self._is_dirty = True

        if not isinstance(self._obj['anonymous'], list) or not isinstance(self._obj['groups'], dict):
            raise ValueError("invalid subscribes.json, please fix it")

        if self._is_dirty:
            self.dump()

    def dump(self):
        with open(self._path, 'w', encoding='utf-8') as file:
            file.write(json.dumps(self._obj, indent=2, ensure_ascii=False))
        self._is_dirty = False

    def anonymous_count(self) -> int:
        if 'anonymous' not in self._obj:
            return 0
        return len(self._obj['anonymous'])

    def group_count(self) -> int:
        if 'groups' not in self._obj:
            return 0
        return len(self._obj['groups'])

    def anonymous_names(self):
        if 'anonymous' not in self._obj:
            return []
        return [item['name'] for item in self._obj['anonymous']]

    def groups(self):
        if 'groups' not in self._obj:
            return []
        return list(self._obj['groups'].keys())

    def group_node_names(self, name):
        if 'groups' not in self._obj or name not in self._obj['groups']:
            return []

        sub_list = self._obj['groups'][name]
        if 'nodes' not in sub_list:
            return []

        return [item['name'] for item in sub_list['nodes']]

    def has_anonymous(self, name) -> bool:
        if 'anonymous' not in self._obj:
            return False

        for item in self._obj['anonymous']:
            if 'name' in item and item['name'] == name:
                return True

        return False

    def has_group(self, name) -> bool:
        if 'groups' not in self._obj:
            return False

        return name in self._obj['groups']

    def add_anonymous(self, url, param: dict, flush=True):
        if len(param['remark']) != 0:
            name = f'{param["remark"]} ({param["protocol"]}:{param["server"]}:{param["port"]}:{param["identify"]})'
        else:
            name = f'{param["protocol"]}:{param["server"]}:{param["port"]}:{param["identify"]}'

        if self.has_anonymous(name):
            raise ValueError(f'anonymous {name} node already exists')

        self._obj['anonymous'].append({
            'name': name,
            'url': url,
            'info': {key: value for key, value in param.items() if key != 'success'}
        })
        self._is_dirty = True

        if flush and self._is_dirty:
            self.dump()

    def _parse_node(self, url):
        result = protocol.parse(url)
        if result['success'] == 0:
            logging.error(f'invalid node: {url}, reason: {result["reason"]}')
            return None

        if len(result['remark']) != 0:
            name = f'{result["remark"]} ({result["protocol"]}:{result["server"]}:{result["port"]}:{result["identify"]})'
        else:
            name = f'{result["protocol"]}:{result["server"]}:{result["port"]}:{result["identify"]}'

        return {
            'name': name,
            'url': url,
            'info': {key: value for key, value in result.items() if key != 'success'}
        }

    def add_group(self, name, url, param: dict, flush=True):
        if not name:
            raise ValueError('invalid subscribe name')

        if self.has_group(name):
            raise ValueError(f'subscribe {name} already exists')

        nodes = []
        for n in param['subscribe_list']:
            node = self._parse_node(n)
            if node:
                nodes.append(node)

        self._obj['groups'][name] = {
            'url': url,
            'nodes': nodes
        }
        self._is_dirty = True

        if flush and self._is_dirty:
            self.dump()

    def update(self, name, flush=True):
        if name not in self._obj['groups']:
            raise ValueError(f'subscribe <{name}> not exists')

        result = protocol.parse(self._obj['groups'][name]['url'])
        if result['success'] == 0:
            raise ValueError(result['reason'])

        new_nodes = []
        for n in result['subscribe_list']:
            node = self._parse_node(n)
            if node:
                new_nodes.append(node)

        self._obj['groups'][name]['nodes'] = new_nodes
        self._is_dirty = True

        if flush and self._is_dirty:
            self.dump()

    def update_all(self):
        for name in self.groups():
            print(f'update subscribe list: {name}')
            self.update(name, flush=False)

        if self._is_dirty:
            self.dump()

    def clean(self):
        self._obj['anonymous'] = []
        self._obj['groups'] = {}
        self._is_dirty = True
        self.dump()

    def delete_anonymous_node(self, name):
        self._obj['anonymous'] = list(filter(lambda node: node['name'] != name, self._obj['anonymous']))
        self._is_dirty = True
        self.dump()

    def delete_group(self, name):
        self._obj['groups'].pop(name)
        self._is_dirty = True
        self.dump()

    def selected(self, service_mode=False) -> object:
        key = 'service_mode_selected' if service_mode else 'selected'
        if key not in self._obj:
            return None
        return self._obj[key]

    def _get_node(self, group_name, node_name) -> object:
        if not group_name:
            for node in self._obj['anonymous']:
                if node['name'] == node_name:
                    return copy.deepcopy(node)
            return None

        nodes = self._obj['groups'][group_name]['nodes']
        for node in nodes:
            if node['name'] == node_name:
                return copy.deepcopy(node)

        return None

    def select(self, group_name, node_name, service_mode=False) -> object:
        if not group_name:
            group_name = ''

        node = self._get_node(group_name, node_name)
        if not node:
            raise ValueError('node not found')

        self._obj['service_mode_selected' if service_mode else 'selected'] = {
            'name': node_name,
            'group_name': group_name,
            'node': node
        }
        self._is_dirty = True
        self.dump()

        return copy.deepcopy(node)


def generate_v2ray_base_config(app_dir, config_path, log_level=None, socks_port=None, http_port=None,
                               socks_port_s=None, http_port_s=None, listen=None) -> bool:
    if log_level is None:
        log_level = 'warning'
    if socks_port is None:
        socks_port = '23338'
    if http_port is None:
        http_port = '23339'
    if socks_port_s is None:
        socks_port_s = '22338'
    if http_port_s is None:
        http_port_s = '22339'
    if listen is None:
        listen = '127.0.0.1'

    base_config = {}
    base_config['log'] = {
        'access': os.path.join(app_dir, 'v2ray_access.log'),
        'error': os.path.join(app_dir, 'v2ray_error.log'),
        'loglevel': log_level
    }
    base_config['inbounds'] = [
        {
            'tag': 'socks',
            "port": socks_port,
            "listen": listen,
            "service_mode_port": socks_port_s,
            "service_mode_listen": listen,
            "protocol": "socks",
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls"],
                "routeOnly": False
            },
            "settings": {
                "auth": "noauth",
                "udp": True,
                "allowTransparent": False
            }
        },
        {
            "tag": "http",
            "port": http_port,
            "listen": listen,
            "service_mode_port": http_port_s,
            "service_mode_listen": listen,
            "protocol": "http",
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls"],
                "routeOnly": False
            },
            "settings": {
                "auth": "noauth",
                "udp": True,
                "allowTransparent": False
            }
        }
    ]
    base_config['outbounds'] = [
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {}
        },
        {
            "tag": "block",
            "protocol": "blackhole",
            "settings": {
                "response": {
                    "type": "http"
                }
            }
        }
    ]
    base_config['dns'] = {
        "servers": [
            "1.1.1.1",
            "8.8.8.8"
        ]
    }
    base_config['routing'] = {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "inboundTag": ["api"],
                "outboundTag": "api"
            },
            {
                "type": "field",
                "outboundTag": "direct",
                "domain": ["domain:example-example.com", "domain:example-example2.com"]
            },
            {
                "type": "field",
                "outboundTag": "block",
                "domain": ["geosite:category-ads-all"]
            },
            {
                "type": "field",
                "outboundTag": "direct",
                "domain": ["geosite:cn"]
            },
            {
                "type": "field",
                "outboundTag": "direct",
                "ip": ["geoip:private", "geoip:cn"]
            }
        ]
    }

    result = True

    try:
        with open(config_path, 'w', encoding='utf-8') as file:
            file.write(json.dumps(base_config, indent=2, ensure_ascii=False))
    except Exception as e:
        result = False
        logging.error(f'generate v2ray base config failed: {e}')

        if os.path.exists(config_path):
            os.remove(config_path)

    return result


def generate_outbound_config(node) -> object:
    config = {}
    node_info = node['info']
    node_options = node_info['options']

    config['tag'] = 'proxy'
    config['protocol'] = node_info['protocol']
    config['settings'] = {}

    if node_info['protocol'] == 'shadowsocks':
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
    elif node_info['protocol'] == 'trojan':
        config['settings']['servers'] = [{
            'address': node_info['server'],
            'method': 'chacha20',
            'ota': False,
            'password': node_info['identify'],
            'port': int(node_info['port'])
        }]
        config['streamSettings'] = protocol.generate_trojan_stream_settings(node_options)
    elif node_info['protocol'] == 'vmess':
        config['settings']['vnext'] = [{
            'address': node_info['server'],
            'port': int(node_info['port']),
            'users': [{
                'id': node_info['identify'],
                'alterId': int(node_options.get('aid', 0)),
                'email': 't@t.tt',  # fake email, see v2rayN
                'security': node_options.get('scy', 'auto')
            }]
        }]
        config['streamSettings'] = protocol.generate_vmess_stream_settings(node_options)
    else:
        raise ValueError(f'{node_info["protocol"]} protocol unsupport')

    config['mux'] = {
        'enabled': False,
        'concurrency': -1
    }

    return config


def generate_node_config(node_config_path, base_config_path, outbound_config, service_mode):
    with open(base_config_path, 'r', encoding='utf-8') as file:
        config = json.loads(file.read())

    config['outbounds'].insert(0, outbound_config)

    for inbound in config.get('inbounds', []):
        if service_mode:
            inbound['port'] = inbound.get('service_mode_port', 22338 if inbound.get('tag', '') == 'socks' else 22339)
            inbound['listen'] = inbound.get('service_mode_listen', '127.0.0.1')

        if 'service_mode_port' in inbound:
            del inbound['service_mode_port']

        if 'service_mode_listen' in inbound:
            del inbound['service_mode_listen']

    if service_mode:
        if platform.system() == 'Linux':
            access_log = '/var/log/v2sub/v2ray_access.log'
            error_log = '/var/log/v2sub/v2ray_error.log'
        else:
            service_dir = os.path.dirname(node_config_path)
            access_log = f'{service_dir}\\v2sub_service_access.log'
            error_log = f'{service_dir}\\v2sub_service_error.log'

        config['log'] = {
            'access': access_log,
            'error': error_log,
            'loglevel': 'warning'
        }

    with open(node_config_path, 'w', encoding='utf-8') as file:
        file.write(json.dumps(config, indent=2, ensure_ascii=False))
