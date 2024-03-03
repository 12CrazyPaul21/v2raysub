import re
import json

from urllib.parse import unquote, urlparse, ParseResult

from . import util


def _regular_content(url: ParseResult) -> str:
    raw = url.geturl()[len(url.scheme) + 3:]

    if util.is_base64(raw):
        return util.decode_base64(raw)

    return raw


def load_subscribe(url: ParseResult) -> object:
    result = {'success': 0, 'reason': '', 'subscribe_list': []}

    try:
        response = util.request_get(url.geturl())
        if not response.ok:
            response.raise_for_status()
        else:
            result['success'] = 1
            result['subscribe_list'] = util.decode_base64(response.content.decode('utf-8')).splitlines()
    except Exception as e:
        result['success'] = 0
        result['reason'] = e

    return result


def parse_shadowsocks_url(url: ParseResult) -> object:
    """
    ss://[method:]<password>@<server>:<port>[#remark]
    ss://<base64 string>
    """

    result = {'success': 0}
    pattern = r'^((?P<method>.*?):)?(?P<password>.+)@(?P<server>.+):(?P<port>\d+)$'

    url = urlparse(f'ss://{_regular_content(url)}')
    match = re.match(pattern, url.netloc)
    if match is None:
        result['reason'] = 'invalid shadowsocks params'
        return result

    result['success'] = 1
    result['protocol'] = 'shadowsocks'
    result['remark'] = unquote(url.fragment)
    result['server'] = match['server']
    result['port'] = match['port']

    if match['method']:
        result['identify'] = match['password']
        result['method'] = match['method']
    else:
        password = match['password']
        if util.is_base64(password):
            password = util.decode_base64(password)
        splited = password.split(':')
        if len(splited) > 1:
            result['identify'] = splited[1]
            result['method'] = splited[0]
        else:
            result['identify'] = splited[0]
            result['method'] = ''

    result['options'] = util.parse_query_string(url.query)

    return result


def parse_shadowsocksr_url(_: ParseResult) -> object:
    return {
        'success': 0,
        'reason': 'shadowsocks-R unsupported'
    }


def parse_trojan_url(url: ParseResult) -> object:
    """
    trojan://<password>@<server>:<port>[?options...}[#remark]
    trojan://<base64 string>

    options:
        - security
        - type
        - headerType: Fake type
        - flow
        - host(url encode)
        - sni(url encode): Server Name Indication
        - alpn(url encode)
        - fp: Fingerprint
        - path
        - encryption(url encode): ss;method;password
    """

    result = {'success': 0}
    pattern = r'^(?P<password>.+)@(?P<server>.+):(?P<port>\d+)$'

    url = urlparse(f'trojan://{_regular_content(url)}')
    match = re.match(pattern, url.netloc)
    if match is None:
        result['reason'] = 'invalid trojan params'
        return result

    result['success'] = 1
    result['protocol'] = 'trojan'
    result['remark'] = unquote(url.fragment)
    result['server'] = match['server']
    result['port'] = match['port']
    result['identify'] = match['password']
    result['method'] = ''
    result['options'] = util.parse_query_string(url.query)

    return result


def parse_vmess_url(url: ParseResult) -> object:
    """
    vmess://<base64 string>

    items:
        - v: Version
        - ps: Remark
        - add: Server Address
        - port
        - id: UUID
        - aid: Alter ID
        - scy: Security Type
        - net: Transport Protocol
        - type: Fake Type
        - host: Fake Host
        - path
        - tls
        - sni: Server Name Indication
        - alpn
        - fp: Fingerprint
    """

    result = {'success': 0}
    content = None

    try:
        content = json.loads(_regular_content(url))
    except Exception as e:
        content = None
        result['reason'] = e

    if content is None:
        return result

    if not set(['add', 'port', 'id']).issubset(content.keys()):
        result['reason'] = 'invalid vmess params'
        return result

    result['success'] = 1
    result['protocol'] = 'vmess'
    result['remark'] = content['ps']
    result['server'] = content['add']
    result['port'] = content['port']
    result['identify'] = content['id']
    result['method'] = '' if 'scy' not in content else content['scy']
    result['options'] = content

    return result


def parse(url: str) -> object:
    parsed_url = urlparse(url)
    return {
        'http': load_subscribe,
        'https': load_subscribe,
        'ss': parse_shadowsocks_url,
        'ssr': parse_shadowsocksr_url,
        'trojan': parse_trojan_url,
        'vmess': parse_vmess_url,
    }.get(
        parsed_url.scheme,
        lambda u: {'success': 0, 'reason': f'unknown scheme : {u.geturl()}'}
    )(parsed_url)


def generate_trojan_stream_settings(options) -> object:
    settings = {}
    allow_stream_type = ['tcp', 'kcp', 'ws', 'h2', 'http', 'quic', 'grpc']
    allow_security_type = ['tls', 'reality']
    stream_type = options.get('type')
    security_type = options.get('security', 'tls')

    if stream_type in allow_stream_type:
        settings['network'] = stream_type
    if security_type in allow_security_type:
        settings['security'] = security_type

    if stream_type == 'tcp':
        if options.get('headerType') == 'http':
            settings['tcpSettings'] = {
                'header': {
                    'type': 'http',
                    'request': {
                        'version': '1.1',
                        'method': 'GET',
                        'path': [options.get('path', '/')],
                        'headers': {
                            'Host': unquote(options['host']).split(',') if ('host' in options) else [],
                            'User-Agent': [''],
                            'Accept-Encoding': ['gzip, deflate'],
                            'Connection': ['keep-alive'],
                            'Pragma': 'no-cache'
                        }
                    }
                }
            }
    elif stream_type == 'kcp':
        settings['kcpSettings'] = {
            'mtu': 1350,
            'tti': 50,
            'uplinkCapacity': 12,
            'downlinkCapacity': 100,
            'congestion': False,
            'readBufferSize': 2,
            'writeBufferSize': 2,
            'header': {
                "type": options.get('headerType', 'none')
            },
            'seed': options.get('path', '')
        }
    elif stream_type == 'ws':
        settings['wsSettings'] = {
            'path': options.get('path', '/'),
            'headers': {
                'Host': unquote(options.get('host', ''))
            }
        }
    elif stream_type in ['h2', 'http']:
        settings['httpSettings'] = {
            'path': options.get('path', '/'),
            'host': unquote(options['host']).split(',') if ('host' in options) else []
        }
    elif stream_type == 'quic':
        settings['quicSettings'] = {
            'security': unquote(options.get('quicSecurity', '')),
            'key': unquote(options.get('key', '')),
            'header': {
                'type': options.get('headerType', 'none')
            }
        }
    elif stream_type == 'grpc':
        settings['grpcSettings'] = {
            'serviceName': unquote(options.get('serviceName', '')),
            'multiMode': options.get('mode', 'gun') == 'multi',
            'idle_timeout': 60,
            'health_check_timeout': 20,
            'permit_without_stream': False,
            'initial_windows_size': 0
        }

    if security_type == 'tls':
        settings['tlsSettings'] = {
            'allowInsecure': options.get('allowInsecure', '1') == '1',
            'show': False,
            'serverName': options.get('sni', ''),
            'alpn': unquote(options['alpn']).split(',') if ('alpn' in options) else [],
            'fingerprint': options.get('fp', '')
        }
    elif security_type == 'reality':
        settings['realitySettings'] = {
            'show': False,
            'serverName': options.get('sni', ''),
            'fingerprint': options.get('fp', ''),
            'publicKey': options.get('pbk', ''),
            'shortId': options.get('sid', ''),
            'spiderX': options.get('spx', ''),
        }

    return settings


def generate_vmess_stream_settings(options) -> object:
    settings = {}
    allow_stream_type = ['tcp', 'kcp', 'ws', 'h2', 'http', 'quic', 'grpc']
    allow_security_type = ['tls']
    stream_type = options.get('net')
    security_type = options.get('tls')

    if stream_type in allow_stream_type:
        settings['network'] = stream_type
    if security_type in allow_security_type:
        settings['security'] = security_type

    if stream_type == 'tcp':
        if options.get('headerType') == 'http':
            settings['tcpSettings'] = {
                'header': {
                    'type': 'http',
                    'request': {
                        'version': '1.1',
                        'method': 'GET',
                        'path': [options.get('path', '/')],
                        'headers': {
                            'Host': unquote(options['host']).split(',') if ('host' in options) else [],
                            'User-Agent': [''],
                            'Accept-Encoding': ['gzip, deflate'],
                            'Connection': ['keep-alive'],
                            'Pragma': 'no-cache'
                        }
                    }
                }
            }
    elif stream_type == 'kcp':
        settings['kcpSettings'] = {
            'mtu': 1350,
            'tti': 50,
            'uplinkCapacity': 12,
            'downlinkCapacity': 100,
            'congestion': False,
            'readBufferSize': 2,
            'writeBufferSize': 2,
            'header': {
                "type": options.get('type', 'none')
            },
            'seed': options.get('path', '')
        }
    elif stream_type == 'ws':
        settings['wsSettings'] = {
            'path': options.get('path', '/'),
            'headers': {
                'Host': unquote(options.get('host', ''))
            }
        }
    elif stream_type in ['h2', 'http']:
        settings['httpSettings'] = {
            'path': options.get('path', '/'),
            'host': unquote(options['host']).split(',') if ('host' in options) else []
        }
    elif stream_type == 'quic':
        settings['quicSettings'] = {
            'security': unquote(options.get('host', '')),
            'key': unquote(options.get('path', '')),
            'header': {
                'type': options.get('type', 'none')
            }
        }
    elif stream_type == 'grpc':
        settings['grpcSettings'] = {
            'serviceName': unquote(options.get('path', '')),
            'multiMode': options.get('type', 'gun') == 'multi',
            'idle_timeout': 60,
            'health_check_timeout': 20,
            'permit_without_stream': False,
            'initial_windows_size': 0
        }

    if security_type == 'tls':
        settings['tlsSettings'] = {
            'allowInsecure': True,
            'serverName': options.get('sni', ''),
            'alpn': unquote(options['alpn']).split(',') if ('alpn' in options) else [],
            'fingerprint': options.get('fp', ''),
            'show': False
        }

    return settings