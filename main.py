import requests
import base64
import yaml
import json
import socket
import time
import re
import os
import shutil
import tempfile
import platform
import subprocess
import random
import zipfile
import io
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
#  https://raw.githubusercontent.com/moneyfly1/collectSub/refs/heads/main/output/all.txt
# 订阅链接列表
links = [
    "https://raw.githubusercontent.com/gzpanda/temppp/refs/heads/main/panda.yaml", 
    "https://raw.githubusercontent.com/jianguogongyong/ssr_subscrible_tool/refs/heads/master/node.txt", 
    "https://raw.githubusercontent.com/jgchengxin/ssr_subscrible_tool/refs/heads/master/node.txt",
    "https://raw.githubusercontent.com/dl250/dl250/refs/heads/master/node.txt", 
    "https://raw.githubusercontent.com/zhangkaiitugithub/passcro/refs/heads/main/speednodes.txt", 
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/refs/heads/master/list.meta.yml",        
]

# 测试使用
# links = [
#     "https://ghproxy.net/https://raw.githubusercontent.com/firefoxmmx2/v2rayshare_subcription/main/subscription/clash_sub.yaml",
#     "https://ghproxy.net/https://raw.githubusercontent.com/Roywaller/clash_subscription/refs/heads/main/clash_subscription.txt",
#     "https://www.freeclashnode.com/uploads/{Y}/{m}/0-{Ymd}.yaml",
#     "https://ghproxy.net/https://raw.githubusercontent.com/aiboboxx/clashfree/refs/heads/main/clash.yml",
#     "https://ghproxy.net/https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/LogInfo.txt",
#     'https://ghproxy.net/https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2',
#     'https://ghproxy.net/https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt',
#     'https://ghproxy.net/https://raw.githubusercontent.com/vpnmarket/sub/refs/heads/main/hiddify1.txt',
#    ]

# 支持的协议类型列表
SUPPORTED_PROTOCOLS = [
    'vmess://', 
    'trojan://', 
    'vless://', 
    'ss://', 
    'ssr://', 
    'http://', 
    'https://', 
    'socks://', 
    'socks5://',
    'hysteria://',
    'wireguard://'
]

# 测速相关配置
# 测试URL列表
TEST_URLS = [
    "http://www.gstatic.com/generate_204",  # Google测试
]
CONNECTION_TIMEOUT = 10  # 连接超时时间，单位为秒
MAX_CONCURRENT_TESTS = 100  # 最大并发测试数量
DEBUG_MODE = False  # 默认开启调试模式，方便查看处理过程

# 核心程序配置
CORE_PATH = None  # 核心程序路径，将自动检测

# ========== sing-box 内核相关 ==========
SINGBOX_PATH = r'C:/Users/Administrator/Desktop/nodespeedtest-master/xray-core/windows-64/sing-box'
SINGBOX_DIR = os.path.dirname(SINGBOX_PATH)
SINGBOX_EXE = SINGBOX_PATH

def is_github_raw_url(url):
    """判断是否为GitHub的raw URL"""
    return 'raw.githubusercontent.com' in url

def extract_file_pattern(url):
    """从URL中提取文件模式，例如{x}.yaml中的.yaml"""
    match = re.search(r'\{x\}(\.[a-zA-Z0-9]+)(?:/|$)', url)
    if match:
        return match.group(1)  # 返回文件后缀，如 '.yaml', '.txt', '.json'
    return None

def get_github_filename(github_url, file_suffix):
    """从GitHub API获取匹配指定后缀的文件名"""
    try:
        print(f"处理GitHub URL: {github_url}")
        # 标准化URL - 移除代理前缀
        url_without_proxy = github_url
        if 'ghproxy.net/' in github_url:
            url_without_proxy = github_url.split('ghproxy.net/', 1)[1]
        
        # 提取仓库所有者、名称和分支信息
        url_parts = url_without_proxy.replace('https://raw.githubusercontent.com/', '').split('/')
        if len(url_parts) < 3:
            print(f"URL格式不正确: {github_url}")
            return None
        
        owner = url_parts[0]
        repo = url_parts[1]
        branch = url_parts[2]
        
        # 处理分支信息
        original_branch = branch
        if 'refs/heads/' in branch:
            branch = branch.split('refs/heads/')[1]
        
        # 提取文件路径 - 忽略仓库信息和{x}部分
        # 例如：owner/repo/branch/path/to/directory/{x}.yaml -> path/to/directory
        path_parts = '/'.join(url_parts[3:])  # 获取路径部分
        if '{x}' in path_parts:
            directory_path = path_parts.split('/{x}')[0]
        else:
            directory_path = path_parts
        
        print(f"解析结果: 仓库={owner}/{repo}, 分支={branch}, 路径={directory_path}")
        
        # 构建GitHub API URL
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{directory_path}"
        
        # 添加ref参数指定分支
        if branch:
            api_url += f"?ref={branch}"
            
        print(f"构建的API URL: {api_url}")
        
        # 使用代理访问GitHub API
        proxy_api_url = f"https://ghproxy.net/{api_url}"
        print(f"尝试通过代理访问: {proxy_api_url}")
        
        try:
            response = requests.get(proxy_api_url, timeout=30)
            if response.status_code != 200:
                print("代理访问失败，尝试直接访问GitHub API")
                response = requests.get(api_url, timeout=30)
        except Exception as e:
            print(f"代理访问失败: {str(e)}，尝试直接访问")
            response = requests.get(api_url, timeout=30)
            
        if response.status_code != 200:
            print(f"GitHub API请求失败: {response.status_code} - {api_url}")
            print(f"响应内容: {response.text[:200]}...")
            return None
        
        # 解析返回的JSON
        files = response.json()
        if not isinstance(files, list):
            print(f"GitHub API返回的不是文件列表: {type(files)}")
            print(f"响应内容: {str(files)[:200]}...")
            return None
        
        print(f"在目录中找到{len(files)}个文件/目录")
        
        # 查找匹配后缀的文件
        matching_files = [f['name'] for f in files if f['name'].endswith(file_suffix)]
        
        if not matching_files:
            print(f"未找到匹配{file_suffix}后缀的文件，目录包含: {[f['name'] for f in files][:10]}")
            return None
        
        # 排序并选择第一个匹配的文件（通常选择最近的文件）
        matching_files.sort(reverse=True)
        selected_file = matching_files[0]
        print(f"选择文件: {selected_file}")
        return selected_file
        
    except Exception as e:
        print(f"获取GitHub文件列表出错: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

def format_current_date(url):
    """替换URL中的日期占位符和{x}占位符"""
    # 定义和生成所有可能的日期格式变量
    now = datetime.now()
    date_vars = {
        # 基本日期组件
        'Y': now.strftime('%Y'),          # 年份，如2023
        'm': now.strftime('%m'),          # 月份，如05
        'd': now.strftime('%d'),          # 日期，如09
        
        # 组合日期格式
        'Ymd': now.strftime('%Y%m%d'),    # 组合格式，如20230509
        'Y-m-d': now.strftime('%Y-%m-%d'), # 带连字符格式，如2023-05-09
        'Y_m_d': now.strftime('%Y_%m_%d'), # 带下划线格式，如2023_05_09
        
        # 额外日期格式
        'Y-m': now.strftime('%Y-%m'),     # 年月，如2023-05
        'Y_m': now.strftime('%Y_%m'),     # 带下划线的年月，如2023_05
        'md': now.strftime('%m%d'),       # 月日，如0509
        'm-d': now.strftime('%m-%d'),     # 带连字符的月日，如05-09
        'm_d': now.strftime('%m_%d'),     # 带下划线的月日，如05_09
    }
    
    # 处理日期占位符
    try:
        formatted_url = url.format(**date_vars)
    except KeyError as e:
        print(f"URL中包含未支持的日期格式占位符: {e}")
        print(f"支持的日期占位符有: {', '.join(date_vars.keys())}")
        return url  # 返回原始URL，让后续处理决定是否跳过
    
    # 处理{x}占位符
    if '{x}' in formatted_url:
        # 提取后缀
        file_suffix = extract_file_pattern(formatted_url)
        if file_suffix and is_github_raw_url(formatted_url):
            # 获取GitHub中匹配的文件名
            filename = get_github_filename(formatted_url, file_suffix)
            if filename:
                # 替换{x}占位符为实际文件名
                pattern = r'\{x\}' + re.escape(file_suffix)
                formatted_url = re.sub(pattern, filename, formatted_url)
            else:
                print(f"警告: 未能解析{x}占位符, URL: {formatted_url}")
    
    return formatted_url

def fetch_content(url):
    """获取订阅内容"""
    try:
        # 1. 首先替换日期相关的占位符
        now = datetime.now()
        date_vars = {
            # 基本日期组件
            'Y': now.strftime('%Y'),          # 年份，如2023
            'm': now.strftime('%m'),          # 月份，如05
            'd': now.strftime('%d'),          # 日期，如09
            
            # 组合日期格式
            'Ymd': now.strftime('%Y%m%d'),    # 组合格式，如20230509
            'Y-m-d': now.strftime('%Y-%m-%d'), # 带连字符格式，如2023-05-09
            'Y_m_d': now.strftime('%Y_%m_%d'), # 带下划线格式，如2023_05_09
            
            # 额外日期格式
            'Y-m': now.strftime('%Y-%m'),     # 年月，如2023-05
            'Y_m': now.strftime('%Y_%m'),     # 带下划线的年月，如2023_05
            'md': now.strftime('%m%d'),       # 月日，如0509
            'm-d': now.strftime('%m-%d'),     # 带连字符的月日，如05-09
            'm_d': now.strftime('%m_%d'),     # 带下划线的月日，如05_09
        }
        
        # 先将{x}占位符临时替换，以免被format误处理
        temp_marker = "___X_PLACEHOLDER___"
        temporary_url = url.replace("{x}", temp_marker)
        
        # 尝试使用format方法替换所有日期占位符
        try:
            formatted_url = temporary_url.format(**date_vars)
        except KeyError as e:
            # 如果format失败，尝试手动替换
            print(f"URL中包含未支持的日期格式占位符: {e}")
            print(f"支持的日期占位符有: {', '.join(date_vars.keys())}")
            formatted_url = temporary_url
            # 手动替换常见的日期占位符
            for pattern, replacement in [
                ('{Y_m_d}', now.strftime('%Y_%m_%d')),
                ('{Y-m-d}', now.strftime('%Y-%m-%d')),
                ('{Ymd}', now.strftime('%Y%m%d')),
                ('{Y}', now.strftime('%Y')),
                ('{m}', now.strftime('%m')),
                ('{d}', now.strftime('%d')),
            ]:
                if pattern in formatted_url:
                    formatted_url = formatted_url.replace(pattern, replacement)
                    print(f"手动替换日期占位符 {pattern} 为 {replacement}")
        
        # 将临时标记替换回{x}
        formatted_url = formatted_url.replace(temp_marker, "{x}")
        
        # 2. 然后处理{x}占位符 - 现在日期占位符已经被替换
        if '{x}' in formatted_url:
            file_suffix = extract_file_pattern(formatted_url)
            if file_suffix and is_github_raw_url(formatted_url):
                print(f"在URL中找到{{x}}占位符，尝试获取匹配的文件...")
                filename = get_github_filename(formatted_url, file_suffix)
                if filename:
                    pattern = r'\{x\}' + re.escape(file_suffix)
                    formatted_url = re.sub(pattern, filename, formatted_url)
                    print(f"成功替换{{x}}占位符为: {filename}")
                else:
                    print(f"警告: 未能获取匹配{file_suffix}的文件")
            else:
                print(f"警告: 无法处理{{x}}占位符，URL不是GitHub raw链接或找不到文件后缀")
        
        print(f"实际请求URL: {formatted_url}")
        
        # 模拟Chrome浏览器请求头，与curl命令类似
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Cache-Control': 'no-cache',
            'DNT': '1',
            'Pragma': 'no-cache',
            'Upgrade-Insecure-Requests': '1',
            'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'sec-fetch-user': '?1'
        }
        
        # 特殊站点处理 - 对特定的站点使用不同的请求方式
        special_sites = ['igdux.top']
        use_session = any(site in formatted_url for site in special_sites)
        
        if use_session:
            # 使用Session对象来保持cookie等状态
            session = requests.Session()
            # 先发送一个HEAD请求，获取cookie等信息
            session.head(formatted_url, headers=headers, timeout=30)
            response = session.get(formatted_url, headers=headers, timeout=60, stream=True)
        else:
            # 普通请求
            response = requests.get(formatted_url, headers=headers, timeout=60, stream=True)
        
        response.raise_for_status()
        
        # 检查Content-Type，确保正确处理各种类型的内容
        content_type = response.headers.get('Content-Type', '').lower()
        # print(f"Content-Type: {content_type}")
        
        # 处理不同内容类型
        # 1. 处理二进制类型
        if 'application/octet-stream' in content_type or 'application/x-yaml' in content_type:
            content = response.content.decode('utf-8', errors='ignore')
        # 2. 处理明确指定了UTF-8字符集的文本
        elif 'charset=utf-8' in content_type or 'text/plain' in content_type:
            # 尝试多种解码方式
            encodings_to_try = ['utf-8', 'gbk', 'latin1', 'ascii', 'iso-8859-1']
            for encoding in encodings_to_try:
                try:
                    content = response.content.decode(encoding, errors='ignore')
                    # 检查解码是否成功 - 如果包含常见订阅指示符
                    if any(indicator in content for indicator in ['proxies:', 'vmess://', 'trojan://', 'ss://', 'vless://']):
                        # print(f"使用 {encoding} 编码成功解码内容")
                        break
                except UnicodeDecodeError:
                    continue
            else:
                # 如果所有编码都失败，使用默认UTF-8
                content = response.content.decode('utf-8', errors='ignore')
                
            # 如果网址是特殊站点但仍然得到乱码，尝试拆解HTML标记
            if use_session and not any(indicator in content for indicator in ['proxies:', 'vmess://', 'trojan://', 'ss://', 'vless://']):
                try:
                    # 尝试解析HTML并提取内容
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.content, 'html.parser')
                    # 查找所有可能包含订阅信息的元素
                    for element in soup.find_all(['pre', 'code', 'div', 'textarea']):
                        element_text = element.get_text()
                        if any(indicator in element_text for indicator in ['proxies:', 'vmess://', 'trojan://', 'ss://', 'vless://']):
                            print(f"从HTML元素中提取到订阅内容")
                            content = element_text
                            break
                except ImportError:
                    print("未安装BeautifulSoup，跳过HTML解析")
                except Exception as e:
                    print(f"HTML解析错误: {str(e)}")
        # 3. 处理可能是base64编码的内容
        elif 'text/base64' in content_type:
            content = response.content.decode('utf-8', errors='ignore')
        # 4. 处理其他文本格式，如json
        elif 'application/json' in content_type or 'text/' in content_type:
            content = response.content.decode('utf-8', errors='ignore')
        # 5. 默认情况
        else:
            content = response.text
        
        # 测试内容是否可能是Base64编码
        if not any(indicator in content for indicator in ['proxies:', 'vmess://', 'trojan://', 'ss://', 'vless://']):
            try:
                # 移除空白字符，尝试base64解码
                cleaned_content = re.sub(r'\s+', '', content)
                # 添加适当的填充
                padding = len(cleaned_content) % 4
                if padding:
                    cleaned_content += '=' * (4 - padding)
                # 尝试base64解码
                decoded = base64.b64decode(cleaned_content)
                decoded_text = decoded.decode('utf-8', errors='ignore')
                
                if any(indicator in decoded_text for indicator in ['proxies:', 'vmess://', 'trojan://', 'ss://', 'vless://']):
                    print("检测到Base64编码的订阅内容，已成功解码")
                    content = decoded_text
            except:
                # 解码失败，继续使用原始内容
                pass
            
        return content
    except KeyError as e:
        print(f"URL中包含未支持的占位符: {e}")
        return None
    except Exception as e:
        print(f"Error fetching {url}: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

def parse_clash_yaml(content):
    """解析Clash配置文件，补全所有协议字段"""
    try:
        data = yaml.safe_load(content)
        if not data:
            return []
        proxies = []
        if 'proxies' in data:
            proxies = data['proxies']
        for key in ['proxy-providers', 'Proxy', 'proxys']:
            if key in data and isinstance(data[key], list):
                proxies.extend(data[key])
        for p in proxies:
            if 'type' not in p:
                if 'uuid' in p:
                    p['type'] = 'vmess'
                elif 'password' in p and 'cipher' in p:
                    p['type'] = 'ss'
                elif 'password' in p:
                    p['type'] = 'trojan'
                else:
                    p['type'] = 'ss'
            if 'port' in p:
                try:
                    p['port'] = int(p['port'])
                except Exception:
                    p['port'] = 443
            if p['type'] == 'vmess':
                p.setdefault('uuid', p.get('id', ''))
                p.setdefault('alterId', 0)
                p.setdefault('cipher', 'auto')
                p.setdefault('network', 'tcp')
                p.setdefault('tls', False)
                p.setdefault('path', '/')
                p.setdefault('host', p.get('server', ''))
            if p['type'] == 'ss':
                p.setdefault('cipher', 'aes-256-gcm')
                p.setdefault('password', '')
            if p['type'] == 'trojan':
                p.setdefault('password', '')
                p.setdefault('sni', p.get('server', ''))
            if p['type'] == 'hysteria':
                p.setdefault('auth', '')
                p.setdefault('protocol', '')
                p.setdefault('obfs', '')
                p.setdefault('alpn', '')
                p.setdefault('insecure', False)
            if p['type'] == 'reality':
                p.setdefault('publicKey', '')
                p.setdefault('shortId', '')
                p.setdefault('sni', p.get('server', ''))
                p.setdefault('fingerprint', '')
                p.setdefault('spiderX', '')
                p.setdefault('uuid', '')
        return proxies
    except Exception as e:
        print(f"解析Clash YAML失败: {str(e)}")
        return []

def parse_v2ray_base64(content):
    """解析V2Ray Base64编码的配置"""
    try:
        # 处理多行base64
        content = content.strip().replace('\n', '').replace('\r', '')
        # 尝试修复可能的编码问题
        try:
            if isinstance(content, bytes):
                content = content.decode('utf-8')
            # 确保内容是ASCII兼容的
            content = content.encode('ascii', 'ignore').decode('ascii')
        except UnicodeError:
            print("Error: Invalid encoding in base64 content")
            return []
            
        try:
            decoded = base64.b64decode(content + '=' * (-len(content) % 4))
            decoded_str = decoded.decode('utf-8', 'ignore')
        except Exception as e:
            print(f"Error decoding base64 content: {str(e)}")
            return []
            
        nodes = []
        for line in decoded_str.split('\n'):
            if line.startswith('vmess://') or line.startswith('trojan://'):
                node = parse_v2ray_uri(line)
                if node:
                    nodes.append(node)
        return nodes
    except Exception as e:
        # print(f"Error parsing V2Ray base64: {str(e)}")
        return []

def parse_v2ray_uri(uri):
    """解析V2Ray URI格式的配置，兼容标准、非标准、明文参数型vmess等格式，支持hysteria、reality"""
    try:
        # 处理vmess协议
        if uri.startswith('vmess://'):
            b64_config = uri.replace('vmess://', '')
            # 1. 标准base64-json格式
            try:
                b64_config_padded = b64_config + '=' * (-len(b64_config) % 4)
                decoded = base64.b64decode(b64_config_padded).decode()
                config = json.loads(decoded)
                return {
                    'type': 'vmess',
                    'name': config.get('ps', 'Unknown'),
                    'server': config.get('add', ''),
                    'port': int(config.get('port', 0)),
                    'uuid': config.get('id', ''),
                    'alterId': int(config.get('aid', 0)),
                    'cipher': config.get('type', 'auto'),
                    'tls': config.get('tls', '') == 'tls',
                    'network': config.get('net', 'tcp'),
                    'path': config.get('path', '/'),
                    'host': config.get('host', '')
                }
            except Exception:
                pass
            # 2. 明文json格式
            try:
                config = json.loads(b64_config)
                return {
                    'type': 'vmess',
                    'name': config.get('ps', 'Unknown'),
                    'server': config.get('add', ''),
                    'port': int(config.get('port', 0)),
                    'uuid': config.get('id', ''),
                    'alterId': int(config.get('aid', 0)),
                    'cipher': config.get('type', 'auto'),
                    'tls': config.get('tls', '') == 'tls',
                    'network': config.get('net', 'tcp'),
                    'path': config.get('path', '/'),
                    'host': config.get('host', '')
                }
            except Exception:
                pass
            # 3. 明文参数型vmess://user:uuid@host:port?...参数
            try:
                # 先补全协议头，urlparse才能正确解析
                if not b64_config.startswith('//'):
                    uri_full = 'vmess://' + b64_config
                else:
                    uri_full = uri
                parsed = urlparse(uri_full)
                query = parse_qs(parsed.query)
                # user:uuid@host:port
                user = parsed.username or ''
                uuid = parsed.password or user or ''
                server = parsed.hostname or ''
                port = parsed.port or 443
                alterId = int(query.get('alterId', [0])[0])
                network = query.get('type', ['tcp'])[0]
                cipher = query.get('security', ['auto'])[0]
                tls = query.get('tls', [''])[0] == 'tls'
                path = query.get('path', ['/'])[0]
                host = query.get('host', [server])[0]
                obfs = query.get('obfs', [''])[0]
                remarks = query.get('remarks', ['Unknown'])[0]
                # 兼容部分机场用tfo=1等参数
                return {
                    'type': 'vmess',
                    'name': remarks,
                    'server': server,
                    'port': int(port),
                    'uuid': uuid,
                    'alterId': alterId,
                    'cipher': cipher,
                    'tls': tls,
                    'network': network,
                    'path': path,
                    'host': host,
                    'obfs': obfs
                }
            except Exception:
                print(f"Non-standard vmess format: {uri}")
                return None
        # 处理trojan协议
        elif uri.startswith('trojan://'):
            parsed = urlparse(uri)
            query = parse_qs(parsed.query)
            return {
                'type': 'trojan',
                'name': query.get('sni', [query.get('peer', ['Unknown'])[0]])[0],
                'server': parsed.hostname or '',
                'port': parsed.port or 443,
                'password': parsed.username or '',
                'sni': query.get('sni', [''])[0]
            }
        # 处理vless协议
        elif uri.startswith('vless://'):
            parsed = urlparse(uri)
            query = parse_qs(parsed.query)
            return {
                'type': 'vless',
                'name': query.get('remarks', [query.get('sni', ['Unknown'])[0]])[0],
                'server': parsed.hostname or '',
                'port': parsed.port or 443,
                'uuid': parsed.username or '',
                'tls': query.get('security', [''])[0] == 'tls',
                'flow': query.get('flow', [''])[0],
                'network': query.get('type', ['tcp'])[0]
            }
        # 处理shadowsocks协议
        elif uri.startswith('ss://'):
            name = 'Unknown'
            if '#' in uri:
                name_part = uri.split('#', 1)[1]
                name = unquote(name_part)
                uri = uri.split('#', 1)[0]
            if '@' in uri:
                parsed = urlparse(uri)
                server = parsed.hostname or ''
                port = parsed.port or 443
                userinfo = parsed.username
                if userinfo:
                    try:
                        decoded = base64.b64decode(userinfo + '=' * (-len(userinfo) % 4)).decode()
                        if ':' in decoded:
                            method, password = decoded.split(':', 1)
                        else:
                            method, password = 'aes-256-gcm', userinfo
                    except:
                        if ':' in userinfo:
                            method, password = userinfo.split(':', 1)
                        else:
                            method, password = 'aes-256-gcm', userinfo
                else:
                    method, password = 'aes-256-gcm', ''
                query = parse_qs(parsed.query)
                if 'remarks' in query:
                    name = query.get('remarks', ['Unknown'])[0]
                return {
                    'type': 'ss',
                    'name': name,
                    'server': server,
                    'port': port,
                    'cipher': method,
                    'password': password
                }
            else:
                b64_config = uri.replace('ss://', '')
                try:
                    b64_config = b64_config + '=' * (-len(b64_config) % 4)
                    config_str = base64.b64decode(b64_config).decode()
                    if '@' in config_str:
                        method_pwd, server_port = config_str.rsplit('@', 1)
                        method, password = method_pwd.split(':', 1)
                        server, port = server_port.rsplit(':', 1)
                        return {
                            'type': 'ss',
                            'name': name,
                            'server': server,
                            'port': int(port),
                            'cipher': method,
                            'password': password
                        }
                except Exception as e:
                    return None
        # 处理shadowsocksr协议
        elif uri.startswith('ssr://'):
            b64_config = uri.replace('ssr://', '')
            try:
                b64_config = b64_config + '=' * (-len(b64_config) % 4)
                config_str = base64.b64decode(b64_config).decode()
                parts = config_str.split(':')
                if len(parts) >= 6:
                    server = parts[0]
                    port = parts[1]
                    protocol = parts[2]
                    method = parts[3]
                    obfs = parts[4]
                    password_and_params = parts[5].split('/?', 1)
                    password_b64 = password_and_params[0]
                    password = base64.b64decode(password_b64 + '=' * (-len(password_b64) % 4)).decode()
                    name = 'Unknown'
                    if len(password_and_params) > 1 and 'remarks=' in password_and_params[1]:
                        remarks_b64 = password_and_params[1].split('remarks=', 1)[1].split('&', 1)[0]
                        try:
                            name = base64.b64decode(remarks_b64 + '=' * (-len(remarks_b64) % 4)).decode()
                        except:
                            pass
                    return {
                        'type': 'ssr',
                        'name': name,
                        'server': server,
                        'port': int(port),
                        'protocol': protocol,
                        'cipher': method,
                        'obfs': obfs,
                        'password': password
                    }
            except Exception as e:
                return None
        # 处理hysteria协议
        elif uri.startswith('hysteria://'):
            parsed = urlparse(uri)
            query = parse_qs(parsed.query)
            return {
                'type': 'hysteria',
                'name': query.get('peer', ['Unknown'])[0],
                'server': parsed.hostname or '',
                'port': parsed.port or 443,
                'protocol': query.get('protocol', [''])[0],
                'auth': parsed.username or query.get('auth', [''])[0],
                'obfs': query.get('obfs', [''])[0],
                'alpn': query.get('alpn', [''])[0],
                'insecure': query.get('insecure', ['false'])[0] == 'true'
            }
        # 处理reality协议
        elif uri.startswith('reality://'):
            parsed = urlparse(uri)
            query = parse_qs(parsed.query)
            return {
                'type': 'reality',
                'name': query.get('remarks', ['Unknown'])[0],
                'server': parsed.hostname or '',
                'port': parsed.port or 443,
                'publicKey': query.get('publicKey', [''])[0],
                'shortId': query.get('shortId', [''])[0],
                'sni': query.get('sni', [''])[0],
                'fingerprint': query.get('fp', [''])[0],
                'spiderX': query.get('spiderX', [''])[0],
                'uuid': parsed.username or ''
            }
        # 处理HTTP/HTTPS协议
        elif uri.startswith(('http://', 'https://')):
            parsed = urlparse(uri)
            query = parse_qs(parsed.query)
            return {
                'type': 'http' if uri.startswith('http://') else 'https',
                'name': query.get('remarks', ['Unknown'])[0],
                'server': parsed.hostname or '',
                'port': parsed.port or (80 if uri.startswith('http://') else 443),
                'username': parsed.username or '',
                'password': parsed.password or ''
            }
            
        # 处理SOCKS协议
        elif uri.startswith(('socks://', 'socks5://')):
            parsed = urlparse(uri)
            query = parse_qs(parsed.query)
            return {
                'type': 'socks',
                'name': query.get('remarks', ['Unknown'])[0],
                'server': parsed.hostname or '',
                'port': parsed.port or 1080,
                'username': parsed.username or '',
                'password': parsed.password or ''
            }
            
        # 处理wireguard协议
        elif uri.startswith('wireguard://'):
            parsed = urlparse(uri)
            query = parse_qs(parsed.query)
            return {
                'type': 'wireguard',
                'name': query.get('remarks', ['Unknown'])[0],
                'server': parsed.hostname or '',
                'port': parsed.port or 51820,
                'private_key': query.get('privateKey', [''])[0],
                'public_key': query.get('publicKey', [''])[0],
                'allowed_ips': query.get('allowedIPs', ['0.0.0.0/0'])[0]
            }

    except Exception as e:
        # print(f"Error parsing URI: {str(e)}")
        return None

def extract_nodes(content):
    """级联提取节点，按照Base64 -> 明文vmess/json -> YAML -> 正则表达式 -> JSON的顺序尝试"""
    if not content:
        return []
    nodes = []
    methods_tried = []
    # 1. 尝试Base64解码提取
    try:
        cleaned_content = re.sub(r'[\s\n\r\t]+', '', content)
        cleaned_content = re.sub(r'[^A-Za-z0-9+/=]', '', cleaned_content)
        padding_length = len(cleaned_content) % 4
        if padding_length:
            cleaned_content += '=' * (4 - padding_length)
        try:
            decoded_bytes = base64.b64decode(cleaned_content)
            decoded_str = decoded_bytes.decode('utf-8', 'ignore')
            if any(protocol in decoded_str for protocol in SUPPORTED_PROTOCOLS):
                print("使用Base64解码提取节点")
                methods_tried.append("Base64")
                for line in decoded_str.split('\n'):
                    line = line.strip()
                    if any(line.startswith(protocol) for protocol in SUPPORTED_PROTOCOLS):
                        node = parse_v2ray_uri(line)
                        if node:
                            nodes.append(node)
        except Exception:
            pass
    except Exception as e:
        print(f"Base64预处理失败: {str(e)}")
    if len(nodes) > 0:
        print(f"通过【{methods_tried[-1]}】方法成功提取到{len(nodes)}个节点")
        return nodes
    # 2. 尝试明文vmess/json
    try:
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('vmess://'):
                node = parse_v2ray_uri(line)
                if node:
                    nodes.append(node)
            elif line.startswith('{') and 'add' in line and 'id' in line:
                # 可能是明文json
                try:
                    config = json.loads(line)
                    node = {
                        'type': 'vmess',
                        'name': config.get('ps', 'Unknown'),
                        'server': config.get('add', ''),
                        'port': int(config.get('port', 0)),
                        'uuid': config.get('id', ''),
                        'alterId': int(config.get('aid', 0)),
                        'cipher': config.get('type', 'auto'),
                        'tls': config.get('tls', '') == 'tls',
                        'network': config.get('net', 'tcp'),
                        'path': config.get('path', '/'),
                        'host': config.get('host', '')
                    }
                    nodes.append(node)
                except Exception:
                    continue
        if len(nodes) > 0:
            print(f"通过【明文vmess/json】方法成功提取到{len(nodes)}个节点")
            return nodes
    except Exception as e:
        print(f"明文vmess/json解析失败: {str(e)}")
    # 3. 尝试解析YAML格式
    try:
        # 移除HTML标签和特殊标记
        cleaned_content = re.sub(r'<[^>]+>|!&lt;str&gt;', '', content)
        
        # 更强大的YAML格式检测，查找常见Clash配置特征
        yaml_indicators = [
            'proxies:', 'Proxy:', 'proxy:', 'proxy-providers:', 
            'port:', 'socks-port:', 'allow-lan:', 'mode:',
            'type: vmess', 'type: ss', 'type: trojan', 'type: vless'
        ]
        
        if any(indicator in cleaned_content for indicator in yaml_indicators):
            # print("尝试解析YAML格式内容")
            methods_tried.append("YAML")
            
            # 尝试直接加载YAML
            try:
                yaml_nodes = parse_clash_yaml(cleaned_content)
                if yaml_nodes:
                    # print(f"从YAML中提取到{len(yaml_nodes)}个节点")
                    nodes.extend(yaml_nodes)
            except Exception as yaml_error:
                print(f"标准YAML解析失败: {str(yaml_error)}")
                
                # 如果标准解析失败，尝试更宽松的解析方式
                try:
                    # 尝试提取proxies部分
                    proxies_match = re.search(r'proxies:\s*\n([\s\S]+?)(?:\n\w+:|$)', cleaned_content)
                    if proxies_match:
                        proxies_yaml = "proxies:\n" + proxies_match.group(1)
                        yaml_nodes = parse_clash_yaml(proxies_yaml)
                        if yaml_nodes:
                            print(f"从proxies块提取到{len(yaml_nodes)}个节点")
                            nodes.extend(yaml_nodes)
                except Exception as fallback_error:
                    print(f"尝试解析proxies块失败: {str(fallback_error)}")
    except Exception as e:
        print(f"YAML解析过程出错: {str(e)}")
    
    # 如果已经提取到节点，直接返回
    if len(nodes) > 0:
        print(f"通过【{methods_tried[-1]}】方法成功提取到{len(nodes)}个节点")
        return nodes
    
    # 4. 尝试使用正则表达式直接提取
    try:
        # print("尝试使用正则表达式直接提取节点")
        methods_tried.append("正则表达式")
        
        # 为每种支持的协议定义正则表达式并提取
        for protocol in SUPPORTED_PROTOCOLS:
            if protocol == 'vmess://':
                # vmess通常是一个base64编码的字符串
                found_nodes = re.findall(r'vmess://[A-Za-z0-9+/=]+', content)
            elif protocol == 'hysteria://' or protocol == 'wireguard://':
                # 这些协议可能有特殊格式，需要特别处理
                found_nodes = re.findall(f'{protocol}[^"\'<>\\s]+', content)
            else:
                # 对于其他协议，采用通用正则表达式
                found_nodes = re.findall(f'{protocol}[^"\'<>\\s]+', content)
            
            for uri in found_nodes:
                node = parse_v2ray_uri(uri)
                if node:
                    nodes.append(node)
    except Exception as e:
        print(f"正则表达式提取失败: {str(e)}")
    
    # 如果已经提取到节点，直接返回
    if len(nodes) > 0:
        print(f"通过【{methods_tried[-1]}】方法成功提取到{len(nodes)}个节点")
        return nodes
    
    # 5. 尝试解析JSON格式
    try:
        # print("尝试解析JSON格式")
        methods_tried.append("JSON")
        
        # 清理内容，移除可能的HTML标签和注释
        cleaned_content = re.sub(r'<[^>]+>|/\*.*?\*/|//.*?$', '', content, flags=re.MULTILINE)
        
        # 尝试解析JSON
        try:
            json_data = json.loads(cleaned_content)
            json_nodes = parse_json_nodes(json_data)
            if json_nodes:
                # print(f"从JSON中提取到{len(json_nodes)}个节点")
                nodes.extend(json_nodes)
        except json.JSONDecodeError as e:
            # 尝试查找内容中的JSON片段
            try:
                # 查找类似于 [{...}] 或 {...} 形式的JSON
                json_matches = re.findall(r'(\[{.*?}\]|\{.*?\})', cleaned_content, re.DOTALL)
                for json_match in json_matches:
                    try:
                        potential_json = json.loads(json_match)
                        json_nodes = parse_json_nodes(potential_json)
                        if json_nodes:
                            # print(f"从JSON片段中提取到{len(json_nodes)}个节点")
                            nodes.extend(json_nodes)
                            # 找到有效的JSON片段后，不再继续查找
                            break
                    except:
                        continue
            except Exception as extract_error:
                # print(f"尝试提取JSON片段失败: {str(extract_error)}")
                pass
    except Exception as e:
        print(f"JSON解析过程出错: {str(e)}")
    
    if len(nodes) > 0:
        print(f"通过【{methods_tried[-1]}】方法成功提取到{len(nodes)}个节点")
        return nodes
    else:
        print("未找到任何节点")
        return []

def parse_json_nodes(json_data):
    """从JSON数据中解析节点信息"""
    nodes = []
    
    # 处理数组形式的JSON
    if isinstance(json_data, list):
        for item in json_data:
            node = parse_single_json_node(item)
            if node:
                nodes.append(node)
    # 处理对象形式的JSON
    elif isinstance(json_data, dict):
        # 检查是否是单个节点
        node = parse_single_json_node(json_data)
        if node:
            nodes.append(node)
        # 检查是否包含节点列表
        elif 'servers' in json_data and isinstance(json_data['servers'], list):
            for server in json_data['servers']:
                node = parse_single_json_node(server)
                if node:
                    nodes.append(node)
        # 检查其他可能的字段名
        for key in ['proxies', 'nodes', 'configs']:
            if key in json_data and isinstance(json_data[key], list):
                for item in json_data[key]:
                    node = parse_single_json_node(item)
                    if node:
                        nodes.append(node)
    
    return nodes

def parse_single_json_node(item):
    """解析单个JSON节点数据"""
    # 如果不是字典，直接返回
    if not isinstance(item, dict):
        return None
    
    # 支持Shadowsocks格式
    if ('server' in item and 'server_port' in item and 
        'method' in item and 'password' in item):
        try:
            return {
                'type': 'ss',
                'name': item.get('remarks', f"SS-{item['server']}"),
                'server': item['server'],
                'port': int(item['server_port']),
                'cipher': item['method'],
                'password': item['password'],
                'plugin': item.get('plugin', ''),
                'plugin_opts': item.get('plugin_opts', '')
            }
        except Exception as e:
            print(f"解析Shadowsocks节点失败: {str(e)}")
            return None
    
    # 支持VMess格式
    elif ('add' in item and 'port' in item and 'id' in item):
        try:
            return {
                'type': 'vmess',
                'name': item.get('ps', item.get('remarks', f"VMess-{item['add']}")),
                'server': item['add'],
                'port': int(item['port']),
                'uuid': item['id'],
                'alterId': int(item.get('aid', 0)),
                'cipher': item.get('scy', item.get('security', 'auto')),
                'tls': item.get('tls', '') == 'tls',
                'network': item.get('net', 'tcp'),
                'path': item.get('path', '/'),
                'host': item.get('host', '')
            }
        except Exception as e:
            print(f"解析VMess节点失败: {str(e)}")
            return None
    
    # 支持Trojan格式
    elif ('server' in item and 'port' in item and 'password' in item and 
          item.get('type', '').lower() == 'trojan'):
        try:
            return {
                'type': 'trojan',
                'name': item.get('remarks', f"Trojan-{item['server']}"),
                'server': item['server'],
                'port': int(item['port']),
                'password': item['password'],
                'sni': item.get('sni', item.get('peer', ''))
            }
        except Exception as e:
            print(f"解析Trojan节点失败: {str(e)}")
            return None
    
    # 支持Clash格式
    elif ('type' in item and 'server' in item and 'port' in item):
        try:
            node_type = item['type'].lower()
            if node_type in ['ss', 'vmess', 'trojan', 'vless', 'http', 'socks']:
                node = {
                    'type': node_type,
                    'name': item.get('name', f"{node_type.upper()}-{item['server']}"),
                    'server': item['server'],
                    'port': int(item['port'])
                }
                
                # 根据不同类型添加特定字段
                if node_type == 'ss':
                    node['cipher'] = item.get('cipher', 'aes-256-gcm')
                    node['password'] = item.get('password', '')
                elif node_type == 'vmess':
                    node['uuid'] = item.get('uuid', '')
                    node['alterId'] = int(item.get('alterId', 0))
                    node['cipher'] = item.get('cipher', 'auto')
                    node['tls'] = item.get('tls', False)
                    node['network'] = item.get('network', 'tcp')
                    if 'ws-path' in item:
                        node['path'] = item['ws-path']
                elif node_type in ['trojan', 'vless']:
                    node['password'] = item.get('password', '')
                    node['sni'] = item.get('sni', '')
                    
                return node
        except Exception as e:
            print(f"解析Clash节点失败: {str(e)}")
            return None
    
    return None

def download_xray_core():
    """下载Xray核心程序到当前目录 (自动适配平台)"""
    print("正在自动下载Xray核心程序...")
    is_windows = platform.system() == "Windows"
    is_64bit = platform.architecture()[0] == '64bit'
    try:
        api_url = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
        response = requests.get(api_url, timeout=30)
        release_info = response.json()
        if is_windows:
            file_keyword = "windows-64" if is_64bit else "windows-32"
        else:
            file_keyword = "linux-64" if is_64bit else "linux-32"
        download_url = None
        for asset in release_info['assets']:
            if file_keyword in asset['name'].lower() and asset['name'].endswith('.zip'):
                download_url = asset['browser_download_url']
                break
        if not download_url:
            print(f"未找到适合当前平台({file_keyword})的Xray下载链接")
            return False
        print(f"下载Xray: {download_url}")
        download_response = requests.get(download_url, timeout=120)
        download_response.raise_for_status()
        xray_dir = "./xray-core"
        platform_dir = os.path.join(xray_dir, file_keyword)
        os.makedirs(platform_dir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(download_response.content)) as z:
            z.extractall(platform_dir)
        # 自动查找解压目录下的 xray 可执行文件
        exe_name = "xray.exe" if is_windows else "xray"
        for root, dirs, files in os.walk(platform_dir):
            for file in files:
                if file == exe_name:
                    full_path = os.path.join(root, file)
                    if not is_windows:
                        os.chmod(full_path, 0o755)
                    print(f"Xray核心程序已下载并解压到 {full_path}")
                    return True
        print("[ERROR] Xray 解压后未检测到主程序")
        return False
    except Exception as e:
        print(f"下载Xray失败: {str(e)}")
        return False

def find_core_program():
    """查找Xray核心程序 (自动适配平台)"""
    global CORE_PATH
    is_windows = platform.system() == "Windows"
    is_64bit = platform.architecture()[0] == '64bit'
    xray_core_dir = "./xray-core"
    file_keyword = "windows-64" if is_windows and is_64bit else ("windows-32" if is_windows else ("linux-64" if is_64bit else "linux-32"))
    exe_name = "xray.exe" if is_windows else "xray"
    xray_platform_path = os.path.join(xray_core_dir, file_keyword, exe_name)
    if os.path.isfile(xray_platform_path) and os.access(xray_platform_path, os.X_OK if not is_windows else os.F_OK):
        CORE_PATH = xray_platform_path
        print(f"找到Xray核心程序: {CORE_PATH}")
        return CORE_PATH
    print("未找到V2Ray或Xray核心程序，准备自动下载...")
    if download_xray_core():
        if os.path.isfile(xray_platform_path) and os.access(xray_platform_path, os.X_OK if not is_windows else os.F_OK):
            CORE_PATH = xray_platform_path
            print(f"已成功下载并使用Xray核心程序: {CORE_PATH}")
            return CORE_PATH
    print("自动下载失败。请访问 https://github.com/XTLS/Xray-core/releases 手动下载并安装")
    print(f"将Xray核心程序放在 {os.path.join(xray_core_dir, file_keyword)} 目录中")
    return None

def find_available_port(start_port=10000, end_port=60000):
    """查找可用的端口"""
    while True:
        port = random.randint(start_port, end_port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(('127.0.0.1', port))
            sock.close()
            return port
        except:
            sock.close()
            continue

def generate_v2ray_config(node, local_port):
    """根据节点信息生成V2Ray配置文件，支持hysteria、reality"""
    config = {
        "inbounds": [
            {
                "port": local_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"]
                }
            }
        ],
        "outbounds": [],
        "log": {
            "loglevel": "none"
        }
    }
    if node['type'] == 'vmess':
        # 基本VMess配置
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": node['server'],
                        "port": node['port'],
                        "users": [
                            {
                                "id": node['uuid'],
                                "alterId": node.get('alterId', 0),
                                "security": node.get('cipher', 'auto')
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": node.get('network', 'tcp'),
                "security": "tls" if node.get('tls', False) else "none"
            }
        }
        
        # 添加网络特定配置，参考V2RayN的配置
        if node.get('network') == 'ws':
            outbound["streamSettings"]["wsSettings"] = {
                "path": node.get('path', '/'),
                "headers": {
                    "Host": node.get('host', node['server'])
                }
            }
        elif node.get('network') == 'h2':
            outbound["streamSettings"]["httpSettings"] = {
                "path": node.get('path', '/'),
                "host": [node.get('host', node['server'])]
            }
        elif node.get('network') == 'quic':
            outbound["streamSettings"]["quicSettings"] = {
                "security": node.get('quicSecurity', 'none'),
                "key": node.get('quicKey', ''),
                "header": {
                    "type": node.get('headerType', 'none')
                }
            }
        elif node.get('network') == 'grpc':
            outbound["streamSettings"]["grpcSettings"] = {
                "serviceName": node.get('path', ''),
                "multiMode": node.get('multiMode', False)
            }
        elif node.get('network') == 'tcp':
            if node.get('headerType') == 'http':
                outbound["streamSettings"]["tcpSettings"] = {
                    "header": {
                        "type": "http",
                        "request": {
                            "path": [node.get('path', '/')],
                            "headers": {
                                "Host": [node.get('host', '')]
                            }
                        }
                    }
                }
                
        # TLS相关设置
        if node.get('tls'):
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": node.get('sni', node.get('host', node['server'])),
                "allowInsecure": node.get('allowInsecure', False)
            }
        
        config["outbounds"] = [outbound]
    elif node['type'] == 'trojan':
        # 增强Trojan配置
        config["outbounds"] = [{
            "protocol": "trojan",
            "settings": {
                "servers": [
                    {
                        "address": node['server'],
                        "port": node['port'],
                        "password": node['password']
                    }
                ]
            },
            "streamSettings": {
                "network": node.get('network', 'tcp'),
                "security": "tls",
                "tlsSettings": {
                    "serverName": node.get('sni', node.get('host', node['server'])),
                    "allowInsecure": node.get('allowInsecure', False)
                }
            }
        }]
        
        # 添加网络特定配置
        if node.get('network') == 'ws':
            config["outbounds"][0]["streamSettings"]["wsSettings"] = {
                "path": node.get('path', '/'),
                "headers": {
                    "Host": node.get('host', node['server'])
                }
            }
    elif node['type'] == 'vless':
        # 增强VLESS配置
        config["outbounds"] = [{
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": node['server'],
                        "port": node['port'],
                        "users": [
                            {
                                "id": node['uuid'],
                                "encryption": "none",
                                "flow": node.get('flow', '')
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": node.get('network', 'tcp'),
                "security": "tls" if node.get('tls', False) else "none"
            }
        }]
        
        # 添加网络特定配置
        if node.get('network') == 'ws':
            config["outbounds"][0]["streamSettings"]["wsSettings"] = {
                "path": node.get('path', '/'),
                "headers": {
                    "Host": node.get('host', node['server'])
                }
            }
        elif node.get('network') == 'grpc':
            config["outbounds"][0]["streamSettings"]["grpcSettings"] = {
                "serviceName": node.get('path', ''),
                "multiMode": node.get('multiMode', False)
            }
            
        # TLS相关设置
        if node.get('tls'):
            config["outbounds"][0]["streamSettings"]["tlsSettings"] = {
                "serverName": node.get('sni', node.get('host', node['server'])),
                "allowInsecure": node.get('allowInsecure', False)
            }
    elif node['type'] == 'ss':
        # Shadowsocks配置
        config["outbounds"] = [{
            "protocol": "shadowsocks",
            "settings": {
                "servers": [
                    {
                        "address": node['server'],
                        "port": node['port'],
                        "method": node['cipher'],
                        "password": node['password']
                    }
                ]
            }
        }]
    elif node['type'] == 'ssr':
        # SSR暂不直接支持Xray，跳过
        return None
    elif node['type'] == 'hysteria':
        config["outbounds"] = [{
            "protocol": "hysteria",
            "settings": {
                "servers": [
                    {
                        "address": node['server'],
                        "port": node['port'],
                        "auth": node.get('auth', ''),
                        "protocol": node.get('protocol', ''),
                        "obfs": node.get('obfs', ''),
                        "alpn": node.get('alpn', ''),
                        "insecure": node.get('insecure', False)
                    }
                ]
            }
        }]
    elif node['type'] == 'reality':
        config["outbounds"] = [{
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": node['server'],
                        "port": node['port'],
                        "users": [
                            {
                                "id": node.get('uuid', ''),
                                "encryption": "none",
                                "flow": "",
                                "publicKey": node.get('publicKey', ''),
                                "shortId": node.get('shortId', ''),
                                "sni": node.get('sni', ''),
                                "fingerprint": node.get('fingerprint', ''),
                                "spiderX": node.get('spiderX', '')
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "publicKey": node.get('publicKey', ''),
                    "shortId": node.get('shortId', ''),
                    "serverName": node.get('sni', ''),
                    "fingerprint": node.get('fingerprint', ''),
                    "spiderX": node.get('spiderX', '')
                }
            }
        }]
    elif node['type'] == 'socks':
        # SOCKS配置
        outbound = {
            "protocol": "socks",
            "settings": {
                "servers": [
                    {
                        "address": node['server'],
                        "port": node['port']
                    }
                ]
            }
        }
        
        # 如果有用户名和密码，添加到配置中
        if node.get('username') and node.get('password'):
            outbound["settings"]["servers"][0]["users"] = [
                {
                    "user": node['username'],
                    "pass": node['password']
                }
            ]
            
        config["outbounds"] = [outbound]
    elif node['type'] in ['http', 'https']:
        # HTTP/HTTPS配置
        outbound = {
            "protocol": "http",
            "settings": {
                "servers": [
                    {
                        "address": node['server'],
                        "port": node['port']
                    }
                ]
            }
        }
        
        # 如果有用户名和密码，添加到配置中
        if node.get('username') and node.get('password'):
            outbound["settings"]["servers"][0]["users"] = [
                {
                    "user": node['username'],
                    "pass": node['password']
                }
            ]
            
        config["outbounds"] = [outbound]
    else:
        if DEBUG_MODE:
            print(f"警告: 节点类型 {node['type']} 可能不被完全支持，使用基本配置")
        return None
    return config

def test_node_latency(node):
    """使用核心程序测试节点延迟"""
    if not CORE_PATH:
        if DEBUG_MODE:
            print("未找到核心程序，无法进行延迟测试")
        return -1
    
    # 为测试创建临时目录
    temp_dir = tempfile.mkdtemp(prefix="node_test_")
    config_file = os.path.join(temp_dir, "config.json")
    
    # 获取一个可用端口
    local_port = find_available_port()
    
    # 生成配置文件
    config = generate_v2ray_config(node, local_port)
    if not config:
        shutil.rmtree(temp_dir)
        return -1
    
    with open(config_file, 'w') as f:
        json.dump(config, f)
    
    # 启动核心进程
    core_process = None
    try:
        # 设置代理环境变量，使用SOCKS代理
        proxies = {
            'http': f'socks5://127.0.0.1:{local_port}',
            'https': f'socks5://127.0.0.1:{local_port}'
        }
        
        # 设置与V2RayN相同的请求头
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2'
        }
        
        # 在Windows上，使用CREATE_NO_WINDOW标志隐藏控制台窗口
        startupinfo = None
        if platform.system() == "Windows":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
        
        # 启动核心程序
        core_process = subprocess.Popen(
            [CORE_PATH, "-c", config_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            startupinfo=startupinfo
        )
        
        # 等待核心程序启动
        time.sleep(3)
        
        # 测试连接延迟 - 不再使用重试机制
        start_time = time.time()
        
        # 按顺序尝试不同的测试URL
        for test_url in TEST_URLS:
            try:
                if DEBUG_MODE:
                    print(f"测试节点: {node['name']} - 尝试URL: {test_url}")
                
                response = requests.get(
                    test_url,
                    proxies=proxies,
                    headers=headers,
                    timeout=CONNECTION_TIMEOUT
                )
                
                if response.status_code in [200, 204]:
                    latency = int((time.time() - start_time) * 1000)
                    if DEBUG_MODE:
                        print(f"测试成功: {node['name']} - URL: {test_url} - 延迟: {latency}ms")
                    return latency
                else:
                    if DEBUG_MODE:
                        print(f"测试URL状态码错误: {response.status_code}")
            except Exception as e:
                if DEBUG_MODE:
                    print(f"测试失败: {test_url} - 错误: {str(e)}")
                continue  # 尝试下一个URL
        
        # 所有URL测试都失败
        if DEBUG_MODE:
            print(f"节点 {node['name']} 所有测试URL都失败")
        return -1
    
    except Exception as e:
        if DEBUG_MODE:
            print(f"测试节点 {node['name']} 时发生错误: {str(e)}")
        return -1
    
    finally:
        # 清理资源
        if core_process:
            core_process.terminate()
            try:
                core_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                core_process.kill()
        
        # 删除临时目录
        try:
            shutil.rmtree(temp_dir)
        except:
            pass

def test_latency(node):
    """测试节点延迟"""
    # 必须有核心程序才能进行测试
    if not CORE_PATH:
        print(f"未找到核心程序，无法测试节点: {node['name']}")
        return -1
    
    # 使用核心程序进行精确测试
    latency = test_node_latency(node)
    
    return latency

def process_node(node):
    """处理单个节点，添加延迟信息"""
    if not node or 'name' not in node or 'server' not in node:
        return None

    # print(f"测试节点: {node['name']} [{node['type']}] - {node['server']}:{node['port']}")
    latency = test_latency(node)
    
    # 过滤掉延迟为0ms或连接失败的节点
    if latency <= 0:
        # status = "连接失败" if latency == -1 else "延迟为0ms"
        # print(f"节点: {node['name']} ，{status}，跳过")
        return None
    
    # 更新节点名称，添加延迟信息
    node['name'] = f"{node['name']} [{latency}ms]"
    print(f"有效节点: {node['name']} ，延迟: {latency}ms")
    return node

def remove_duplicates(nodes):
    """去除重复节点"""
    unique_nodes = {}
    for node in nodes:
        try:
            key = f"{node['server']}:{node['port']}"
            if key not in unique_nodes:
                unique_nodes[key] = node
        except Exception as e:
            # print(f"处理节点 {node['name']} 时出错: {str(e)}")
            continue
    return list(unique_nodes.values())

def node_to_v2ray_uri(node):
    """将节点信息转换为V2Ray URI格式"""
    if node['type'] == 'vmess':
        config = {
            'v': '2',
            'ps': node['name'],
            'add': node['server'],
            'port': str(node['port']),
            'id': node['uuid'],
            'aid': str(node['alterId']),
            'net': node.get('network', 'tcp'),
            'type': node.get('type', 'none'),
            'tls': 'tls' if node.get('tls', False) else ''
        }
        return f"vmess://{base64.b64encode(json.dumps(config).encode()).decode()}"
    elif node['type'] == 'trojan':
        return f"trojan://{node['password']}@{node['server']}:{node['port']}?sni={node['name']}"
    elif node['type'] == 'vless':
        # 构建vless uri
        query_parts = []
        if node.get('tls'):
            query_parts.append('security=tls')
        if node.get('flow'):
            query_parts.append(f"flow={node['flow']}")
        if node.get('network'):
            query_parts.append(f"type={node['network']}")
        query_string = '&'.join(query_parts)
        return f"vless://{node['uuid']}@{node['server']}:{node['port']}?{query_string}&remarks={node['name']}"
    elif node['type'] == 'ss':
        # 构建ss uri
        userinfo = f"{node['cipher']}:{node['password']}"
        b64_userinfo = base64.b64encode(userinfo.encode()).decode()
        return f"ss://{b64_userinfo}@{node['server']}:{node['port']}#{node['name']}"
    elif node['type'] == 'ssr':
        # 构建ssr uri
        password_b64 = base64.b64encode(node['password'].encode()).decode()
        name_b64 = base64.b64encode(node['name'].encode()).decode()
        ssr_str = f"{node['server']}:{node['port']}:{node['protocol']}:{node['cipher']}:{node['obfs']}:{password_b64}/?remarks={name_b64}"
        return f"ssr://{base64.b64encode(ssr_str.encode()).decode()}"
    elif node['type'] in ['http', 'https']:
        # 构建http/https uri
        proto = 'http' if node['type'] == 'http' else 'https'
        auth = f"{node['username']}:{node['password']}@" if node['username'] else ""
        return f"{proto}://{auth}{node['server']}:{node['port']}?remarks={node['name']}"
    elif node['type'] == 'socks':
        # 构建socks uri
        auth = f"{node['username']}:{node['password']}@" if node['username'] else ""
        return f"socks://{auth}{node['server']}:{node['port']}?remarks={node['name']}"
    elif node['type'] == 'hysteria':
        # 构建hysteria uri
        auth = f"{node['auth']}@" if node.get('auth') else ""
        protocol_part = f"?protocol={node['protocol']}" if node.get('protocol') else ""
        return f"hysteria://{auth}{node['server']}:{node['port']}{protocol_part}&peer={node['name']}"
    elif node['type'] == 'wireguard':
        # 构建wireguard uri
        query_parts = []
        if node.get('private_key'):
            query_parts.append(f"privateKey={node['private_key']}")
        if node.get('public_key'):
            query_parts.append(f"publicKey={node['public_key']}")
        if node.get('allowed_ips'):
            query_parts.append(f"allowedIPs={node['allowed_ips']}")
        query_string = '&'.join(query_parts)
        return f"wireguard://{node['server']}:{node['port']}?{query_string}&remarks={node['name']}"
    return None

def get_latest_singbox_download_url():
    """自动获取 sing-box 最新稳定版 linux-amd64 下载链接"""
    api_url = "https://api.github.com/repos/SagerNet/sing-box/releases"
    try:
        resp = requests.get(api_url, timeout=30)
        releases = resp.json()
        for rel in releases:
            if not rel.get("prerelease", False):
                for asset in rel.get("assets", []):
                    if "linux-amd64.zip" in asset["name"]:
                        print(f"[sing-box] 最新稳定版: {rel['tag_name']}，下载链接: {asset['browser_download_url']}")
                        return asset["browser_download_url"]
        print("[ERROR] 未找到 sing-box 最新稳定版 linux-amd64 下载链接")
        return None
    except Exception as e:
        print(f"[ERROR] 获取 sing-box 版本信息失败: {e}")
        return None

def download_singbox_core():
    """跳过自动下载，直接使用本地sing-box内核"""
    if os.path.exists(SINGBOX_EXE):
        print(f"[sing-box] 已检测到本地内核: {SINGBOX_EXE}")
        return True
    print("[ERROR] 未找到本地 sing-box 内核，请检查路径是否正确")
    return False

def find_singbox_core():
    """直接检测本地sing-box内核路径"""
    global SINGBOX_PATH
    if os.path.exists(SINGBOX_EXE):
        SINGBOX_PATH = SINGBOX_EXE
        print(f"[sing-box] 使用本地内核: {SINGBOX_PATH}")
        return SINGBOX_PATH
    print("[ERROR] 未找到本地 sing-box 内核，请检查路径是否正确")
    return None

def generate_singbox_config(node, local_port):
    """根据节点信息生成 sing-box 配置文件（仅支持常见协议）"""
    # 这里只实现 vmess、ss、trojan、vless、hysteria、reality、socks
    out = None
    if node['type'] == 'vmess':
        out = {
            "type": "vmess",
            "tag": "proxy",
            "server": node['server'],
            "server_port": node['port'],
            "uuid": node['uuid'],
            "alter_id": node.get('alterId', 0),
            "security": node.get('cipher', 'auto'),
            "network": node.get('network', 'tcp'),
            "tls": node.get('tls', False),
            "ws_opts": {"path": node.get('path', '/')},
            "host": node.get('host', node['server'])
        }
    elif node['type'] == 'ss':
        out = {
            "type": "shadowsocks",
            "tag": "proxy",
            "server": node['server'],
            "server_port": node['port'],
            "method": node['cipher'],
            "password": node['password']
        }
    elif node['type'] == 'trojan':
        out = {
            "type": "trojan",
            "tag": "proxy",
            "server": node['server'],
            "server_port": node['port'],
            "password": node['password'],
            "sni": node.get('sni', node['server'])
        }
    elif node['type'] == 'vless':
        out = {
            "type": "vless",
            "tag": "proxy",
            "server": node['server'],
            "server_port": node['port'],
            "uuid": node['uuid'],
            "encryption": "none",
            "flow": node.get('flow', ''),
            "network": node.get('network', 'tcp'),
            "tls": node.get('tls', False)
        }
    elif node['type'] == 'hysteria':
        out = {
            "type": "hysteria",
            "tag": "proxy",
            "server": node['server'],
            "server_port": node['port'],
            "auth_str": node.get('auth', ''),
            "protocol": node.get('protocol', ''),
            "obfs": node.get('obfs', ''),
            "alpn": node.get('alpn', ''),
            "insecure": node.get('insecure', False)
        }
    elif node['type'] == 'reality':
        out = {
            "type": "vless",
            "tag": "proxy",
            "server": node['server'],
            "server_port": node['port'],
            "uuid": node.get('uuid', ''),
            "encryption": "none",
            "flow": "",
            "tls": True,
            "reality_opts": {
                "public_key": node.get('publicKey', ''),
                "short_id": node.get('shortId', ''),
                "server_name": node.get('sni', node['server'])
            }
        }
    elif node['type'] == 'socks':
        out = {
            "type": "socks5",
            "tag": "proxy",
            "server": node['server'],
            "server_port": node['port']
        }
    if not out:
        return None
    config = {
        "log": {"level": "error"},
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": local_port
            }
        ],
        "outbounds": [out]
    }
    return config

def test_node_latency_singbox(node):
    """用 sing-box 测速，返回延迟ms，失败返回-1"""
    if not SINGBOX_PATH:
        print("[sing-box] 未找到内核，跳过测速")
        return -1
    temp_dir = tempfile.mkdtemp(prefix="singbox_test_")
    config_file = os.path.join(temp_dir, "config.json")
    local_port = find_available_port()
    config = generate_singbox_config(node, local_port)
    if not config:
        shutil.rmtree(temp_dir)
        return -1
    with open(config_file, 'w', encoding='utf-8') as f:
        json.dump(config, f)
    core_process = None
    try:
        proxies = {
            'http': f'socks5://127.0.0.1:{local_port}',
            'https': f'socks5://127.0.0.1:{local_port}'
        }
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2'
        }
        startupinfo = None
        if platform.system() == "Windows":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
        core_process = subprocess.Popen(
            [SINGBOX_PATH, "run", "-c", config_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            startupinfo=startupinfo
        )
        time.sleep(3)
        start_time = time.time()
        for test_url in TEST_URLS:
            try:
                response = requests.get(
                    test_url,
                    proxies=proxies,
                    headers=headers,
                    timeout=CONNECTION_TIMEOUT
                )
                if response.status_code in [200, 204]:
                    latency = int((time.time() - start_time) * 1000)
                    return latency
            except Exception:
                continue
        return -1
    except Exception as e:
        print(f"[sing-box] 测速异常: {e}")
        return -1
    finally:
        if core_process:
            core_process.terminate()
            try:
                core_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                core_process.kill()
        try:
            shutil.rmtree(temp_dir)
        except:
            pass

def main():
    global CORE_PATH
    # 查找Xray核心
    CORE_PATH = find_core_program()
    # 查找sing-box核心
    find_singbox_core()
    all_nodes = []
    print("\n开始获取节点信息...")
    for link in links:
        print(f"\n正在处理订阅链接: {link}")
        content = fetch_content(link)
        if not content:
            print("获取失败，跳过该链接")
            continue
        nodes = extract_nodes(content)
        all_nodes.extend(nodes)
    print(f"去重前节点数量: {len(all_nodes)}")
    all_nodes = remove_duplicates(all_nodes)
    print(f"去重后节点数量: {len(all_nodes)}")
    # 保存去重后的所有节点到all.txt（仿照v2ray.txt写法）
    all_uris = []
    for node in all_nodes:
        uri = node_to_v2ray_uri(node)
        if uri:
            all_uris.append(uri)
    all_txt_path = os.path.join(os.getcwd(), "all.txt")
    try:
        all_content = '\n'.join(all_uris)
        with open(all_txt_path, "w", encoding="utf-8") as f:
            f.write(all_content)
        # 立即读取确认写入
        with open(all_txt_path, "r", encoding="utf-8") as f:
            check_content = f.read()
        if check_content.strip() == all_content.strip():
            print(f"已将 {len(all_uris)} 个去重节点保存到 all.txt 文件: {all_txt_path}")
        else:
            print(f"[ERROR] all.txt 写入后内容校验失败，请检查写入权限或路径。")
    except Exception as e:
        print(f"[ERROR] 写入all.txt失败: {e}")
    # Xray测速
    print(f"\n开始Xray测速...")
    valid_nodes = []
    failed_nodes = []
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_TESTS) as executor:
        future_to_node = {executor.submit(process_node, node): node for node in all_nodes}
        for future in as_completed(future_to_node):
            processed_node = future.result()
            if processed_node:
                valid_nodes.append(processed_node)
            else:
                failed_nodes.append(future_to_node[future])
    print(f"Xray测速完成，有效节点数量: {len(valid_nodes)}，失败节点: {len(failed_nodes)}")
    # sing-box测速补测
    print(f"\n对Xray未通过的节点用sing-box补测...")
    valid_nodes_singbox = []
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_TESTS) as executor:
        future_to_node = {executor.submit(lambda n: (n if test_node_latency_singbox(n) > 0 else None), node): node for node in failed_nodes}
        for future in as_completed(future_to_node):
            processed_node = future.result()
            if processed_node:
                valid_nodes_singbox.append(processed_node)
    print(f"sing-box补测完成，有效节点数量: {len(valid_nodes_singbox)}")
    # 合并所有可用节点
    all_valid_nodes = valid_nodes + valid_nodes_singbox
    print(f"\n最终有效节点总数: {len(all_valid_nodes)}")
    # 收集所有有效节点的URI
    valid_uris = []
    valid_uri_count = 0
    for node in all_valid_nodes:
        uri = node_to_v2ray_uri(node)
        if uri:
            valid_uris.append(uri)
            valid_uri_count += 1
    if valid_uri_count > 0:
        uri_content = '\n'.join(valid_uris)
        base64_content = base64.b64encode(uri_content.encode('utf-8')).decode('utf-8')
        with open('v2ray.txt', 'w', encoding='utf-8') as f:
            f.write(base64_content)
        print(f"\n已将 {valid_uri_count} 个有效节点以base64编码保存到 v2ray.txt 文件")
        with open('v2ray_raw.txt', 'w', encoding='utf-8') as f:
            f.write(uri_content)
        print(f"同时保存了原始文本版本到 v2ray_raw.txt 文件")
    else:
        print("\n未找到有效节点，不生成文件")

if __name__ == '__main__':
    main()
