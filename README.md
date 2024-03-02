[![PyPI - Version](https://img.shields.io/pypi/v/v2raysub)](https://pypi.org/project/v2raysub/) [![Build Status](https://github.com/12CrazyPaul21/v2raysub/actions/workflows/build-and-test-v2sub.yml/badge.svg)](https://github.com/12CrazyPaul21/v2raysub/actions) [![MIT/Apache-2 licensed](https://img.shields.io/crates/l/lopxy.svg)](./LICENSE)

# v2raysub

v2sub 主要是为了给在纯命令的 Linux 环境使用 v2ray 提供一些辅助，比如订阅分组、切换节点配置、给 proxychains 创建别名等。虽然工具能在 Windows 和 Mac 环境使用，但是对于桌面环境，可以考虑其它选择，比如 [v2rayN](https://github.com/2dust/v2rayN)。

## 安装方法

```bash
pip install v2raysub
```

v2sub 依赖 v2ray，除了 [手动安装](https://www.v2ray.com/chapter_00/install.html) 外，也可以在安装了 v2sub 后通过以下命令尝试安装

```bash
v2sub install v2ray
# 如果网不通，可尝试指定可用的代理
v2sub install --proxy <server:port> v2ray
```

proxychains 工具不是必须的，需要的话也可以通过 v2sub 尝试安装

```bash
v2sub install proxychains
```

## 订阅分享支持的链接格式

- [x] shadowsocks（`ss://[method:]<password>@<server>:<port>[#remark]` | `ss://base64`）
- [x] trojan（`trojan://<password>@<server>:<port>[?options...}[#remark]` | `trojan://base64`）
- [x] vmess（`vmess://base64`）
- [x] http / https（订阅分组）

## 注意事项

- 确保 v2ray 和 proxychains 所在的目录已经添加到了 `PATH ` 环境变量中，使 v2sub 能够找到它们（对于Windows，如果通过 `v2sub install` 安装的话，则不需要）
- 对于 Mac 环境，由于 SIP（System Integrity Protection）特性，一些在 `/usr/bin/` 等目录中的命令不能直接走代理，比如 `/usr/bin/curl`。这可以用命令对应的参数来指定代理，像 `curl` 可以使用 `--proxy` 来指定，也可以考虑进 `Recovery` 模式执行 `csrutil disable` 来将 SIP 禁掉。

## v2ray服务启动方式

v2sub 有两种启动 v2ray 服务的模式：

1.  `v2sub node start `（临时服务）：主要是给临时使用的，不过即使 `shell` 退出了，它也会在后台运行，可以通过 `v2sub node stop` 停止
2.  `v2sub service start`（系统服务）：以系统服务方式运行，运行前需要通过 `v2sub service install` 来安装服务，默认是自启动的，对于 Linux 环境，只支持 `systemd` 类型的服务管理器

## 使用方法

> 除了下面说明外，更多使用方法可直接看 `v2sub --help`

### 1. 初始化配置

```bash
v2sub init
```

这一步是必须的，这会在家目录的 `.v2sub` 文件夹内生成一个初始的 v2ray 配置文件 `base_config.json`，里面没有 `outbounds` 的设置，在实际启动 v2ray 的时候，会根据这个文件生成对应的配置文件。

初始化之后可根据需要执行 `v2sub config edit` 来对配置文件进行修改，配置条目的说明可以看：[v2ray 配置文件](https://www.v2ray.com/chapter_02/)，修改完成之后，在 Linux 和 Mac 环境中会对 v2ray 服务自动重启，而 Windows 需要手动重启。

### 2. 订阅节点或者节点分组

```bash
# 添加
v2sub subscribe add <url>
# 更新分组
v2sub subscribe update
v2sub subscribe update --all
# 删除节点或分组
v2sub subscribe delete
v2sub subscribe delete --all
# 纯解析节点或分组，不会添加到列表中
v2sub subscribe parse <url>
```

url 可以是单个节点（比如： `ss://...`），也可以是分组订阅链接（比如：`https://xxx.com/subscribe?token=xxx`），订阅分组需要执行 http 请求，如果网不通可以指定可用的代理

```bash
v2sub subscribe --proxy <server:port> add <url>
```

### 3. 选择节点

在启动临时服务或者安装系统服务前都得先选择一个节点以生成对应的 v2ray 配置文件，这两种模式选择节点的方法分别是：

1. `v2sub node select`
2. `v2sub service select`

如果订阅列表中有独立节点和分组，会有类似下面的选择提示：

```bash
# anonymous内是独立节点列表，groups则是分组列表
choose subscribe type:
 » anonymous
   groups
   <Cancel>
```

**notes: **在服务启动之后也可以重新执行 `select` 来切换节点

### 4. 启动临时服务

```bash
# 启动
v2sub node start
# 停止
v2sub node stop
# 查看运行状态
v2sub node status
# 切换节点
v2sub node select
```

默认端口号：

- sock5: 23338
- http: 23339

### 5. 安装和启动 v2sub 系统服务

```bash
# 安装服务（Windows环境这一步需要编译服务，可能需要些时间）
v2sub service install
# 启动服务
v2sub service start
# 停止服务
v2sub service stop
# 查看服务运行状态
v2sub service status
# 切换节点
v2sub service select
# 卸载服务
v2sub service uninstall
```

默认端口号：

- sock5: 22338
- http: 22339

### 6. 应用代理

#### a. shell 内临时生效

```bash
# linux shell
export http_proxy='http://127.0.0.1:<端口号>'
export https_proxy='http://127.0.0.1:<端口号>'

# powershell
$env:http_proxy='http://127.0.0.1:<端口号>'
$env:https_proxy='http://127.0.0.1:<端口号>'

# cmd
set http_proxy=http://127.0.0.1:<端口号>
set https_proxy=http://127.0.0.1:<端口号>
```

#### b. proxychains 别名

```bash
# 执行后会提示你选择应用的是临时服务还是系统服务模式，并提供别名
v2sub proxychains alias
# 删除别名
v2sub proxychains alias --delete <别名>
```

创建别名之后，在 Windows 环境需要重启你的 powershell 或者 cmd，Linux 或 Mac 需要执行 `source <shell配置文件>` 来使别名生效。

这只是创建一个 proxychains 的配置文件和命令别名，不会对 v2ray 服务运行有影响，使用的时候要确保对应的服务运行中。

```bash
# 比如创建了一个别名为vproxy，在确保对应的服务运行后，可以这样使用
vproxy curl https://ipinfo.io/ip
```

#### c. 系统代理设置

对于 Windows 和 Mac 执行以下命令可以启用或禁用系统代理设置，Windows 是修改 IE 的 http 代理设置，Mac 则是修改网络接口的 http 和 socks 设置。对于 Linux，由于发行版众多，v2sub 的目标也不是桌面环境，所以不提供这个设置，有需要的话手动设置。

```bash
# 启用
v2sub config proxy enable
# 禁用
v2sub config proxy disable
```

#### d. 允许局域网连接

使用以下两个命令可以允许或禁止其它机器连接对应的代理服务，为了安全起见，修改之后请手动添加或删除防火墙规则。

```bash
# 允许
v2sub config lan allow
# 禁止
v2sub config lan disallow
```





