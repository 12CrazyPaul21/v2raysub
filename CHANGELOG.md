# ChangeLog

## 0.2.2, 2024-03-02

### Fixed

- 修复未init时执行install找不到app目录

## 0.2.3, 2024-03-03

### Fixed

- trojan分享链接的security缺省为tls

## 0.3.0, 2024-03-07

### Fixed

- 修复mac环境在修改v2sub service设置后没更新服务目录下的配置文件
- 修复linux与mac环境在删除proxychains alias时，要删除的alias的名字被硬编码了，profile路径也没扩展出来，这使得删除alias会失败

### Feature

- 增加以下子命令
  - service restart：服务重启
  - node restart：临时服务重启
  - subscribe show：查看订阅
- 持久化proxy enable/disable设置
- 加入重新select时，是否复用上次配置的提示
- 增加显示proxychains alias列表
- 增加一个base节点选择（直接复用base_config的设置，默认没有配置proxy的outbound，可用来完成block域名或者向局域网其它机器提供proxy等操作）
- 增加direct和block路由规则管理子命令（基于默认base config中tag为direct和block的outbound）
- 增加plugins特性，以支持一些别的协议或者重写解析和生成配置方式

