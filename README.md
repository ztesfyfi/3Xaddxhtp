# 3x-ui VLESS XHTTP H2/H3 批量添加脚本

本项目用于在**已有的 3x-ui** 中批量新增 VLESS + XHTTP 入站，不卸载、不升级、不覆盖现有入站。

## 一键执行

在 3x-ui 服务器上以 root 执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ztesfyfi/3Xaddxhtp/main/install.sh)
```

默认自动新增 **5 组**，共 **10 个入站**。每组 H2/H3 共用一个 UUID，不同组使用不同 UUID。

## 自动化规则

- 自动识别 3x-ui 数据库、面板端口/路径、TLS 域名、证书和私钥。
- 每次运行随机分配连续 5 个 UDP 端口（H3）和连续 5 个 TCP 端口（H2）。
- 检查数据库现有入站端口，并尝试绑定系统端口。
- 每次运行自动生成唯一节点名称前缀和 UUID。
- XHTTP 路径为 `/xhttp/01` 至 `/xhttp/05`。
- 成功后输出 10 条 VLESS 分享链接。
- 创建前备份数据库到 `/root/x-ui-before-xhttp-batch-时间戳.db`。
- 不修改 Hiddify，不使用 80/443，不自动修改防火墙规则。

## 无人值守授权

脚本不读取、不询问面板用户名、密码或 2FA。它只支持具有完整 `api_tokens` 表及 `scope`、`expires_at` 字段的 3x-ui 数据库：脚本在本机创建临时 `node-sync` API Token，使用 Bearer Token 调用面板 API，退出时删除临时令牌。

若当前版本缺少上述结构，脚本会停止；不会自动建表、升级数据库或退回到明文密码登录。

## 只检查，不创建

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ztesfyfi/3Xaddxhtp/main/install.sh) --check
```

## 注意

1. 需要 root 权限，以及 `curl`、`python3`、`openssl`、`ss`、`systemctl`。
2. 脚本只检查本机端口占用；云服务商安全组/上游防火墙仍需按输出开放对应 TCP/UDP 端口。
3. API 中途失败时，已成功创建的入站会保留，不会自动删除。失败后先检查 3x-ui 入站列表及备份，再决定是否重试。
4. API 返回创建成功不等于外网链路已验证；H2/H3 仍需在实际客户端测试。
