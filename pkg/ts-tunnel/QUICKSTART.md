# TS-Tunnel 快速开始指南

## 简介

TS-Tunnel 是 tsctl 项目中基于 mTLS 的自定义传输协议，提供安全、灵活的远程 Docker 访问能力。

## 前置要求

1. **远程主机**：已安装并运行 `guest` agent
2. **TLS 证书**：客户端证书和密钥（可选，用于 mTLS）
3. **网络连通性**：客户端可访问服务器的 443 端口（或自定义端口）

## 快速开始

### 1. 准备 TLS 证书（可选）

对于开发环境，可以跳过 TLS 验证（使用 `--ts-insecure` 标志）。生产环境建议使用证书。

### 2. 启动 Guest Agent

在远程主机上启动 guest agent：

```bash
# 默认端口 8080
guest

# 或指定端口
guest --port 9090
```

Guest agent 会监听 HTTP 请求，提供命令执行和文件拷贝端点。

### 3. 启动 tsctl 代理

#### 方式 A：使用 mTLS（推荐）

```bash
tsctl start \
  --listen 127.0.0.1:2375 \
  --ts-server containers.tinyscale.net:443 \
  --ts-cert /path/to/client.crt \
  --ts-key /path/to/client.key \
  --ts-ca /path/to/ca.crt \
  --remote-docker unix:///var/run/docker.sock
```

#### 方式 B：跳过 TLS 验证（仅开发）

```bash
tsctl start \
  --listen 127.0.0.1:2375 \
  --ts-server remote-host:8080 \
  --ts-insecure \
  --remote-docker unix:///var/run/docker.sock
```

### 4. 使用 Docker CLI

```bash
# 配置 Docker CLI
export DOCKER_HOST=tcp://127.0.0.1:2375

# 测试连接
docker info

# 运行容器（自动端口转发和文件同步）
docker run -d -p 8080:80 -v $(pwd):/app nginx

# 查看容器
docker ps
```

## 生成测试证书

仅用于开发和测试环境：

```bash
# 生成 CA
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
  -keyout ca.key -out ca.crt \
  -subj "/CN=TinyscaleCA"

# 生成服务器证书
openssl req -newkey rsa:4096 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=containers.tinyscale.net"

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 \
  -extfile <(echo "subjectAltName=DNS:containers.tinyscale.net,DNS:*.containers.tinyscale.net")

# 生成客户端证书
openssl req -newkey rsa:4096 -nodes \
  -keyout client.key -out client.csr \
  -subj "/CN=client"

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt -days 365
```

  -CAcreateserial -out client.crt -days 365
```

## URL 格式详解

### 端口转发 URL

格式：
```
tstunnel://server-host:port/tcp:target-address?cert=...&key=...&ca=...
```

示例：
```bash
# 转发本地 8080 到远程 localhost:8080
tstunnel://containers.tinyscale.net:443/tcp:localhost:8080?cert=/certs/client.crt&key=/certs/client.key&ca=/certs/ca.crt
```

### 文件同步 URL

格式：
```
tstunnel://server-host:port/remote/path?cert=...&key=...
```

示例：
```bash
# 同步到远程 /app 目录
tstunnel://containers.tinyscale.net:443/app?cert=/certs/client.crt&key=/certs/client.key
```

### URL 参数说明

| 参数 | 必需 | 说明 | 示例 |
|------|------|------|------|
| `server-host:port` | ✅ | 服务器地址 | `containers.tinyscale.net:443` |
| `cert` | ⚪ | 客户端证书路径 | `/path/to/client.crt` |
| `key` | ⚪ | 客户端私钥路径 | `/path/to/client.key` |
| `ca` | ⚪ | CA 证书路径 | `/path/to/ca.crt` |
| `insecure` | ⚪ | 跳过 TLS 验证 | `insecure=true` |

**注意**：
- `cert` 和 `key` 必须同时提供或同时省略
- 如果省略证书，端口默认为 80；否则默认为 443
- `insecure=true` 仅用于开发，生产环境不推荐

## 使用场景

### 场景 1：本地开发，远程 Docker

```bash
# 启动代理
tsctl start --listen :2375 --ts-server dev-host:8080 --ts-insecure

# 设置环境变量
export DOCKER_HOST=tcp://localhost:2375

# 像使用本地 Docker 一样工作
docker build -t myapp .
docker run -p 3000:3000 -v $(pwd):/workspace myapp
```

### 场景 2：多环境管理

```bash
# 开发环境
alias docker-dev='DOCKER_HOST=tcp://localhost:2375 docker'

# 生产环境
alias docker-prod='DOCKER_HOST=tcp://localhost:2376 docker'

# 使用
docker-dev ps
docker-prod ps
```

### 场景 3：远程命令执行

```bash
# 执行单条命令
tsctl host-exec --server-addr remote:8080 --insecure -- ls -la

# 执行脚本
tsctl host-exec --server-addr remote:8080 --insecure -- bash -c "cd /app && ./deploy.sh"

# 带环境变量
tsctl host-exec \
  --server-addr remote:8080 \
  --insecure \
  -e "ENV=production" \
  -e "DEBUG=false" \
  -- printenv
```

## 常见问题

## 常见问题

### Q1: 连接失败 - 证书错误

```
Error: failed to establish TLS connection: x509: certificate signed by unknown authority
```

**解决方案**：
- 确保使用正确的 CA 证书（`--ts-ca`）
- 或在开发环境使用 `--ts-insecure`

### Q2: Guest agent 无响应

```
Error: connection refused
```

**解决方案**：
1. 检查 guest agent 是否运行：`ps aux | grep guest`
2. 检查端口是否正确
3. 检查防火墙规则

### Q3: 端口转发不生效

**检查步骤**：
1. 查看 tsctl 日志，确认转发会话已创建
2. 使用 `docker ps` 确认容器正在运行
3. 测试本地端口：`curl localhost:8080`

### Q4: 文件同步不工作

**检查步骤**：
1. 确认本地路径存在：`ls -la /local/path`
2. 查看 tsctl 日志中的同步会话状态
3. 检查远程主机上的文件：使用 `host-exec` 执行 `ls`

### Q5: 证书验证失败

```
Error: x509: certificate is valid for containers.tinyscale.net, not abc.containers.tinyscale.net
```

**解决方案**：
- 确保服务器证书包含正确的 SAN（Subject Alternative Name）
- 使用通配符证书：`*.containers.tinyscale.net`
- 或使用 `--ts-insecure` 跳过验证（仅开发）

## 性能优化

### 1. 减少连接开销

当前每个操作建立新连接，未来版本将支持连接池。

### 2. 调整超时设置

在代码中可配置超时参数（未来将暴露为 CLI 参数）。

### 3. 使用本地证书

将 CA 证书添加到系统信任存储，减少验证开销：

```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt

# Linux
sudo cp ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

## 安全最佳实践

1. ✅ **使用强密钥**：至少 2048 位 RSA 或 256 位 ECDSA
2. ✅ **定期轮换证书**：建议每 90 天轮换
3. ✅ **保护私钥**：
   ```bash
   chmod 600 client.key
   chmod 600 server.key
   ```
4. ✅ **限制证书权限**：使用证书扩展限制用途
5. ✅ **监控和审计**：记录所有连接和操作

