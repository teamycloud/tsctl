# TS-Tunnel (mTLS TCP Tunnel) 实现文档

## 概述

TS-Tunnel 是为 tsctl 项目实现的基于 mTLS 的 TCP 隧道传输协议，用于替代传统 SSH 作为远程通信机制。它集成了 Mutagen 的转发和同步功能，为 Docker 远程访问提供安全、灵活的传输层。

## 核心特性

- ✅ **mTLS 双向认证** - 客户端和服务器相互验证
- ✅ **SNI 路由支持** - 通过 SNI 区分不同远程主机
- ✅ **与 Mutagen 深度集成** - 支持端口转发和文件同步
- ✅ **HTTP UPGRADE 机制** - 建立原始 TCP 流
- ✅ **灵活的证书管理** - 支持自定义 CA 和证书
- ✅ **TLS 配置可选** - 支持开发时跳过验证

## 架构设计

```
┌────────────────┐           ┌─────────────────────┐           ┌──────────────┐
│  tsctl Client  │  mTLS     │  TS-Tunnel Server   │           │ Remote Host  │
│                ├──────────→│  (containers.ts.net)│──────────→│  + guest     │
│  - Transport   │           │  - SNI Router       │           │  + Docker    │
│  - Protocols   │           │  - HTTP UPGRADE     │           └──────────────┘
└────────────────┘           └─────────────────────┘
       │
       ├─ agent-transport/     → Mutagen Transport 实现
       ├─ forwarding-protocol/ → 端口转发协议处理器
       └─ synchronization-protocol/ → 文件同步协议处理器
```

## 组件说明

### 1. URL 解析 (`url.go`)

解析 `ts://` URL 格式：

```
ts://server-host:port/path?cert=...&key=...&ca=...&insecure=true
```

**参数说明：**
- `server-host:port` - 服务器地址（支持自动端口推断）
- `path` - 目标路径（转发或同步）
- `cert` - 客户端证书路径（可选，与 key 配对）
- `key` - 客户端私钥路径（可选，与 cert 配对）
- `ca` - CA 证书路径（可选）
- `insecure` - 跳过 TLS 验证（仅开发用）

**关键函数：**
- `ParseTSTunnelURL()` - 解析 URL 并转换为 Mutagen URL 结构
- `UseTLS()` - 判断是否使用 TLS
- `IsTLSPort()` - 判断端口是否为 443

### 2. Agent Transport (`agent-transport/`)

实现 Mutagen 的 `agent.Transport` 接口，提供底层传输能力。

**transport.go:**
```go
type tstunnelTransport struct {
    serverAddr string
    certFile   string
    keyFile    string
    caFile     string
    insecure   bool
    tlsConfig  *tls.Config
    prompter   string
}
```

**核心方法：**
- `Copy(localPath, remoteName string)` - 文件上传到远程
  - 使用 `/tinyscale/v1/host/copy?path=` 端点
  - 支持 HTTP POST with streaming body
  
- `Command(command string)` - 执行远程命令
  - 调用 tsctl 的 `host-exec` 子命令
  - 通过 `/tinyscale/v1/host/command` 端点
  - 使用 HTTP UPGRADE 建立 TCP 流
  
- `ClassifyError()` - 错误分类
  - 识别连接错误、agent 未找到等情况

**tls.go:**

TLS 配置构建器，简化证书加载：

```go
tlsConfig := NewTLSConfigBuilder().
    WithClientCertificate(certFile, keyFile).
    WithCACertificate(caFile).
    WithServerName(serverName).
    Build()
```

### 3. Forwarding Protocol (`forwarding-protocol/`)

实现 Mutagen 的 `forwarding.ProtocolHandler` 接口，处理端口转发。

**工作流程：**
1. 解析目标地址（如 `tcp:localhost:8080`）
2. 创建 tstunnel transport
3. 通过 Mutagen agent 建立连接
4. 创建 remote endpoint 进行转发

**注册：**
```go
func init() {
    forwarding.ProtocolHandlers[ts_tunnel.Protocol_Tstunnel] = &ProtocolHandler{}
}
```

### 4. Synchronization Protocol (`synchronization-protocol/`)

实现 Mutagen 的 `synchronization.ProtocolHandler` 接口，处理文件同步。

**工作流程：**
1. 解析同步路径
2. 创建 tstunnel transport
3. 通过 Mutagen agent 建立连接
4. 创建 remote endpoint 进行同步

**注册：**
```go
func init() {
    synchronization.ProtocolHandlers[ts_tunnel.Protocol_Tstunnel] = &ProtocolHandler{}
}
```

## 与 Guest Agent 的交互

TS-Tunnel 依赖远程主机上的 guest agent 提供以下端点：

### 1. `/tinyscale/v1/host/command`
- **方法**: POST
- **用途**: 命令执行
- **流程**:
  1. 客户端发送 HTTP UPGRADE 请求（带命令 JSON）
  2. Guest 返回 `101 Switching Protocols`
  3. 连接升级为 TCP 流
  4. 双向代理 stdin/stdout

### 2. `/tinyscale/v1/host/copy`
- **方法**: POST
- **用途**: 文件上传
- **参数**: `?path=/remote/file/path`
- **流程**:
  1. 客户端发送文件内容（可选 gzip 压缩）
  2. Guest 接收并写入指定路径
  3. 返回 200 OK

在运行远程主机上的 `guest` agent 时，要把工作目录设置为相对 `.mutagen` 的上级目录。比如 `/home/alpine`。否则将出现在执行时，找不到 mutagen agent 可执行文件的问题。

## 使用示例

### 在 tsctl 中使用

```bash
# 启动代理
tsctl start \
  --listen 127.0.0.1:2375 \
  --ts-server containers.tinyscale.net:443 \
  --ts-cert /path/to/client.crt \
  --ts-key /path/to/client.key \
  --ts-ca /path/to/ca.crt \
  --remote-docker unix:///var/run/docker.sock
```

### URL 格式示例

**端口转发：**
```
ts://containers.tinyscale.net:443/tcp:localhost:8080?cert=/path/to/client.crt&key=/path/to/client.key
```

**文件同步：**
```
ts://containers.tinyscale.net:443/app/data?cert=/path/to/client.crt&key=/path/to/client.key&ca=/path/to/ca.crt
```

### 编程使用

```go
// 创建 transport
transport, err := tstunneltransport.NewTransport(tstunneltransport.TransportOptions{
    ServerAddr: "containers.tinyscale.net:443",
    CertFile:   "/path/to/client.crt",
    KeyFile:    "/path/to/client.key",
    CAFile:     "/path/to/ca.crt",
    Insecure:   false,
    Prompter:   prompter,
})

// 通过 Mutagen agent 拨号
stream, err := agent.Dial(logger, transport, agent.CommandForwarder, prompter)
defer stream.Close()
```

3. **低优先级**
   - [ ] 添加 HTTP/2 支持
   - [ ] 实现监控和日志
   - [ ] 性能优化

## 文档链接

- **[完整实现文档](IMPLEMENTATION.md)** - 详细的架构和实现说明
- **[快速开始指南](QUICKSTART.md)** - 使用示例和故障排查

## 总结

本实现提供了一个完整的 mTLS TCP 隧道传输层框架，可以替代 SSH 用于 Mutagen 的所有主要功能。虽然还有一些待完成的集成工作（主要是 protobuf 定义和服务器端实现），但核心传输层代码、protocol handlers 和文档已经完成，为进一步开发奠定了坚实的基础。

主要成就：
- ✅ 完整的 transport 层实现
- ✅ Forwarding 和 Synchronization protocol handlers
- ✅ TLS 配置工具
- ✅ 详细的文档和使用指南

