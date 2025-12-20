
Remote Docker Agent: 可识别 Docker API 的 HTTP 代理
==================

## 概述

本项目是一个迷你代理程序，可将本地 Docker API 调用代理到远程 SSH 主机，以解决以下两个挑战：

* 自动端口转发

* 本地 → 远程文件同步

它侦听与 Docker Engine API 兼容的本地端口，收到调用之后，会通过 SSH 将请求转发到远程 Docker  Daemon 进行处理，并通过以下方式解决上述两个问题：

1. 自动端口转发

    1. 检测 -p 8080:80

    2. 创建 SSH 隧道

    3. 公开本地端口

    4. 重写 Docker API 请求以绑定远程端口

    5. 在容器运行期间保持隧道活跃

2. 本地 → 远程文件同步

    1. 检测 -v ./src:/app

    2. 通过 SFTP 或 rsync-over-SSH 上传文件

    3. 将挂载重写到远程临时目录

    4. 可选地监视更改并增量同步


项目仍在开发中，尚未准备好用于生产环境。

## 架构

`pkg/tcp_agent` 包提供了一个支持 HTTP 的 TCP 代理，通过 SSH 隧道转发 Docker API 流量，并具有选择性请求拦截功能。

```
┌─────────────┐       ┌──────────────┐       ┌─────────┐       ┌──────────────┐
│ Docker CLI  │──TCP─→│  TCP Proxy   │──SSH─→│ Remote  │──────→│ Docker       │
│             │       │  (HTTP-Aware)│       │ Host    │       │ Daemon       │
└─────────────┘       └──────────────┘       └─────────┘       └──────────────┘
                            │
                            ├─ Parse HTTP requests
                            ├─ Intercept specific endpoints
                            ├─ Dump request/response
                            ├─ Handle Keep-Alive
                            └─ Detect protocol upgrades
```


首先 agent 在本地监听，例如 localhost:23750。

然后在 Docker CLI 里通过环境变量把其目标主机指向 DOCKER_HOST=tcp://localhost:23750 （还可以使用 `docker context` 系列命名来切换）

代理程序解析传入的 Docker API 请求。

对于 POST /containers/create：

* 解析 HostConfig.PortBindings → 设置 SSH 端口转发。

* 解析 HostConfig.Binds → 将本地路径同步到远程临时目录并重写。

对于其他请求路径 → 通过 Docker API over SSH 传递到远程。

## 功能特性

- **SSH 传输**: 通过 SSH 隧道安全访问 Docker API
- **HTTP Keep-Alive 支持**: 在同一 TCP 连接上处理多个 HTTP 请求
- **选择性拦截**: 解析和拦截特定的 Docker API 调用（例如容器创建）
- **协议升级检测**: 自动切换到透明 TCP 模式以支持升级连接（attach、exec）
- **透明回退**: 对非 HTTP 流量使用原始 TCP 代理
- **Unix Socket 支持**: 通过 Unix socket 或 TCP 连接到远程主机上的 Docker

## 使用方法

### 命令行示例

```bash
# 构建示例
go build -o remote-docker-agent ./cmd/main.go

# 使用 SSH 传输运行
./remote-docker-agent \
  --listen 127.0.0.1:2375 \
  --ssh-user root \
  --ssh-host remote.example.com:22 \
  --ssh-key ~/.ssh/id_rsa \
  --remote-docker unix:///var/run/docker.sock

# 使用代理的 Docker CLI
export DOCKER_HOST=tcp://127.0.0.1:2375
docker ps
docker run -it hello-world
```

### 配置字段

- **`ListenAddr`**: 本地监听地址（例如 `"127.0.0.1:2375"`）
- **`SSHUser`**: 远程连接的 SSH 用户名（例如 `"root"`）
- **`SSHHost`**: SSH 主机和端口（例如 `"remote.example.com:22"`）
- **`SSHKeyPath`**: SSH 私钥路径（例如 `"/home/user/.ssh/id_rsa"`）
- **`RemoteDocker`**: 远程 Docker socket URL：
    - Unix socket: `"unix:///var/run/docker.sock"`
    - TCP: `"tcp://127.0.0.1:2375"`

你需要一个可通过 SSH 访问的远程 Docker 守护进程，通常是：

SSH: user@remote-host

Docker: unix:///var/run/docker.sock on remote


## 开发计划

- 支持 WebSocket/劫持连接（exec、attach、logs -f）
- 自动端口转发设置（完整处理 nat.Port 类型和多端口映射），跟踪每个容器的端口转发并在停止时关闭它们。
- 为绑定挂载提供卷路径转换，支持真实的 SFTP 同步、增量更新和忽略模式：包括跨操作系统（Windows vs Linux）的正确本地/远程路径检测。
- 健壮的 SSH 连接池和重用。
- 多租户映射：context → remote host → SSH key → Docker daemon。
- 网络桥接：访问目标虚拟机底层的整个组织网络


## Docker API 开发中的注意事项

启动容器过程中有五个关键 Docker API：

1. `HEAD /_ping` 检测服务的状态，获取基本信息，比如支持的 API 版本等
1. `POST /v1.45/containers/create` 创建新的容器
1. `POST /v1.45/containers/<container_id>/attach` 附加到新创建的容器
1. `POST /v1.45/containers/<container_id>/wait` 等待容器结束
1. `POST /v1.45/containers/<container_id>/start` 启动新创建的容器

这几个请求各有特点，而且在代理过程中需要特别注意：

1. **在分析请求时，需要注意同一个连接中的多个 HTTP 请求。** 服务器是 HTTP 1.1 的，虽然没有明确的 Keep-Alive 响应头，但默认是会尽可能地复用连接的。已经观察发现，`create` 这个请求作为第二个请求，通常就是复用的 `_ping` 这个第一个请求所在的连接。

2. **注意连接升级** `attach` 这个请求带有 `Upgrade: tcp`，服务器收到请求之后会先返回 `HTTP/1.1 101 UPGRADED` 响应，然后就切换为一个原生的 tcp 连接了（类似于 websocket，但更彻底）。

3. **注意长连接** `wait` 这个请求明显是用来等待容器结束的，因此响应头里包含 `Transfer-Encoding: chunked`。它是一个长连接，不能像对待普通问答式 HTTP 那样去读取它所有的 Response.Body，不然就会卡住。

4. **注意处理流程** `start` 这个请求似乎一定是要在 `wait` 的响应头收到之后才发出的。因此如果 3 中没能正确处理避免卡住的情况，就会导致 `start` 请求不会发出。具体表现就是 `docker run` 命令卡住不动了。实际上容器已创建出来，却没有启动。




