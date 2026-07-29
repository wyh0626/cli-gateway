# White-label CLI / 企业 CLI 定制

## 中文

cli-gateway 把品牌配置固定在客户端构建产物中，把业务命令保留在服务端 Manifest 中。
这样员工不能通过运行时参数随意切换凭证命名空间，而每家公司仍能使用自己的命令名。

### 最小构建

```bash
make build-client CLI_NAME=acme VERSION=v0.3.0
./bin/acme --help
```

只设置 `CLI_NAME=acme` 时会自动生成：

| 项目 | 值 |
|---|---|
| 根命令 | `acme` |
| 环境变量 | `ACME_SERVER`、`ACME_REGION`、`ACME_TOKEN`、`ACME_INVOKER` |
| 路径覆盖 | `ACME_CONFIG_DIR`、`ACME_CACHE_DIR` |
| 默认配置目录 | `~/.config/acme`（按操作系统规则） |
| 默认缓存目录 | `~/.cache/acme`（按操作系统规则） |
| 系统 Keyring Service | `acme-cli-refresh-token` |
| User-Agent | `acme-cli/<version>` |

服务端必须使用相同名称：

```yaml
cli:
  name: acme
```

名称不一致时，客户端拒绝加载命令目录，避免错误连接到其他公司的网关。

### 高级覆盖

```bash
make build-client \
  CLI_NAME=acme \
  CLI_DISPLAY_NAME="Example Company CLI" \
  CLI_ENV_PREFIX=EXAMPLE \
  CLI_CONFIG_DIR=example-cli \
  CLI_CACHE_DIR=example-cli \
  CLI_KEYRING_SERVICE=example-cli-refresh-token \
  CLI_USER_AGENT=example-cli
```

构建值必须满足安全校验：名称和目录不能包含路径字符，环境变量前缀只能是大写
字母、数字和下划线，User-Agent 必须是合法 HTTP product token。

### OAuth 配置

CLI 的品牌名不等于 OAuth `client_id`。客户端会从 cli-gateway 的
`/.well-known/oauth-protected-resource` 获取 `client_id` 和授权服务器地址。
每家公司仍应在自己的 Hydra 或其他 IdP 中注册独立的公共客户端：

```yaml
auth:
  mode: oidc
  issuer: https://auth.example.com
  client_id: acme-cli
  audience: cli-gateway
cli:
  name: acme
```

PKCE 使用随机 loopback 端口。IdP 需要允许原生应用 loopback callback；Device
Flow 则需要 IdP 开启对应 grant。

### 从 cg 迁移到 acme

`cg` 和 `acme` 默认不会共享配置、缓存或刷新令牌。推荐迁移步骤：

1. 服务端先发布 `cli.name: acme` 的独立环境或入口。
2. 在 IdP 注册 `acme` 使用的公共 OAuth 客户端。
3. 分发 `acme` 二进制，让用户重新执行 `acme login` 和 `acme update-commands`。
4. 保留旧 `cg` 一段时间，再停止旧入口。

不要复制操作系统 Keyring 中的刷新令牌，也不要让两个品牌共用默认本地目录。

### 分发

- 对每个平台构建独立二进制并生成 SHA-256。
- 对构建产物生成 SBOM 和 provenance。
- 使用代码签名或平台公证能力签署最终客户端。
- 发布页应明确 CLI 名称、服务端地址、最低版本和升级方式。

## English

cli-gateway fixes branding in the built client while keeping business commands in
the server manifest. This prevents users from switching credential namespaces
with a runtime flag while still allowing every organization to ship its own
command name.

Build a client:

```bash
make build-client CLI_NAME=acme VERSION=v0.3.0
./bin/acme --help
```

`CLI_NAME=acme` derives the `ACME_*` environment prefix, OS-specific `acme`
configuration and cache directories, `acme-cli-refresh-token` keyring service,
and `acme-cli/<version>` User-Agent. The server manifest must use:

```yaml
cli:
  name: acme
```

Use the advanced Make variables shown in the Chinese section when a company
needs a different display name, environment prefix, local namespaces, keyring
service, or User-Agent. OAuth `client_id` remains a server-discovered value and
is deliberately independent of the executable name.

For migration, deploy a matching server entry point, register the new public
OAuth client, distribute the new binary, and require a fresh login. Do not copy
refresh tokens or share default local directories between brands.
