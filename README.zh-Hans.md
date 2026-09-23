# Automic Vault

[English](README.md) · [简体中文](README.zh-Hans.md)

**CLI 的安全出了问题。我们从工具的打包与分发层着手修复。**

我创造了 Homebrew。现在，我要解决智能体使用它时带来的问题。

—— [Max Howell](https://mxcl.dev/)

你安装工具是为了完成工作。但工具的凭证往往存放在文件或凭证辅助程序中，其他以你的身份运行的代码也能读取。智能体也继承了这些访问权限。

Automic Vault 加固 macOS 上受支持的 CLI 工具。AV 了解受支持命令如何使用凭证，并按敏感程度对操作分类。你可以预先为各个应用和工具设置访问级别，减少批准提示，而不必授予不受限制的权限。未知操作仍需人工批准。

我们将暴露的凭证移入钥匙串，并改变工具请求凭证的方式。你继续使用原有命令；AV 在应用受保护的凭证前检查完整操作。

&nbsp;


## 快速开始

下载[最新版本][latest release]，或通过 Homebrew 安装：

```sh
brew install --cask automic-vault/isotopes/automic-vault
open /Applications/Automic\ Vault.app
```

扫描暴露的凭证，加固一个受支持的工具，然后验证结果：

```sh
av scan   # 或打开应用
av harden gh
av doctor gh
```

> [!TIP]
> 对于加固程序无法覆盖的场景，Automic Vault 还提供已认可脚本（Blessed Scripts）、启动器应用包（Launcher Bundles）、Secret 代理和 Secret 直接访问。请参阅[选择适合的机制](docs/choosing-a-mechanism.md)。

&nbsp;

# 产品概览

## 检测器

Automic Vault 持续检查 100 多种开发工具配置中的凭证暴露路径和隐患，包括明文凭证、访问控制宽松的钥匙串项目，以及环境中可直接调用的凭证辅助程序。每项发现都包含缓解建议。

检测器只检查环境，不修改配置，也不请求 Secret。扫描未发现问题，只代表受支持的检测器没有发现问题，不能证明你的机器安全。

[检测范围与结果解读](docs/tool-hardening.md)

## 加固程序

加固程序将受支持的凭证移入 macOS 数据保护钥匙串，由 Automic Vault 保管，并配置工具的授权关卡（Authorization Gate）。根据工具的不同，加固可能使用凭证辅助程序、包装器或 Isotope。Isotope 是与 Automic Vault 兼容的工具构建版本。

`av doctor` 验证 Automic Vault 安装的保护措施。

> [!NOTE]
> 我们的加固程序处于业界领先水平。
> AWS 加固为常规命令提供短期凭证；
> Docker 加固移除环境中的注册表凭证辅助程序访问路径。
> Homebrew 的执行关卡控制受支持的操作，即使这些操作不涉及 Secret。

> [!IMPORTANT]
> 加固程序本身就证明了加固的必要性：如果你的凭证*尚未处于暴露状态*，我们就无法将它们迁移到 Automic Vault。

[加固、验证与 AWS/Docker 凭证交接](docs/tool-hardening.md)

## 授权关卡

Automic Vault 在操作实际运行的 Mac 上检查已验证启动器、工具、目标、命令、参数、工作目录、Secret 名称及选定值的来源，然后决定是否允许完整操作。

在**只读**访问级别下，同一个 GitHub 令牌会得到三种决定：

```text
gh issue list     → 自动授权
gh issue create   → 需要人工批准
gh auth token     → Secret 披露；需要人工批准
```

每个关卡采用默认访问级别，或针对已验证启动器的专属规则。**写入权限**允许已识别的读取和写入操作；Secret 披露和高权限凭证使用仍需要人工批准。任何访问级别下，未知操作都需要人工批准。

<img src="./docs/img/authorization-gate-v4.jpg" alt="Automic Vault 授权关卡" style="width: 589px; height: auto" />

Automic Vault 控制凭证交接。目标收到 Secret 后，就能控制该 Secret。

> [!TIP]
> 将授权关卡的默认级别设为：需要批准。
> 给智能体：只读权限。
> 给终端：写入权限。
>
> 也可以考虑将终端设为只读，并花些时间配置已认可脚本，减少频繁批准带来的疲劳。
>
> 对于 `npm i` 这类易受供应链攻击影响的操作，请在没有自动授权权限、也没有 macOS TCC 权限的独立终端中运行。

[访问级别、批准与设备锁定时的行为](docs/authorization.md)

### 临时访问授权

符合条件的 Codex 任务或 Claude Code 会话可以请求**允许写入 10 分钟…**。这项内存中的授权只覆盖一个已验证启动器、一个工具专属关卡和一个智能体任务。可见的授权栏让你增加十分钟、暂停访问权限及其倒计时，或结束授权。

<img src="./docs/img/temporary-write-access.png" alt="Automic Vault 临时写入权限控件" style="width: 589px; height: auto" />

任务标识符是可伪造的范围限制标签；身份边界仍是已验证启动器。临时授权不包括 Secret 直接访问、Secret 修改、高权限凭证使用、Secret 披露或未知操作。

> [!TIP]
> 这样可以让智能体平时保持只读权限，再按任务批准临时提权。

[授权范围、到期与控制](docs/authorization.md#temporary-access-grants)

### 触控 ID 批准

要求在 Mac 上通过触控 ID 执行允许操作。每次批准都为该确定请求重新进行生物识别验证，不提供密码、Apple Watch 或指针操作的后备批准方式。触控 ID 需要活跃的 Mac 用户会话和未休眠的显示器，可与 iPhone 批准同时使用。

[启用触控 ID 批准](docs/authorization.md#touch-id-approval)

### iPhone 批准

通过同一 iCloud 钥匙串账户下符合条件的 iPhone，批准已登记 Mac 上的操作。每台 Mac 在本地保管 Secret、维护策略、执行授权并记录授权历史；iPhone 不会收到 Secret 值。

启用 iPhone 批准后，该 Mac 不再提供通过指针或键盘执行的允许操作。单独启用的触控 ID 批准仍可用于批准请求。

> [!WARNING]
> 手机未启用生物识别保护时，iPhone 镜像和**在 Mac 上显示**可能把批准控件带回 Mac。只要智能体能够操控该 Mac，就应禁用这些功能，或在每台符合条件的 iPhone 上要求使用面容 ID 或触控 ID。

[登记、通知与账户级恢复](docs/authorization.md#iphone-approval) · [通过 TestFlight 加入 iPhone 公开测试](https://testflight.apple.com/join/cfnDU5kM)

### 授权历史

查看允许和拒绝的请求、涉及的操作与软件，以及决定的来源。Automic Vault 在释放 Secret 前，持久化并验证获准 Secret 使用的记录；记录失败就拒绝释放。

```sh
$ av history
$ av history --since 7d --json
```

每次读取都需要人工批准，除非你在设置中为该确切的已验证启动器授予了授权历史访问权限。这与 `av list` 的 Secret 名称访问权限是两个独立设置。无法验证的启动器不能使用这项授权，仍需人工批准。读取操作本身也会出现在返回的历史记录中。

历史记录保存在本地，作为加密行存储在一个 SQLite 文件中，加密密钥保存在数据保护钥匙串内。可查看的记录最多保留 30 天，加密记录载荷最多 25 MiB，以先达到的上限为准。响应超过 1 MiB 时会失败，不会截断；此时请缩小查询时间范围。历史记录不具备防篡改保证，也不是完整的取证日志。

[授权历史及其限制](docs/authorization.md#authorization-history)

## 已验证启动器

选择哪些终端、IDE、智能体或符合条件的独立 CLI 可以获得权限。Automic Vault 在每次请求中检查存活启动器的代码身份和运行时保护。启动器专属策略绑定的正是该身份。

代码签名证明身份和完整性，不证明意图。身份或运行时检查失败会阻止自动授权。存在厂商签名版本时，应优先使用；给解释器签名并不能验证它加载的脚本、依赖或插件。

[启动器资格与厂商签名工具](docs/signed-cli-launchers.md)

### 启动器应用包

对于未签名的单文件 Mach-O CLI，Automic Vault 可以为可执行文件创建快照，将其放入启用强化运行时的已签名启动器应用包，并建立 root 所有的命令链接。每次授权都会重新验证已登记的版本、载荷、签名和运行时保护状态。更改或重新签名后，请求会被直接拒绝。

启动器应用包为打包的代码建立身份，但不能证明发布者可信，也不能让 CLI 自动变得安全。不支持脚本或以目录形式分发的工具。

> [!TIP]
> 强化运行时是安全模型的重要组成部分。没有它，恶意软件和智能体就可能直接读取运行中进程的内存，窃取 Secret。

[创建与更新启动器应用包](docs/signed-cli-launchers.md#create-a-launcher-bundle)

&nbsp;

## Secrets

> [!NOTE]
> 加固程序将 Secret 从暴露的存储位置迁移到 Automic Vault。你无须自行运行 `av save`，`av harden` 会为你完成这一步。

保存一个 Secret：

```sh
$ av save API_TOKEN   # 通过标准输入提示输入
```

保存一个项目 Secret：

```sh
$ av save --project-directory=. API_TOKEN
```

Automic Vault 从物理工作目录及其祖先目录中选择最近的项目值；没有匹配项时使用全局值。读取选定值失败会结束请求，不会尝试其他值。

目录只选择值，不授予权限。同一套基于名称的策略覆盖该 Secret 的所有值。

- [项目值、dotenvx 与 mise](docs/project-secrets.md)
- [Varlock](docs/varlock.md)

### 保存多行或原样输入

```sh
$ av save --multiline DEPLOY_PRIVATE_KEY
# 输入内容不可见；输入最后一个换行后，按 Ctrl-D 结束。
$ av save --stdin API_TOKEN <&3
# 从已有文件描述符读取原始字节，直到 EOF。
```

两种模式都需要人工批准。`--stdin` 保留空白和换行；值必须是非空、不含 NUL 字节的 UTF-8，最大 1 MiB。

[输入模式](docs/project-secrets.md#multiline-and-exact-input) ·
[复制选定的 v1 Secrets](docs/migrating-from-v1.md)

&nbsp;

## 脚本编写

你可以将 Secret 注入任何程序：

```sh
av inject +SECRET_NAME -- /path/to/something   # 显示批准窗口
```

> [!NOTE]
> `av inject` 是我们构建 Automic Vault 其他功能的基础机制。
> 用户很少需要直接调用它。如果你发现自己需要使用它，通常可以考虑我们提供的其他工具。

> [!TIP]
> 加固后的工具使用具名 Secret，你可以通过 `av inject` 使用它们，例如 `AWS_ACCESS_KEY_ID`。

> [!NOTE]
> 我们有意不提供直接将 Secret 打印到标准输出的命令。
> 需要取出并持有 Secret 的场景都会带来风险，应尽量寻找其他办法。
>
> 如果确实必须这样做：`av inject +FOO -- sh -c 'echo "$FOO"'`

为了减少暴露†，我们支持通过文件描述符而非环境变量注入：

```sh
$ av inject --mode=fd +FOO:3 +BAR:4 -- /path/to/something
```

每个 Secret 通过独立的匿名管道按存储时的原始字节传递，随后是 EOF。Automic Vault 从目标环境中移除请求的名称，并要求每次调用重新获得批准。描述符必须尚未使用，每个值必须能装入可用的管道缓冲区。

[FD 传递及其限制](docs/direct-secret-access.md#apply-secrets-through-file-descriptors)

> † 环境变量会传递给子进程，大型代码库中的任何部分也都能读取它们。

可以为已验证启动器配置直接注入的自动授权。我们不推荐这样做，建议使用已认可脚本。

### 已认可脚本

审阅一次脚本，通过认可记录（Blessing）绑定其规范路径、确切内容、声明和能力范围：

```sh
$ av bless ./path/to/script
```

脚本声明所需的 Secrets 和工具能力范围：

```sh
#!/usr/local/bin/av inject +DEPLOY_TOKEN -- /bin/bash
# --- automic-vault
# capabilities:
#   gh: read-only
#   aws: write
# ---
```

为保持兼容性，省略声明会继承调用上下文中已有的自动授权权限。可用以下方式明确这一选择：

```sh
# --- automic-vault
# capabilities: { inherit: true }
# ---
```

使用空声明后，只要 Automic Vault 能将后续的受控操作归属于该次存活的脚本执行，每次操作都需要人工批准，不论哪个启动器调用脚本：

```sh
# --- automic-vault
# capabilities: {}
# ---
```

`av inject` shebang 中的 Secret 名称会单独获得授权。不请求 Secret 且声明 `capabilities: {}` 的脚本无须批准即可启动，因为它没有获得 Automic Vault 权限。这是授权上限，不是沙盒：普通命令仍以用户原有的操作系统权限运行。重新启动 Automic Vault 或无法再观察祖先链时，内存中的上限会失效，活跃的已认可脚本状态也同样结束。

留待下个主要版本处理的兼容性问题记录在[未来的不兼容更改](docs/future-breaking-changes.md)中。

编辑脚本或声明会使认可失效。启动器背书（Launcher Endorsement）允许一个已验证启动器自动授权那一份确切的认可记录。对于审阅后运行并退出的工作，使用已认可脚本；对于长期运行的进程，使用工具授权关卡。

文件描述符（FD）传递目前每次都需要重新批准，即使调用发生在已认可脚本内。`av inject` shebang 不支持 FD 模式。

<img src="./docs/img/blessed-script.png" alt="Automic Vault 已认可脚本审阅" style="width: 589px; height: auto" />

[认可与执行保证](docs/domain-language.md#blessed-script) ·
[跨应用重启运行脚本](docs/direct-secret-access.md#blessed-script-lifecycle)

#### 可重入的已认可脚本

可重入的已认可脚本先执行确定性工作，直到需要智能体输入时，输出提示并退出。提示说明所需输出、提供已审阅能力的固定子命令，以及继续执行的命令。

Automic Vault 为每次调用单独授权。让 Secret 值始终留在脚本执行范围内，并在使用智能体输出前验证它。

[GitHub、S3 和 CloudFront 发布示例](docs/examples/reentrant-release.sh)包含输入验证、摘要检查、条件写入和幂等重试。

&nbsp;

## GPG 签名

为 Git 提交和标签签名，无须把私钥或口令交给 Git。GPG 签名关卡为私钥使用授权，原有 Git 命令继续工作。你可以为特定的已验证启动器选择独立签名凭证，让智能体使用不同的签名身份。

此关卡提供**需要批准**和**允许签名**两个选项。签名目标在创建签名时处理私钥。

[配置 Git 签名](docs/securing-git.md#gate-gpg-commit-signing)

## SSH 代理

使用我们的 SSH 代理，不只是为了处理凭证暴露问题；这类问题很容易缓解。更重要的是，智能体和恶意软件不应未经你的同意，就能通过 `ssh` 连接到你的密钥可访问的任意主机。

通过我们的 SSH 代理，你可以允许特定应用使用 `ssh`；其他应用都需要经过授权关卡。

&nbsp;

## 凭证代理

AV 的 Secret 代理用随机的、仅限当前会话的 Secret 引用替代每个 Secret 值，交给应用：

```sh
$ av save API_TOKEN
$ av proxy +API_TOKEN -- node --use-env-proxy app.js
```

当该引用出现在获准的出站 HTTP/S 请求中时，代理应用真正的 Secret。启动代理会话和添加目的地都需要人工批准。**在本会话中允许**只在该会话内记住相应源站和 Secret 名称。

应用必须支持提供的代理和限定范围的 CA 设置。Secret 引用和代理凭证都是持有者凭证：获得这些值的代码，可以使用该会话已经允许的目的地。

[应用示例、`.env` 与兼容性](docs/secret-proxy.md)

[Varlock 集成](docs/varlock.md)通过 `ENV` 解析 Secrets，可与 Varlock 自身的凭证代理配合使用。它每次运行都需要一次人工批准，不支持自动授权或脚本认可。Varlock 的代理和 `av proxy` 是独立会话，请勿嵌套使用。

&nbsp;

## 安全边界

Automic Vault 防范以你的普通用户权限运行的不受信任或已受攻击的代码。它基于 macOS 代码签名、数据保护钥匙串、TCC、强化运行时和存活进程身份。

root 或内核失陷、任意本地破坏，以及目标收到 Secret 后的行为，都不在产品的保护边界内。包装器无法拦截每一次进程执行。请让终端和智能体运行环境的 [macOS 权限保持最小](docs/tool-hardening.md#rescind-unneeded-terminal-permissions)。

&nbsp;

## 配套应用

网络过滤和通用智能体沙盒不在 Automic Vault 的产品范围或路线图内。以下应用可以满足这些需求：

- [Tiny Shield](https://tinyshield.proxyman.com) 监控 Mac 的网络连接，让你阻止应用或域名。Automic Vault 控制某项操作能否使用受保护的凭证；Tiny Shield 则控制应用可以连接到哪里，包括不使用凭证的流量。
- [agentsh](https://www.agentsh.org) 对通过它运行的智能体实施文件、网络和进程策略。你可以用它限制工作区访问和命令执行，与 Automic Vault 的 Secret 保管和授权关卡配合使用。这些限制覆盖删除文件等本地操作；这类操作不需要受保护的 Secret，也可能根本不会经过 Automic Vault 的关卡。

&nbsp;

## 文档

macOS 核心界面和批准流程支持简体中文，并跟随 macOS 的首选语言。未翻译的内容回退到英文。命令、路径、Secret 名称等技术标识符保留原文。

更多用法请参阅[用户手册][user manual]或运行 `av help`。除本 README 外，仓库内的文档目前保留英文。

- [用户手册][user manual]
- [文档索引](docs/index.md)
- [选择适合的机制](docs/choosing-a-mechanism.md)
- [领域术语](docs/domain-language.md)、[架构](docs/architecture.md)和[产品定位](docs/positioning.md)
- [架构决策](docs/adr/)
- [Homebrew tap](https://github.com/automic-vault/homebrew-isotopes)
- [![与维护者交流](https://knock-knock.mxcl.dev/badge.svg)](https://knock-knock.mxcl.dev/automic-vault/automic-vault)

&nbsp;

> [!IMPORTANT]
> Automic Vault 与任何加密货币或所谓“代币”均无关联。

[latest release]: https://github.com/automic-vault/automic-vault/releases/latest
[user manual]: https://www.automicvault.com/docs/
