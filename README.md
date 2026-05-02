目前提供windows与andrid版本
### 概述
**LynPass** 是一款军工级本地密码管理器，采用 **Argon2id 密钥派生 + AES‑256‑GCM 数据加密 + HMAC 完整性保护** 的多层安全架构，将所有密码安全存储于单个加密文件（`.pass`）中。程序完全离线运行，无需网络连接，无服务端，数据永远掌握在你手中。

主要应用场景：安全存储网站/应用的用户名与密码，生成高强度随机密码，防止密码重用和弱密码带来的安全风险。

### ✨ 功能特性
- 🔐 **强加密体系**：Argon2id (256 MiB 内存) 密钥派生 + AES‑256‑GCM 认证加密 + HMAC‑SHA256 完整性校验
- 🧹 **内存安全**：主密码存储于 `bytearray`，使用后立即安全擦除（多次置零）；支持 `mlock`/`VirtualLock` 锁定物理内存防交换
- 🛡 **防暴力破解**：连续输错 10 次密码自动触发自毁机制（多遍覆写后删除保险库文件）
- 👁 **防窥屏**：Windows 下自动启用防截屏保护 (`SetWindowDisplayAffinity`)
- ⌨ **虚拟安全键盘**：可选屏幕虚拟键盘输入主密码，防止硬件键盘记录器
- 📜 **加密审计日志**：所有关键操作（解锁、添加、删除、修改主密码等）记录至独立加密的 `audit.log.enc`，审计密钥与主密码解耦
- 🔒 **自动锁定**：无操作 1 分钟后自动锁定，回到登录界面
- 🔑 **强密码生成器**：可调节长度、符号、排除易混淆字符，基于 `secrets` 模块的真随机数生成
- 📦 **单文件存储**：所有密码存储于一个 `.pass` 加密文件，可轻松备份至 U 盘或云盘
- 🚫 **防并发**：文件锁机制防止同时运行多个实例导致数据损坏
- 🖼 **自定义图标**：支持 `icon.ico` 图标文件，打造专属外观
- 📊 **密码强度可视化**：内置密码强度指示器，帮助创建强主密码

### 依赖环境
- Python 3.9+
- tkinter（Python 自带）
- `cryptography`（AES‑GCM / Argon2id）
- `pyperclip`（剪贴板操作）

安装：
```bash
pip install cryptography pyperclip
```

### 使用方法

#### 启动程序
```bash
python LynPass.py
```

#### 创建保险库
1. 首次运行自动进入创建保险库界面。
2. 设置**主密码**（至少 8 位，推荐 12 位以上混合大小写/数字/符号）。
3. 确认主密码后，自动生成加密保险库文件 `vault.pass`。

#### 日常使用
1. 启动后输入主密码解锁。
2. **添加密码**：点击 `+ 添加`，填写网站、用户名、密码（可用内置生成器生成强密码）。
3. **查看密码**：点击表格中的 👁 图标可临时显示密码（5 秒后自动隐藏）。
4. **复制密码**：点击 📋 图标复制密码到剪贴板（15 秒自动清除）。
5. **搜索**：在搜索框输入关键词，快速过滤条目。
6. **编辑/删除**：选中条目后点击 `✎ 编辑` 或 `✕ 删除`。
7. **锁定**：点击 `锁定` 按钮或等待 1 分钟无操作自动锁定。

#### 打包为 EXE
```bash
pip install pyinstaller
pyinstaller --onefile --windowed --icon=icon.ico LynPass.py
```
打包完成后，在 `dist` 目录生成 `LynPass.exe`，可直接运行。

### 安全设计

#### 密钥派生
- 使用 **Argon2id**（256 MiB 内存，4 通道，3 轮迭代）从主密码 + 16 字节随机盐派生 64 字节密钥材料。
- 前 32 字节为 AES 加密密钥（Enc Key），后 32 字节为 HMAC 完整性密钥（Mac Key）。
- 若 Argon2id 不可用，自动回退至 scrypt (128 MiB)。

#### 文件结构
```
[4 字节魔数 "LYNX"]
[1 字节版本号]
[16 字节盐]
[12 字节 Nonce]
[AES-256-GCM 密文 (含 16 字节认证标签)]
[32 字节 HMAC-SHA256]
```
HMAC 覆盖版本号 + 盐 + Nonce + 密文，任何篡改都会导致解密失败并触发安全锁定。

#### 防爆破机制
- 锁文件 `vault.pass.lock` 由主密码加密存储失败尝试次数。
- 缺失或损坏的锁文件自动触发 **24 小时安全锁定**，防止攻击者通过删除锁文件绕过限制。
- 连续 10 次密码错误触发**自毁**：多遍覆写随机数据后永久删除保险库文件。

#### 审计日志
- 审计日志 `audit.log.enc` 使用**独立随机审计密钥**（256 位）加密。
- 审计密钥在创建保险库时随机生成，经主密码加密后存储于保险库文件内。
- 修改主密码时审计密钥重新加密，日志不丢失，可实现完整的操作追溯。

#### 内存防护
- 主密码以 `bytearray` 存储，锁定/退出时多遍置零 (`secure_wipe`)。
- 尝试调用 `mlock` (Unix) / `VirtualLock` (Windows) 锁定物理内存页面，防止被交换至磁盘。
- 若内存锁定不可用（普通用户权限不足），状态栏将显示警告提示。

#### 防窥屏 (Windows)
- 调用 `SetWindowDisplayAffinity(WDA_MONITOR)` 使窗口内容无法被截屏工具捕获。

### 注意事项
- 主密码丢失**不可恢复**，请妥善保管。
- 备份 `.pass` 文件时注意介质安全，文件本身已加密，但仍建议存储于可信位置。
- 内存锁定在非管理员权限下可能不可用，建议配合全盘加密（BitLocker / FileVault / LUKS）使用以获得最佳安全性。
- 
### Overview
**LynPass** is a military‑grade local password manager featuring **Argon2id key derivation + AES‑256‑GCM encryption + HMAC integrity protection** in a multi‑layered security architecture. All passwords are securely stored in a single encrypted file (`.pass`). The application runs entirely offline — no network, no servers, your data stays with you.

Common use cases: securely storing website/app credentials, generating strong random passwords, and preventing risks from password reuse or weak passwords.

### ✨ Features
- 🔐 **Strong Encryption**: Argon2id (256 MiB memory) key derivation + AES‑256‑GCM authenticated encryption + HMAC‑SHA256 integrity check
- 🧹 **Memory Safety**: Master password stored in `bytearray` and securely wiped after use; `mlock`/`VirtualLock` to prevent paging to disk
- 🛡 **Anti‑Brute Force**: 10 consecutive failed attempts trigger self‑destruction (multi‑pass overwrite then deletion)
- 👁 **Anti‑Screenshot**: Windows `SetWindowDisplayAffinity` protection enabled automatically
- ⌨ **Virtual Safe Keyboard**: On‑screen keyboard for master password entry, defeating hardware keyloggers
- 📜 **Encrypted Audit Log**: All critical operations logged to `audit.log.enc` with a decoupled, randomly‑generated audit key
- 🔒 **Auto‑Lock**: Locks automatically after 1 minute of inactivity
- 🔑 **Strong Password Generator**: Adjustable length, symbols, exclusion of ambiguous characters, backed by `secrets` module
- 📦 **Single‑File Storage**: One `.pass` file contains everything; easy to backup via USB or cloud
- 🚫 **Concurrency Protection**: File‑lock prevents multiple instances from corrupting the vault
- 🖼 **Custom Icon**: Supports `icon.ico` for a personalized look
- 📊 **Password Strength Visualizer**: Built‑in indicator helps create strong master passwords

### Dependencies
- Python 3.9+
- tkinter (included)
- `cryptography`
- `pyperclip`

Install:
```bash
pip install cryptography pyperclip
```

### Usage

#### Launch
```bash
python LynPass.py
```

#### Create a Vault
1. On first run, the vault creation screen appears automatically.
2. Set a **master password** (min. 8 characters; 12+ mixed types recommended).
3. Confirm the password — a `vault.pass` file is generated.

#### Daily Use
1. Enter your master password to unlock.
2. **Add entry**: Click `+ Add`, fill in site, username, and password (use the built‑in generator).
3. **View password**: Click the 👁 icon on a row to reveal the password (auto‑hides after 5 seconds).
4. **Copy password**: Click 📋 to copy to clipboard (auto‑cleared after 15 seconds).
5. **Search**: Type in the search box to filter entries instantly.
6. **Edit / Delete**: Select an entry, then click `✎ Edit` or `✕ Delete`.
7. **Lock**: Click `Lock` or wait 1 minute for automatic lock.

#### Package as EXE
```bash
pip install pyinstaller
pyinstaller --onefile --windowed --icon=icon.ico LynPass.py
```
The standalone `LynPass.exe` will be in the `dist` folder.

### Security Design

#### Key Derivation
- **Argon2id** (256 MiB memory, 4 lanes, 3 iterations) derives 64 bytes from master password + 16‑byte random salt.
- First 32 bytes → AES encryption key (Enc Key); last 32 bytes → HMAC integrity key (Mac Key).
- Falls back to scrypt (128 MiB) if Argon2id is unavailable.

#### File Structure
```
[4-byte magic "LYNX"]
[1-byte version]
[16-byte salt]
[12-byte nonce]
[AES-256-GCM ciphertext with 16-byte auth tag]
[32-byte HMAC-SHA256]
```
HMAC covers version + salt + nonce + ciphertext; any tampering fails decryption and triggers a security lockout.

#### Anti‑Brute Force
- The lock file `vault.pass.lock` stores failure counts encrypted with the master password.
- A missing or corrupted lock file triggers an automatic **24‑hour security lockout**.
- 10 consecutive wrong passwords trigger **self‑destruction**: multi‑pass random overwrite followed by permanent deletion.

#### Audit Log
- `audit.log.enc` is encrypted with a **separate random 256‑bit audit key**.
- The audit key is generated at vault creation, encrypted with the master password, and stored inside the vault.
- Changing the master password re‑encrypts the audit key — logs survive password changes.

#### Memory Protection
- Master password stored as `bytearray`; securely wiped (multi‑pass zeroing) on lock/exit.
- Attempts `mlock` (Unix) / `VirtualLock` (Windows) to lock physical memory pages, preventing swap exposure.
- A warning appears in the status bar if memory locking is unavailable.

#### Anti‑Screenshot (Windows)
- `SetWindowDisplayAffinity(WDA_MONITOR)` prevents screen capture tools from reading the window.

### Notes
- A lost master password is **irrecoverable** — store it safely.
- The `.pass` file is encrypted; backing it up is safe, but still use trusted storage.
- Memory locking may require administrator/root privileges; for best results, combine with full‑disk encryption (BitLocker / FileVault / LUKS).
