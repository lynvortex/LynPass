import tkinter as tk
from tkinter import ttk, messagebox, Menu
import json, os, uuid, struct, secrets, string, hashlib, hmac, time, sys, ctypes
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import pyperclip
try:
    import win32clipboard
    HAS_WIN32CLIP = True
except ImportError:
    HAS_WIN32CLIP = False

MAGIC = b'LYNX'
VERSION = 3
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
HMAC_LEN = 32
AUTO_LOCK_TIME = 60                # 秒

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_LOCKOUT_TIME = 15          # 分钟
DEFAULT_ON_MAX_ACTION = 'lock'
SAFE_LOCKOUT = 24 * 3600           # 锁文件缺失时的强制锁定时间（秒）

# -------------------- 安全内存 --------------------
def secure_wipe(byte_array):
    if byte_array is None: return
    for i in range(len(byte_array)):
        byte_array[i] = 0
    addr = ctypes.addressof(ctypes.c_char.from_buffer(byte_array))
    ctypes.memset(addr, 0, len(byte_array))

def try_mlock(byte_array):
    try:
        addr = ctypes.addressof(ctypes.c_char.from_buffer(byte_array))
        length = len(byte_array)
        if sys.platform == 'win32':
            kernel32 = ctypes.windll.kernel32
            if not kernel32.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(length)):
                return False
        else:
            libc = ctypes.CDLL('libc.so.6', use_errno=True)
            if libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(length)) != 0:
                return False
        return True
    except:
        return False

if sys.platform == 'win32':
    WDA_MONITOR = 1
    def prevent_screenshot(hwnd):
        ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, WDA_MONITOR)
else:
    def prevent_screenshot(hwnd): pass

class VirtualKeyboard(tk.Toplevel):
    def __init__(self, parent, target_var):
        super().__init__(parent)
        self.title('安全输入'); self.target = target_var
        self.resizable(False, False); self.attributes('-topmost', True)
        chars = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()'
        for i, ch in enumerate(chars):
            btn = ttk.Button(self, text=ch, width=3, command=lambda c=ch: self._type(c))
            btn.grid(row=i//10, column=i%10, padx=1, pady=1)
    def _type(self, char):
        self.target.set(self.target.get() + char)

# -------------------- 密码学核心 --------------------
def derive_keys(password: bytes, salt: bytes, dklen=64) -> bytes:
    if HAS_ARGON2:
        try:
            kdf = Argon2id(salt=salt, length=dklen, memory_cost=256*1024,
                           parallelism=4, time_cost=3)
            return kdf.derive(password)
        except TypeError:
            try:
                kdf = Argon2id(salt=salt, length=dklen, memory_cost=256*1024,
                               degree_of_parallelism=4, time_cost=3)
                return kdf.derive(password)
            except TypeError: pass
    scrypt_configs = [(2**17, 8, 1), (2**16, 8, 1), (2**15, 8, 1)]
    for n, r, p in scrypt_configs:
        try:
            return hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=dklen)
        except ValueError: continue
    return hashlib.scrypt(password, salt=salt, n=2**14, r=8, p=1, dklen=dklen)

def encrypt_vault(password: bytes, data: dict) -> bytes:
    salt = os.urandom(SALT_LEN)
    raw_key = derive_keys(password, salt, dklen=64)
    enc_key, mac_key = raw_key[:32], raw_key[32:]
    nonce = os.urandom(NONCE_LEN)
    plaintext = json.dumps(data, ensure_ascii=False).encode('utf-8')
    aesgcm = AESGCM(enc_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    payload = struct.pack('B', VERSION) + salt + nonce + ciphertext
    mac = hmac.new(mac_key, payload, hashlib.sha256).digest()
    return MAGIC + payload + mac

def decrypt_vault(password: bytes, raw: bytes) -> dict:
    if raw[:4] != MAGIC: raise ValueError('无效文件')
    version = raw[4]
    if version != VERSION: raise ValueError('版本不匹配')
    salt = raw[5:5+SALT_LEN]
    nonce = raw[5+SALT_LEN:5+SALT_LEN+NONCE_LEN]
    ct_len = len(raw) - 4 - 1 - SALT_LEN - NONCE_LEN - HMAC_LEN
    if ct_len <= 0: raise ValueError('文件长度异常')
    ct_start = 5 + SALT_LEN + NONCE_LEN
    ct_end = ct_start + ct_len
    ciphertext = raw[ct_start:ct_end]
    received_mac = raw[ct_end:ct_end+HMAC_LEN]
    raw_key = derive_keys(password, salt, dklen=64)
    enc_key, mac_key = raw_key[:32], raw_key[32:]
    payload = raw[4:ct_end]
    expected_mac = hmac.new(mac_key, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_mac, received_mac):
        raise ValueError('HMAC 验证失败，文件被篡改')
    aesgcm = AESGCM(enc_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode('utf-8'))

def atomic_save(filepath: str, password: bytes, data: dict):
    encrypted = encrypt_vault(password, data)
    tmp = filepath + '.tmp'
    with open(tmp, 'wb') as f:
        f.write(encrypted); f.flush(); os.fsync(f.fileno())
    os.chmod(tmp, 0o600)  # 在 replace 之前设置权限，避免短暂权限过宽
    os.replace(tmp, filepath)

# -------------------- 安全锁文件（独立，不参与互斥） --------------------
LOCK_FILE = '.vault.lock'

def _lock_static_key(vault_file: str) -> bytes:
    seed = (vault_file + "#LOCK#SALT").encode('utf-8')
    return hashlib.sha256(seed).digest()

def _make_hidden(path):
    if sys.platform == 'win32':
        try: ctypes.windll.kernel32.SetFileAttributesW(path, 2)
        except: pass

def load_lock_state(vault_file: str):
    """读取安全锁状态，文件缺失/损坏返回强制锁定"""
    if not os.path.exists(LOCK_FILE):
        return (999, time.time() + SAFE_LOCKOUT, DEFAULT_MAX_ATTEMPTS, DEFAULT_ON_MAX_ACTION)
    try:
        with open(LOCK_FILE, 'rb') as f:
            data = f.read()
        salt = data[:SALT_LEN]
        nonce = data[SALT_LEN:SALT_LEN+NONCE_LEN]
        ct = data[SALT_LEN+NONCE_LEN:]
        key = _lock_static_key(vault_file)
        aesgcm = AESGCM(key)
        plain = aesgcm.decrypt(nonce, ct, None)
        state = json.loads(plain.decode('utf-8'))
        return (
            state.get('attempts', 0),
            state.get('lock_until', 0),
            state.get('max_attempts', DEFAULT_MAX_ATTEMPTS),
            state.get('action', DEFAULT_ON_MAX_ACTION),
            state.get('_lv', '')  # 完整性校验 HMAC（向后兼容）
        )
    except Exception:
        return (999, time.time() + SAFE_LOCKOUT, DEFAULT_MAX_ATTEMPTS, DEFAULT_ON_MAX_ACTION, '')

def update_lock_file(vault_file, attempts, lock_until, max_attempts=None, action=None, lock_verifier=None):
    """原子写入安全锁文件（不加文件锁，调用前需确保已持有运行锁）"""
    if max_attempts is None: max_attempts = DEFAULT_MAX_ATTEMPTS
    if action is None: action = DEFAULT_ON_MAX_ACTION
    salt = os.urandom(SALT_LEN)
    key = _lock_static_key(vault_file)
    state = {
        'attempts': attempts, 'lock_until': lock_until,
        'max_attempts': max_attempts, 'action': action
    }
    # 如果提供了锁验证密钥，添加 HMAC 完整性校验字段（解锁后用于检测篡改）
    if lock_verifier:
        state['_lv'] = hmac.new(
            bytes.fromhex(lock_verifier),
            json.dumps(state, sort_keys=True).encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    data = json.dumps(state).encode('utf-8')
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ct = aesgcm.encrypt(nonce, data, None)
    new_content = salt + nonce + ct
    tmp = LOCK_FILE + '.tmp'
    with open(tmp, 'wb') as f:
        f.write(new_content); f.flush(); os.fsync(f.fileno())
    os.chmod(tmp, 0o600)  # 在 replace 之前设置权限
    os.replace(tmp, LOCK_FILE)
    _make_hidden(LOCK_FILE)

def clear_lock_state():
    if os.path.exists(LOCK_FILE):
        try: os.remove(LOCK_FILE)
        except: pass

def self_destruct(vault_file):
    if not os.path.exists(vault_file): return
    size = os.path.getsize(vault_file)
    patterns = [b'\x00' * 4096, b'\xff' * 4096]
    with open(vault_file, 'wb') as f:
        for i in range(7):
            f.seek(0)
            pat = patterns[i % 2] if i < 6 else os.urandom(4096)
            written = 0
            while written < size:
                f.write(pat[:min(len(pat), size - written)])
                written += len(pat)
            f.flush(); os.fsync(f.fileno())
    # 截断文件以清除文件系统可能残留的元数据
    with open(vault_file, 'wb') as f:
        f.truncate(0); f.flush(); os.fsync(f.fileno())
    os.remove(vault_file)

# -------------------- 运行锁（并发控制，独立文件，可自动回收） --------------------
RUNNING_FILE = 'vault.pass.running'

if sys.platform == 'win32':
    import msvcrt
    def acquire_running_lock():
        """获取运行锁，成功返回文件句柄，失败返回 None（已有实例或权限问题）"""
        path = RUNNING_FILE
        try:
            # 打开或创建文件并尝试非阻塞锁
            f = open(path, 'a+b')   # 追加模式，确保文件存在且可写
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            return f
        except (IOError, OSError):
            # 文件可能被其他进程独占，或权限不足
            return None
    def release_running_lock(f):
        try: msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        except: pass
        f.close()
        try:
            # 清理运行锁文件（仅当无其他进程持锁时，但实际我们已经释放锁，可以安全删除）
            if os.path.exists(RUNNING_FILE):
                os.remove(RUNNING_FILE)
        except: pass
else:
    import fcntl
    def acquire_running_lock():
        path = RUNNING_FILE
        try:
            f = open(path, 'a+b')
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return f
        except (BlockingIOError, OSError):
            return None
    def release_running_lock(f):
        fcntl.flock(f, fcntl.LOCK_UN)
        f.close()
        try:
            if os.path.exists(RUNNING_FILE):
                os.remove(RUNNING_FILE)
        except: pass

# -------------------- 审计日志 --------------------
AUDIT_MAGIC = b'LAUD'
_audit_chain_hmac = None  # 链式 HMAC：上一条记录密文的 HMAC

def encrypt_audit_entry(entry: dict, audit_key: bytes) -> bytes:
    global _audit_chain_hmac
    nonce = os.urandom(NONCE_LEN)
    # 在记录中包含上一条记录的 HMAC，形成完整性链
    chain_entry = entry.copy()
    chain_entry['seq'] = int(time.time() * 1000000)
    if _audit_chain_hmac is not None:
        chain_entry['prev_hmac'] = _audit_chain_hmac.hex()
    plain = json.dumps(chain_entry).encode('utf-8')
    aesgcm = AESGCM(audit_key)
    ct = aesgcm.encrypt(nonce, plain, None)
    # 更新链 HMAC（基于密文，兼容旧记录）
    _audit_chain_hmac = hmac.new(audit_key, ct, hashlib.sha256).digest()
    return AUDIT_MAGIC + nonce + ct

def audit_log(event: str, audit_key: bytes):
    entry = {'ts': time.time(), 'event': event}
    encrypted = encrypt_audit_entry(entry, audit_key)
    with open('audit.log.enc', 'ab') as f:
        f.write(encrypted + b'\n')

# -------------------- 密码生成器 --------------------
def generate_password(length=16, use_symbols=True, exclude_confusing=False):
    lowers = string.ascii_lowercase; uppers = string.ascii_uppercase; digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    if exclude_confusing:
        lowers = lowers.translate(str.maketrans('', '', 'lo'))
        uppers = uppers.translate(str.maketrans('', '', 'IO'))
        digits = digits.translate(str.maketrans('', '', '01'))
    all_chars = lowers + uppers + digits
    if use_symbols: all_chars += symbols
    password = [secrets.choice(lowers), secrets.choice(uppers), secrets.choice(digits)]
    if use_symbols: password.append(secrets.choice(symbols))
    for _ in range(length - len(password)):
        password.append(secrets.choice(all_chars))
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)

# -------------------- 界面工具 --------------------
def center_window(win, parent=None, width=None, height=None):
    if width and height: win.geometry(f'{width}x{height}')
    win.update_idletasks()
    if parent and parent.winfo_viewable():
        pw, ph = parent.winfo_width(), parent.winfo_height()
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
    else:
        pw, ph = win.winfo_screenwidth(), win.winfo_screenheight()
        px = py = 0
    ww, wh = win.winfo_width(), win.winfo_height()
    x = px + (pw - ww)//2; y = py + (ph - wh)//2
    win.geometry(f'+{x}+{y}')

def set_icon(window):
    # 支持 PyInstaller 打包后的路径（sys._MEIPASS）
    icon_path = 'icon.ico'
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        _mei = os.path.join(sys._MEIPASS, 'icon.ico')
        if os.path.exists(_mei):
            icon_path = _mei
    if os.path.exists(icon_path):
        try: window.iconbitmap(icon_path)
        except: pass

# -------------------- 登录窗口 --------------------
class MilitaryLoginWindow:
    def __init__(self, parent, vault_file='vault.pass'):
        self.parent = parent; self.vault_file = vault_file
        self.master_pwd = None; self.data = None
        self.win = tk.Toplevel(parent)
        self.win.title('LynPass - 解锁')
        self.win.resizable(False, False)
        self.win.protocol('WM_DELETE_WINDOW', self.on_close)
        set_icon(self.win)

        if not os.path.exists(vault_file):
            clear_lock_state()
            self.build_create_ui()
            center_window(self.win, parent, 420, 260)
            self.win.update_idletasks(); prevent_screenshot(self.win.winfo_id())
            self.win.focus()
            return

        # 检查安全锁状态
        lock_state = load_lock_state(vault_file)
        _, lock_until, _, _, _ = lock_state
        if lock_until > time.time():
            mins, secs = divmod(int(lock_until - time.time()), 60)
            messagebox.showwarning('已锁定', f'保险库已锁定，请等待 {mins} 分 {secs} 秒后重试。')
            self.on_close(); return

        self.build_login_ui()
        center_window(self.win, parent, 420, 260)
        self.win.update_idletasks(); prevent_screenshot(self.win.winfo_id())
        self.win.focus()

    def on_close(self): self.parent.destroy()

    def build_create_ui(self):
        ttk.Label(self.win, text='创建新保险库', font=('',12,'bold')).pack(pady=8)
        ttk.Label(self.win, text='设置主密码（至少8位，请牢记）：').pack()
        self.pwd_var1 = tk.StringVar()
        ttk.Entry(self.win, textvariable=self.pwd_var1, show='*', width=30).pack(pady=4)
        ttk.Label(self.win, text='确认主密码：').pack()
        self.pwd_var2 = tk.StringVar()
        ttk.Entry(self.win, textvariable=self.pwd_var2, show='*', width=30).pack(pady=4)
        ttk.Button(self.win, text='创建', command=self.create_vault).pack(pady=12)
        self.status_label = ttk.Label(self.win, text='', foreground='red')
        self.status_label.pack()

    def build_login_ui(self):
        ttk.Label(self.win, text='解锁保险库', font=('',12,'bold')).pack(pady=8)
        ttk.Label(self.win, text='请输入主密码：').pack()
        f = ttk.Frame(self.win); f.pack()
        self.pwd_var = tk.StringVar()
        self.pwd_entry = ttk.Entry(f, textvariable=self.pwd_var, show='*', width=30)
        self.pwd_entry.pack(side='left', padx=4)
        self.use_vkey = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text='虚拟键盘', variable=self.use_vkey, command=self._toggle_vkey).pack(side='left')
        self._vkey_win = None
        ttk.Button(self.win, text='解锁', command=self.unlock).pack(pady=12)
        self.status_label = ttk.Label(self.win, text='', foreground='red')
        self.status_label.pack()
        self.pwd_entry.focus()

    def _toggle_vkey(self):
        if self.use_vkey.get():
            self._vkey_win = VirtualKeyboard(self.win, self.pwd_var)
        else:
            if self._vkey_win: self._vkey_win.destroy(); self._vkey_win = None

    def create_vault(self):
        pwd1 = self.pwd_var1.get(); pwd2 = self.pwd_var2.get()
        if not pwd1 or len(pwd1) < 8:
            self.status_label.config(text='密码至少需要8个字符'); return
        if pwd1 != pwd2:
            self.status_label.config(text='两次输入的密码不一致'); return
        audit_key = secrets.token_bytes(32)
        lock_verifier = secrets.token_hex(32)  # 锁文件完整性校验密钥
        data = {
            'entries': [],
            'audit_key': None,
            '_lock_verifier': lock_verifier,
            'settings': {
                'max_attempts': DEFAULT_MAX_ATTEMPTS,
                'lockout_time': DEFAULT_LOCKOUT_TIME,
                'on_max_action': DEFAULT_ON_MAX_ACTION
            }
        }
        pwd_bytes = bytearray(pwd1.encode('utf-8'))
        # 立即清除内存中的密码字符串
        pwd1 = ''; pwd2 = ''
        self.pwd_var1.set(''); self.pwd_var2.set('')
        mlock_ok = try_mlock(pwd_bytes)
        data['audit_key'] = audit_key.hex()  # 直接存储，无需双层加密
        try:
            atomic_save(self.vault_file, bytes(pwd_bytes), data)
        except Exception as e:
            messagebox.showerror('错误', f'创建失败：{e}'); return
        # 创建安全锁文件（初始正常状态，带完整性校验）
        update_lock_file(self.vault_file, 0, 0, DEFAULT_MAX_ATTEMPTS, DEFAULT_ON_MAX_ACTION,
                         lock_verifier=lock_verifier)
        self.master_pwd = pwd_bytes
        self.data = data
        self.audit_key = audit_key
        self.mlock_ok = mlock_ok
        audit_log('保险库创建', audit_key)
        self.win.destroy()

    def unlock(self):
        pwd = self.pwd_var.get()
        self.pwd_var.set('')  # 立即清空 StringVar 中的密码
        if not pwd: self.status_label.config(text='请输入密码'); return
        pwd_bytes = bytearray(pwd.encode('utf-8'))
        pwd = ''  # 清除不可变的 str 引用

        # 再次检查安全锁
        lock_state = load_lock_state(self.vault_file)
        _, lock_until, max_attempts, action, _ = lock_state
        if lock_until > time.time():
            mins, secs = divmod(int(lock_until - time.time()), 60)
            messagebox.showwarning('已锁定', f'保险库已锁定，请等待 {mins} 分 {secs} 秒后重试。')
            self.win.destroy(); self.parent.destroy(); return

        try:
            with open(self.vault_file, 'rb') as f: raw = f.read()
            vault_data = decrypt_vault(bytes(pwd_bytes), raw)
            # 审计密钥：新格式直接存储 hex(32 bytes)，旧格式双层加密
            audit_key_raw = vault_data.get('audit_key', '')
            if len(audit_key_raw) == 64:
                try:
                    test_key = bytes.fromhex(audit_key_raw)
                    if len(test_key) == 32:
                        audit_key = test_key  # 新格式
                    else:
                        raise ValueError
                except (ValueError, AttributeError):
                    enc_audit = bytes.fromhex(audit_key_raw)
                    audit_plain = decrypt_vault(bytes(pwd_bytes), enc_audit)
                    audit_key = bytes.fromhex(audit_plain['audit_key'])
            else:
                # 旧格式：双层解密
                enc_audit = bytes.fromhex(audit_key_raw)
                audit_plain = decrypt_vault(bytes(pwd_bytes), enc_audit)
                audit_key = bytes.fromhex(audit_plain['audit_key'])
            # 提取锁文件完整性验证密钥（向后兼容：旧保险库没有则生成）
            if '_lock_verifier' not in vault_data:
                vault_data['_lock_verifier'] = secrets.token_hex(32)
            lock_verifier = vault_data['_lock_verifier']
            # 验证锁文件完整性（检测锁文件是否被外部篡改）
            try:
                lv = load_lock_state(self.vault_file)
                stored_lv = lv[4] if len(lv) > 4 else ''
                if stored_lv:
                    expected_lv = hmac.new(
                        bytes.fromhex(lock_verifier),
                        json.dumps({'attempts': 0, 'lock_until': 0,
                                    'max_attempts': max_attempts, 'action': action},
                                   sort_keys=True).encode('utf-8'),
                        hashlib.sha256
                    ).hexdigest()
                    if stored_lv != expected_lv:
                        audit_log('安全警告：锁文件已被篡改，已重置', audit_key)
            except: pass
            # 成功，重置安全锁
            update_lock_file(self.vault_file, 0, 0, max_attempts, action,
                             lock_verifier=lock_verifier)
        except Exception:
            attempts, _, _, _ = lock_state
            attempts += 1
            if attempts >= max_attempts:
                if action == 'destroy':
                    update_lock_file(self.vault_file, attempts, 0, max_attempts, action)
                    secure_wipe(pwd_bytes)
                    self_destruct(self.vault_file)
                    clear_lock_state()
                    messagebox.showerror('已销毁', '连续错误次数过多，保险库已永久销毁！')
                else:
                    lock_until = time.time() + DEFAULT_LOCKOUT_TIME * 60
                    update_lock_file(self.vault_file, attempts, lock_until, max_attempts, action)
                    secure_wipe(pwd_bytes)
                    messagebox.showerror('已锁定', f'连续错误次数过多，保险库已锁定 {DEFAULT_LOCKOUT_TIME} 分钟。')
            else:
                update_lock_file(self.vault_file, attempts, 0, max_attempts, action)
                secure_wipe(pwd_bytes)
                messagebox.showerror('错误', '密码错误，程序退出。')
            self.win.destroy(); self.parent.destroy(); return

        self.master_pwd = pwd_bytes
        self.data = vault_data
        self.audit_key = audit_key
        self.mlock_ok = try_mlock(pwd_bytes)
        audit_log('保险库解锁', audit_key)
        self.win.destroy()

# -------------------- 主窗口（右键菜单） --------------------
class MilitaryMainWindow:
    def __init__(self, parent, vault_file, data, master_pwd, audit_key, mlock_ok):
        self.parent = parent; self.vault_file = vault_file; self.data = data
        self.master_pwd = master_pwd; self.audit_key = audit_key
        self.mlock_ok = mlock_ok
        self.root = tk.Toplevel(parent)
        self.root.title('LynPass')
        self.root.protocol('WM_DELETE_WINDOW', self.on_close)
        set_icon(self.root)
        self._clipboard_clear_id = None; self._auto_lock_id = None
        self.create_widgets()
        self.refresh_list()
        center_window(self.root, None, 720, 520)
        self.setup_auto_lock()
        self.root.update_idletasks(); prevent_screenshot(self.root.winfo_id())
        self.root.focus()
        if not self.mlock_ok:
            self.status_bar.config(text='⚠ 内存锁定未启用（建议管理员运行）')
        audit_log('主窗口打开', self.audit_key)

    def setup_auto_lock(self):
        events = ['<Motion>','<Key>','<FocusIn>','<Button>']
        for e in events: self.root.bind_all(e, self._reset_auto_lock)
        self._reset_auto_lock()
    def _reset_auto_lock(self, event=None):
        if self._auto_lock_id: self.root.after_cancel(self._auto_lock_id)
        self._auto_lock_id = self.root.after(AUTO_LOCK_TIME * 1000, self._auto_lock)
    def _auto_lock(self):
        self._auto_lock_id = None
        self.lock()
    def remove_auto_lock_bindings(self):
        for e in ['<Motion>','<Key>','<FocusIn>','<Button>']:
            self.root.unbind_all(e)

    def create_widgets(self):
        sf = ttk.Frame(self.root); sf.pack(fill='x', padx=10, pady=8)
        ttk.Label(sf, text='搜索：').pack(side='left')
        self.search_var = tk.StringVar()
        self.search_var.trace_add('write', lambda *a: self.refresh_list())
        ttk.Entry(sf, textvariable=self.search_var, width=30).pack(side='left', padx=4)

        cols = ('site','username','password','actions')
        self.tree = ttk.Treeview(self.root, columns=cols, show='headings', height=15)
        self.tree.heading('site', text='网站'); self.tree.heading('username', text='用户名')
        self.tree.heading('password', text='密码'); self.tree.heading('actions', text='操作')
        self.tree.column('site', width=170); self.tree.column('username', width=170)
        self.tree.column('password', width=170); self.tree.column('actions', width=100)
        scroll = ttk.Scrollbar(self.root, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        self.tree.pack(expand=True, fill='both', padx=10)
        self.tree.bind('<Button-3>', self.show_context_menu)

        bf = ttk.Frame(self.root); bf.pack(fill='x', padx=10, pady=10)
        ttk.Button(bf, text='+ 添加', command=self.add_entry).pack(side='left', padx=4)
        ttk.Button(bf, text='✎ 编辑', command=self.edit_entry).pack(side='left', padx=4)
        ttk.Button(bf, text='✕ 删除', command=self.delete_entry).pack(side='left', padx=4)
        ttk.Button(bf, text='🔑 生成器', command=self.open_generator).pack(side='left', padx=4)
        ttk.Button(bf, text='🛡 安全设置', command=self.open_settings).pack(side='left', padx=4)
        ttk.Button(bf, text='修改主密码', command=self.change_master_password).pack(side='left', padx=4)
        ttk.Button(bf, text='锁定', command=self.lock).pack(side='right', padx=4)

        self.status_bar = ttk.Label(self.root, text='', relief='sunken', anchor='w')
        self.status_bar.pack(side='bottom', fill='x')

    def refresh_list(self):
        for row in self.tree.get_children(): self.tree.delete(row)
        q = self.search_var.get().lower()
        for idx, e in enumerate(self.data['entries']):
            if q and q not in e['site'].lower() and q not in e['username'].lower(): continue
            self.tree.insert('', 'end', iid=str(idx), values=(e['site'], e['username'], '********', '右键菜单'))

    def show_context_menu(self, event):
        row = self.tree.identify_row(event.y)
        if not row: return
        idx = int(row)
        entry = self.data['entries'][idx]
        menu = Menu(self.root, tearoff=0)
        menu.add_command(label='复制密码', command=lambda: self.copy_to_clipboard(entry['password']))
        menu.add_command(label='显示密码 (5秒)', command=lambda: self.toggle_show(idx))
        menu.post(event.x_root, event.y_root)

    def toggle_show(self, idx):
        entry = self.data['entries'][idx]
        self.tree.set(str(idx), 'password', entry['password'])
        self.root.after(5000, lambda: self.tree.set(str(idx), 'password', '********'))

    def copy_to_clipboard(self, text):
        success = False
        try: pyperclip.copy(text); success = True
        except: pass
        if not success:
            try:
                self.root.clipboard_clear(); self.root.clipboard_append(text); success = True
            except: pass
        if not success and HAS_WIN32CLIP and sys.platform == 'win32':
            try:
                win32clipboard.OpenClipboard()
                win32clipboard.EmptyClipboard()
                win32clipboard.SetClipboardText(text)
                win32clipboard.CloseClipboard()
                success = True
            except: pass
        if success:
            if self._clipboard_clear_id: self.root.after_cancel(self._clipboard_clear_id)
            self._clipboard_clear_id = self.root.after(8000, self._clear_clipboard)
            # 尝试关闭 Windows 剪贴板历史记录，防止密码被存入历史
            if sys.platform == 'win32':
                try:
                    import winreg
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                        r'Software\Microsoft\Clipboard', 0,
                                        winreg.KEY_SET_VALUE) as k:
                        winreg.SetValueEx(k, 'EnableClipboardHistory', 0, winreg.REG_DWORD, 0)
                except: pass
            messagebox.showinfo('复制成功', '密码已复制到剪贴板，8秒后自动清除。\n'
                                         '建议关闭剪贴板历史记录(Win+V)，防止密码残留。')
        else:
            messagebox.showwarning('复制失败', '无法访问剪贴板，请手动复制以下密码：\n\n' + text)

    def _clear_clipboard(self):
        """安全清除剪贴板：覆盖所有文本格式 + 枚举清除全部格式，防止密码从历史中恢复"""
        for _ in range(3):
            junk = secrets.token_hex(64)
            try: pyperclip.copy(junk)
            except: pass
        try: self.root.clipboard_clear()
        except: pass
        if HAS_WIN32CLIP and sys.platform == 'win32':
            try:
                for _ in range(3):
                    win32clipboard.OpenClipboard()
                    win32clipboard.EmptyClipboard()
                    # 覆盖所有常见文本格式
                    junk = secrets.token_hex(64)
                    win32clipboard.SetClipboardText(junk)  # CF_UNICODETEXT
                    try:
                        # CF_TEXT = 1, CF_OEMTEXT = 7 — 用整数常量确保兼容性
                        win32clipboard.SetClipboardData(1, junk.encode('ascii', errors='replace'))
                    except: pass
                    try:
                        win32clipboard.SetClipboardData(7, junk.encode('ascii', errors='replace'))
                    except: pass
                    win32clipboard.CloseClipboard()
                # 最终清空全部格式
                win32clipboard.OpenClipboard()
                win32clipboard.EmptyClipboard()
                win32clipboard.CloseClipboard()
            except: pass

    def add_entry(self):
        dialog = EntryDialog(self.root, '添加密码')
        self.root.wait_window(dialog)
        if dialog.result:
            s, u, p = dialog.result
            self.data['entries'].append({
                'id': uuid.uuid4().hex[:8], 'site': s, 'username': u, 'password': p,
                'created': datetime.now(timezone.utc).isoformat(),
                'updated': datetime.now(timezone.utc).isoformat()
            })
            self.save(); self.refresh_list(); audit_log('添加条目', self.audit_key)

    def edit_entry(self):
        sel = self.tree.selection()
        if not sel: messagebox.showwarning('提示','请先选中一条记录'); return
        idx = int(sel[0]); e = self.data['entries'][idx]
        dialog = EntryDialog(self.root, '编辑密码', site=e['site'], username=e['username'], password=e['password'])
        self.root.wait_window(dialog)
        if dialog.result:
            s, u, p = dialog.result
            e.update({'site':s,'username':u,'password':p,'updated':datetime.now(timezone.utc).isoformat()})
            self.save(); self.refresh_list(); audit_log('编辑条目', self.audit_key)

    def delete_entry(self):
        sel = self.tree.selection()
        if not sel: messagebox.showwarning('提示','请先选中'); return
        if messagebox.askyesno('确认','确定删除？'):
            del self.data['entries'][int(sel[0])]
            self.save(); self.refresh_list(); audit_log('删除条目', self.audit_key)

    def save(self):
        self.data['audit_key'] = self.audit_key.hex()  # 直接存储，无需双层加密
        if 'settings' not in self.data:
            self.data['settings'] = {}
        # 从锁文件读取设置（仅当锁文件存在且有效时才覆盖保险库中的设置，防止锁文件缺失时静默重置）
        if os.path.exists(LOCK_FILE):
            try:
                lock_state = load_lock_state(self.vault_file)
                attempts, lock_until, max_attempts, action, _ = lock_state
                if attempts < 999:  # 非"文件缺失"的 fallback 状态
                    self.data['settings']['max_attempts'] = max_attempts
                    self.data['settings']['on_max_action'] = action
            except: pass
        atomic_save(self.vault_file, bytes(self.master_pwd), self.data)

    def open_generator(self):
        gen = GeneratorWindow(self.root); self.root.wait_window(gen)

    def open_settings(self):
        lv = self.data.get('_lock_verifier', None) if self.data else None
        dialog = SecuritySettingsDialog(self.root, self.vault_file, lock_verifier=lv)
        self.root.wait_window(dialog)

    def change_master_password(self):
        dialog = ChangePasswordDialog(self.root, self.vault_file, bytes(self.master_pwd))
        self.root.wait_window(dialog)
        if dialog.new_password:
            secure_wipe(self.master_pwd)
            self.master_pwd = bytearray(dialog.new_password.encode('utf-8'))
            try_mlock(self.master_pwd)
            self.save()
            audit_log('修改主密码', self.audit_key)
            messagebox.showinfo('成功', '主密码已更新')

    def lock(self):
        """手动锁定，重置安全锁为正常状态，防止误报24小时"""
        if self._auto_lock_id: self.root.after_cancel(self._auto_lock_id)
        self.remove_auto_lock_bindings()
        self.save()
        lv = self.data.get('_lock_verifier', None) if self.data else None
        update_lock_file(self.vault_file, 0, 0,
                         self.data.get('settings', {}).get('max_attempts', DEFAULT_MAX_ATTEMPTS),
                         self.data.get('settings', {}).get('on_max_action', DEFAULT_ON_MAX_ACTION),
                         lock_verifier=lv)
        audit_log('手动锁定', self.audit_key)
        self._clear_clipboard()  # 锁定前立即清除剪贴板
        secure_wipe(self.master_pwd)
        self.master_pwd = None; self.data = None; self.audit_key = None
        self.root.destroy()
        login = MilitaryLoginWindow(self.parent, self.vault_file)
        self.parent.wait_window(login.win)
        if login.master_pwd and login.data:
            MilitaryMainWindow(self.parent, self.vault_file, login.data, login.master_pwd,
                               login.audit_key, getattr(login,'mlock_ok',False))
        else:
            self.on_exit()

    def on_close(self):
        if self._auto_lock_id: self.root.after_cancel(self._auto_lock_id)
        self.remove_auto_lock_bindings()
        self.save()
        self._clear_clipboard()  # 退出前立即清除剪贴板
        audit_log('程序退出', self.audit_key)
        self.on_exit()

    def on_exit(self):
        if self.master_pwd: secure_wipe(self.master_pwd)
        release_running_lock(running_lock_global)   # 使用全局运行锁句柄
        self.parent.destroy()

# -------------------- 安全设置对话框 --------------------
class SecuritySettingsDialog(tk.Toplevel):
    def __init__(self, parent, vault_file, lock_verifier=None):
        super().__init__(parent)
        self.title('安全设置'); self.resizable(False, False)
        self.vault_file = vault_file
        self.lock_verifier = lock_verifier
        set_icon(self)
        lock_state = load_lock_state(vault_file)
        _, _, cur_max, cur_action, _ = lock_state
        self.max_attempts_var = tk.IntVar(value=cur_max)
        self.action_var = tk.StringVar(value=cur_action)
        ttk.Label(self, text='最大错误次数 (1-20):').pack(pady=2)
        ttk.Spinbox(self, from_=1, to=20, textvariable=self.max_attempts_var, width=5).pack(pady=2)
        ttk.Label(self, text='达到上限后的动作:').pack(pady=2)
        ttk.Radiobutton(self, text='锁定（指定分钟）', variable=self.action_var, value='lock').pack(anchor='w')
        ttk.Radiobutton(self, text='永久销毁保险库', variable=self.action_var, value='destroy').pack(anchor='w')
        ttk.Label(self, text='锁定分钟数 (仅锁定模式):').pack(pady=2)
        self.lockout_var = tk.IntVar(value=DEFAULT_LOCKOUT_TIME)
        ttk.Spinbox(self, from_=1, to=1440, textvariable=self.lockout_var, width=5).pack(pady=2)
        bf = ttk.Frame(self); bf.pack(pady=10)
        ttk.Button(bf, text='保存', command=self.save).pack(side='left', padx=4)
        ttk.Button(bf, text='取消', command=self.destroy).pack(side='left', padx=4)
        center_window(self, parent, 300, 230)

    def save(self):
        new_max = self.max_attempts_var.get()
        new_action = self.action_var.get()
        update_lock_file(self.vault_file, 0, 0, new_max, new_action,
                         lock_verifier=self.lock_verifier)
        messagebox.showinfo('成功', '安全设置已更新。')
        self.destroy()

# -------------------- 对话窗 --------------------
class EntryDialog(tk.Toplevel):
    def __init__(self, parent, title, site='', username='', password=''):
        super().__init__(parent)
        self.title(title); self.resizable(False, False); self.result = None; set_icon(self)
        ttk.Label(self, text='网站/应用:').pack(pady=2)
        self.site_var = tk.StringVar(value=site); ttk.Entry(self, textvariable=self.site_var, width=30).pack()
        ttk.Label(self, text='用户名:').pack(pady=2)
        self.user_var = tk.StringVar(value=username); ttk.Entry(self, textvariable=self.user_var, width=30).pack()
        ttk.Label(self, text='密码:').pack(pady=2)
        pf = ttk.Frame(self); pf.pack()
        self.pwd_var = tk.StringVar(value=password)
        self.pwd_entry = ttk.Entry(pf, textvariable=self.pwd_var, width=24, show='*'); self.pwd_entry.pack(side='left')
        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(pf, text='👁', variable=self.show_var, command=self.toggle_show, width=3).pack(side='left')
        ttk.Button(pf, text='生成', command=self.generate_pwd).pack(side='left', padx=4)
        bf = ttk.Frame(self); bf.pack(pady=10)
        ttk.Button(bf, text='保存', command=self.save).pack(side='left', padx=4)
        ttk.Button(bf, text='取消', command=self.destroy).pack(side='left', padx=4)
        center_window(self, parent, 340, 200)
    def toggle_show(self): self.pwd_entry.config(show='' if self.show_var.get() else '*')
    def generate_pwd(self):
        gen = GeneratorWindow(self); self.wait_window(gen)
        if gen.generated: self.pwd_var.set(gen.generated)
    def save(self):
        s = self.site_var.get().strip(); u = self.user_var.get().strip(); p = self.pwd_var.get()
        if not s or not u or not p: messagebox.showwarning('提示','所有字段必填'); return
        if len(s) > 512 or len(u) > 256: messagebox.showwarning('提示','网站或用户名过长'); return
        # 清除敏感字符串引用
        self.site_var.set(s); self.user_var.set(u)
        self.result = (s, u, p); self.destroy()

class GeneratorWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title('强密码生成器'); self.resizable(False, False); self.generated = None; set_icon(self)
        ttk.Label(self, text='长度 (8-64):').pack(pady=2)
        self.len_var = tk.IntVar(value=16)
        ttk.Scale(self, from_=8, to=64, variable=self.len_var, orient='horizontal', command=self.update).pack(fill='x', padx=20)
        self.sym_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self, text='包含符号', variable=self.sym_var, command=self.update).pack()
        self.nocon_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self, text='排除易混淆字符', variable=self.nocon_var, command=self.update).pack()
        ttk.Label(self, text='生成的密码:').pack(pady=6)
        self.pwd_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.pwd_var, width=30, font=('Courier',10)).pack()
        bf = ttk.Frame(self); bf.pack(pady=10)
        ttk.Button(bf, text='复制并关闭', command=self.copy_close).pack(side='left', padx=4)
        ttk.Button(bf, text='仅复制', command=self.copy_only).pack(side='left', padx=4)
        self.update(); center_window(self, parent, 320, 220)
    def update(self, *a):
        self.pwd_var.set(generate_password(self.len_var.get(), self.sym_var.get(), self.nocon_var.get()))
    def copy_only(self):
        pyperclip.copy(self.pwd_var.get()); messagebox.showinfo('复制成功','密码已复制')
    def copy_close(self):
        self.generated = self.pwd_var.get(); pyperclip.copy(self.generated); self.destroy()

class ChangePasswordDialog(tk.Toplevel):
    def __init__(self, parent, vault_file, current_password: bytes):
        super().__init__(parent)
        self.title('修改主密码'); self.resizable(False, False); self.new_password = None
        self.vault_file = vault_file; self.current_password = current_password; set_icon(self)
        ttk.Label(self, text='原密码:').pack()
        self.old_var = tk.StringVar(); ttk.Entry(self, textvariable=self.old_var, show='*').pack()
        ttk.Label(self, text='新密码 (至少8位):').pack()
        self.new_var = tk.StringVar(); ttk.Entry(self, textvariable=self.new_var, show='*').pack()
        ttk.Label(self, text='确认新密码:').pack()
        self.conf_var = tk.StringVar(); ttk.Entry(self, textvariable=self.conf_var, show='*').pack()
        ttk.Button(self, text='确认修改', command=self.change).pack(pady=8)
        center_window(self, parent, 280, 210)
    def change(self):
        old = self.old_var.get(); new = self.new_var.get(); conf = self.conf_var.get()
        # 提前清空 StringVar，减少密码在内存中的驻留时间
        self.old_var.set(''); self.new_var.set(''); self.conf_var.set('')
        if not old or not new or new != conf: messagebox.showwarning('提示','请正确填写'); return
        if len(new) < 8: messagebox.showwarning('提示','新密码至少8位'); return
        try:
            with open(self.vault_file, 'rb') as f: raw = f.read()
            decrypt_vault(old.encode('utf-8'), raw)
        except Exception:
            messagebox.showwarning('错误','原密码错误'); return
        self.new_password = new
        old = ''; new = ''; conf = ''  # 清除不可变 str 引用
        self.destroy()

# -------------------- 主入口（安全锁检测 + 运行锁） --------------------
if __name__ == '__main__':
    root = tk.Tk()
    root.withdraw()
    vault_file = 'vault.pass'

    # 安全检测：保险库存在但安全锁文件缺失 → 强制锁定并退出
    if os.path.exists(vault_file) and not os.path.exists(LOCK_FILE):
        messagebox.showerror('安全警告', '安全锁文件丢失，保险库已锁定24小时。')
        sys.exit(1)

    # 获取运行锁（独立文件，自动回收残留锁）
    running_lock_global = acquire_running_lock()
    if running_lock_global is None:
        messagebox.showerror('错误', '程序已在运行中，请先关闭其他 LynPass 窗口。')
        sys.exit(1)

    login = MilitaryLoginWindow(root, vault_file)
    root.wait_window(login.win)

    if login.master_pwd is not None and login.data is not None:
        MilitaryMainWindow(root, vault_file, login.data, login.master_pwd,
                           login.audit_key, getattr(login, 'mlock_ok', False))
        root.mainloop()
    else:
        release_running_lock(running_lock_global)
        sys.exit()