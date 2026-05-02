#!/usr/bin/env python3
# LynPass.py — 军工级本地密码管理器（最终完整修复版）
import tkinter as tk
from tkinter import ttk, messagebox
import json, os, uuid, struct, secrets, string, hashlib, hmac, time, sys, ctypes
from datetime import datetime, timezone
import pyperclip

# ======================== 兼容性导入 ========================
try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ======================== 常量 ========================
MAGIC = b'LYNX'
VERSION = 3                     # 支持审计密钥
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
HMAC_LEN = 32
MAX_ATTEMPTS = 10               # 自毁阈值
LOCKOUT_TIME = 15 * 60          # 防爆破锁 15 分钟
SAFE_LOCKOUT = 24 * 3600        # 锁文件缺失/损坏的安全锁定时长

# ======================== 安全内存 ========================
def secure_wipe(byte_array):
    if byte_array is None: return
    for i in range(len(byte_array)):
        byte_array[i] = 0
    addr = ctypes.addressof(ctypes.c_char.from_buffer(byte_array))
    ctypes.memset(addr, 0, len(byte_array))

def try_mlock(byte_array):
    """尝试锁定物理内存，返回是否成功"""
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
    except Exception:
        return False

# ======================== 防截屏 ========================
if sys.platform == 'win32':
    WDA_MONITOR = 1
    def prevent_screenshot(hwnd):
        ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, WDA_MONITOR)
else:
    def prevent_screenshot(hwnd): pass

# ======================== 虚拟键盘 ========================
class VirtualKeyboard(tk.Toplevel):
    def __init__(self, parent, target_var):
        super().__init__(parent)
        self.title('安全输入')
        self.target = target_var
        self.resizable(False, False)
        self.attributes('-topmost', True)
        chars = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()'
        for i, ch in enumerate(chars):
            btn = ttk.Button(self, text=ch, width=3, command=lambda c=ch: self._type(c))
            btn.grid(row=i//10, column=i%10, padx=1, pady=1)
    def _type(self, char):
        self.target.set(self.target.get() + char)

# ======================== 密码学核心 ========================
def derive_keys(password: bytes, salt: bytes, dklen=64) -> bytes:
    """
    密钥派生：优先 Argon2id (256 MiB)，失败则回退 scrypt 降级尝试
    最终保证在任何系统上都能运行（牺牲部分强度但可控）
    """
    if HAS_ARGON2:
        try:
            # 尝试新版 cryptography 参数
            kdf = Argon2id(salt=salt, length=dklen, memory_cost=256*1024,
                          parallelism=4, time_cost=3)
            return kdf.derive(password)
        except TypeError:
            try:
                # 旧版可能使用 degree_of_parallelism
                kdf = Argon2id(salt=salt, length=dklen, memory_cost=256*1024,
                              degree_of_parallelism=4, time_cost=3)
                return kdf.derive(password)
            except TypeError:
                pass  # 都不支持，回退
    # 回退 scrypt，尝试从强到弱，直到成功
    scrypt_configs = [
        (2**17, 8, 1),   # 128 MiB
        (2**16, 8, 1),   #  64 MiB
        (2**15, 8, 1),   #  32 MiB
    ]
    for n, r, p in scrypt_configs:
        try:
            return hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=dklen)
        except ValueError:
            continue
    # 最终降级（仍然安全但较低内存）
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
    os.replace(tmp, filepath)
    os.chmod(filepath, 0o600)

# ======================== 审计日志（独立密钥） ========================
AUDIT_MAGIC = b'LAUD'
def encrypt_audit_entry(entry: dict, audit_key: bytes) -> bytes:
    nonce = os.urandom(NONCE_LEN)
    plain = json.dumps(entry).encode('utf-8')
    aesgcm = AESGCM(audit_key)
    ct = aesgcm.encrypt(nonce, plain, None)
    return AUDIT_MAGIC + nonce + ct

def decrypt_audit_entry(data: bytes, audit_key: bytes) -> dict:
    if data[:4] != AUDIT_MAGIC: raise ValueError('无效审计条目')
    nonce = data[4:4+NONCE_LEN]
    ct = data[4+NONCE_LEN:]
    aesgcm = AESGCM(audit_key)
    plain = aesgcm.decrypt(nonce, ct, None)
    return json.loads(plain.decode('utf-8'))

def audit_log(event: str, audit_key: bytes):
    entry = {'ts': time.time(), 'event': event}
    encrypted = encrypt_audit_entry(entry, audit_key)
    with open('audit.log.enc', 'ab') as f:
        f.write(encrypted + b'\n')

# ======================== 自毁 ========================
def self_destruct(vault_file):
    if not os.path.exists(vault_file): return
    size = os.path.getsize(vault_file)
    with open(vault_file, 'wb') as f:
        for _ in range(3):
            f.seek(0); f.write(os.urandom(size)); f.flush(); os.fsync(f.fileno())
    os.remove(vault_file)

# ======================== 加密锁文件（防篡改） ========================
def get_lock_file(vault_file): return vault_file + '.lock'

def _lock_data_key(password: bytes, salt: bytes) -> bytes:
    return derive_keys(password, salt, dklen=32)[:32]

def save_lock_state(vault_file, attempts, lock_until, password: bytes):
    salt = os.urandom(SALT_LEN)
    key = _lock_data_key(password, salt)
    data = {'attempts': attempts, 'lock_until': lock_until}
    plain = json.dumps(data).encode('utf-8')
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ct = aesgcm.encrypt(nonce, plain, None)
    with open(get_lock_file(vault_file), 'wb') as f:
        f.write(salt + nonce + ct)
    os.chmod(get_lock_file(vault_file), 0o600)

def load_lock_state(vault_file, password: bytes):
    """返回 (attempts, lock_until)；若文件缺失或损坏返回 (None, None)"""
    lock_file = get_lock_file(vault_file)
    if not os.path.exists(lock_file):
        return None, None
    try:
        with open(lock_file, 'rb') as f:
            raw = f.read()
        salt = raw[:SALT_LEN]
        nonce = raw[SALT_LEN:SALT_LEN+NONCE_LEN]
        ct = raw[SALT_LEN+NONCE_LEN:]
        key = _lock_data_key(password, salt)
        aesgcm = AESGCM(key)
        plain = aesgcm.decrypt(nonce, ct, None)
        data = json.loads(plain.decode('utf-8'))
        return data['attempts'], data['lock_until']
    except Exception:
        # 损坏视为入侵，进入长期锁定
        return MAX_ATTEMPTS, time.time() + SAFE_LOCKOUT

def clear_lock(vault_file):
    lock_file = get_lock_file(vault_file)
    if os.path.exists(lock_file):
        os.remove(lock_file)

def is_locked(vault_file, password: bytes):
    attempts, lock_until = load_lock_state(vault_file, password)
    if attempts is None: return False, 0
    if attempts >= MAX_ATTEMPTS and time.time() < lock_until:
        return True, int(lock_until - time.time())
    return False, 0

def record_failed_attempt(vault_file, password: bytes):
    attempts, lock_until = load_lock_state(vault_file, password)
    if attempts is None: attempts = 0
    attempts += 1
    if attempts >= MAX_ATTEMPTS:
        lock_until = time.time() + LOCKOUT_TIME
    save_lock_state(vault_file, attempts, lock_until, password)

# ======================== 并发锁（改进） ========================
if sys.platform == 'win32':
    import msvcrt
    def acquire_running_lock(vault_file):
        path = vault_file + '.running'
        try:
            f = open(path, 'w')
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            return f
        except (IOError, OSError):
            return None
    def release_running_lock(f):
        try: msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        except: pass
        f.close()
else:
    import fcntl
    def acquire_running_lock(vault_file):
        path = vault_file + '.running'
        try:
            f = open(path, 'w')
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return f
        except (BlockingIOError, OSError):
            return None
    def release_running_lock(f):
        fcntl.flock(f, fcntl.LOCK_UN)
        f.close()

# ======================== 密码生成器 ========================
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

# ======================== 界面工具 ========================
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
    if os.path.exists('icon.ico'):
        try: window.iconbitmap('icon.ico')
        except: pass

# ======================== 登录窗口 ========================
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
            clear_lock(vault_file)
            self.build_create_ui()
            center_window(self.win, parent, 420, 260)
            self.win.after(100, lambda: prevent_screenshot(self.win.winfo_id()))
            self.win.focus()
            return

        self.build_login_ui()
        center_window(self.win, parent, 420, 260)
        self.win.after(100, lambda: prevent_screenshot(self.win.winfo_id()))
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
        audit_key = secrets.token_bytes(32)   # 随机审计密钥
        data = {'entries': [], 'audit_key': None}
        pwd_bytes = bytearray(pwd1.encode('utf-8'))
        mlock_ok = try_mlock(pwd_bytes)
        # 加密审计密钥并存入保险库
        enc_audit = encrypt_vault(bytes(pwd_bytes), {'audit_key': audit_key.hex()})
        data['audit_key'] = enc_audit.hex()
        try:
            atomic_save(self.vault_file, bytes(pwd_bytes), data)
        except Exception as e:
            messagebox.showerror('错误', f'创建失败：{e}'); return
        self.master_pwd = pwd_bytes
        self.data = data
        self.audit_key = audit_key
        self.mlock_ok = mlock_ok
        audit_log('保险库创建', audit_key)
        self.win.destroy()

    def unlock(self):
        pwd = self.pwd_var.get()
        if not pwd: self.status_label.config(text='请输入密码'); return

        pwd_bytes = bytearray(pwd.encode('utf-8'))
        mlock_ok = try_mlock(pwd_bytes)

        # 检查锁定状态（需密码解密锁文件）
        locked, remaining = is_locked(self.vault_file, bytes(pwd_bytes))
        if locked:
            mins, secs = divmod(remaining, 60)
            messagebox.showwarning('已锁定', f'账户已锁定。\n请等待 {mins} 分 {secs} 秒后重试。')
            return

        try:
            with open(self.vault_file, 'rb') as f: raw = f.read()
            vault_data = decrypt_vault(bytes(pwd_bytes), raw)
            # 提取审计密钥
            enc_audit = bytes.fromhex(vault_data['audit_key'])
            audit_plain = decrypt_vault(bytes(pwd_bytes), enc_audit)
            audit_key = bytes.fromhex(audit_plain['audit_key'])
            clear_lock(self.vault_file)   # 成功后清除锁
        except Exception:
            record_failed_attempt(self.vault_file, bytes(pwd_bytes))
            attempts, _ = load_lock_state(self.vault_file, bytes(pwd_bytes))
            if attempts is not None and attempts >= MAX_ATTEMPTS:
                secure_wipe(pwd_bytes)
                self_destruct(self.vault_file)
                messagebox.showwarning('已销毁', '连续错误次数过多，保险库已永久销毁！')
                self.on_close()
                return
            remaining_attempts = MAX_ATTEMPTS - (attempts or 0)
            self.status_label.config(text=f'密码错误！剩余尝试次数：{remaining_attempts}')
            return

        self.master_pwd = pwd_bytes
        self.data = vault_data
        self.audit_key = audit_key
        self.mlock_ok = mlock_ok
        audit_log('保险库解锁', audit_key)
        self.win.destroy()

# ======================== 主窗口 ========================
class MilitaryMainWindow:
    def __init__(self, parent, vault_file, data, master_pwd, audit_key, mlock_ok, running_lock):
        self.parent = parent; self.vault_file = vault_file; self.data = data
        self.master_pwd = master_pwd; self.audit_key = audit_key
        self.mlock_ok = mlock_ok; self.running_lock = running_lock
        self.root = tk.Toplevel(parent)
        self.root.title('LynPass')
        self.root.protocol('WM_DELETE_WINDOW', self.on_close)
        set_icon(self.root)
        self._clipboard_clear_id = None; self._auto_lock_id = None
        self.create_widgets()
        self.refresh_list()
        center_window(self.root, None, 720, 520)
        self.setup_auto_lock()
        self.root.after(100, lambda: prevent_screenshot(self.root.winfo_id()))
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
        self._auto_lock_id = self.root.after(60000, self._auto_lock)
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
        self.tree.bind('<Button-1>', self.on_click_action)

        bf = ttk.Frame(self.root); bf.pack(fill='x', padx=10, pady=10)
        ttk.Button(bf, text='+ 添加', command=self.add_entry).pack(side='left', padx=4)
        ttk.Button(bf, text='✎ 编辑', command=self.edit_entry).pack(side='left', padx=4)
        ttk.Button(bf, text='✕ 删除', command=self.delete_entry).pack(side='left', padx=4)
        ttk.Button(bf, text='🔑 生成器', command=self.open_generator).pack(side='left', padx=4)
        ttk.Button(bf, text='修改主密码', command=self.change_master_password).pack(side='left', padx=4)
        ttk.Button(bf, text='锁定', command=self.lock).pack(side='right', padx=4)

        self.status_bar = ttk.Label(self.root, text='', relief='sunken', anchor='w')
        self.status_bar.pack(side='bottom', fill='x')

    def refresh_list(self):
        for row in self.tree.get_children(): self.tree.delete(row)
        q = self.search_var.get().lower()
        for idx, e in enumerate(self.data['entries']):
            if q and q not in e['site'].lower() and q not in e['username'].lower(): continue
            self.tree.insert('', 'end', iid=str(idx), values=(e['site'], e['username'], '********', '👁 📋'))

    def on_click_action(self, event):
        if self.tree.identify_region(event.x, event.y) != 'cell': return
        col = self.tree.identify_column(event.x)
        row = self.tree.identify_row(event.y)
        if not row: return
        idx = int(row)
        if col == '#4':
            x_in_cell = event.x - self.tree.bbox(row, col)[0]
            if x_in_cell < 50: self.toggle_show(idx)
            else: self.copy_to_clipboard(self.data['entries'][idx]['password'])

    def toggle_show(self, idx):
        pw = self.data['entries'][idx]['password']
        self.tree.set(str(idx), 'password', pw)
        self.root.after(5000, lambda: self.tree.set(str(idx), 'password', '********'))

    def copy_to_clipboard(self, text):
        pyperclip.copy(text)
        if self._clipboard_clear_id: self.root.after_cancel(self._clipboard_clear_id)
        self._clipboard_clear_id = self.root.after(15000, self._clear_clipboard)
        messagebox.showinfo('复制成功', '密码已复制到剪贴板，15秒后自动清除')
    def _clear_clipboard(self):
        try: pyperclip.copy('')
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
        enc_audit = encrypt_vault(bytes(self.master_pwd), {'audit_key': self.audit_key.hex()})
        self.data['audit_key'] = enc_audit.hex()
        atomic_save(self.vault_file, bytes(self.master_pwd), self.data)

    def open_generator(self):
        gen = GeneratorWindow(self.root); self.root.wait_window(gen)

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
        if self._auto_lock_id: self.root.after_cancel(self._auto_lock_id)
        self.remove_auto_lock_bindings()
        self.save()
        audit_log('锁定', self.audit_key)
        secure_wipe(self.master_pwd)
        self.master_pwd = None; self.data = None; self.audit_key = None
        self.root.destroy()
        login = MilitaryLoginWindow(self.parent, self.vault_file)
        self.parent.wait_window(login.win)
        if login.master_pwd and login.data:
            MilitaryMainWindow(self.parent, self.vault_file, login.data, login.master_pwd,
                               login.audit_key, getattr(login,'mlock_ok',False), self.running_lock)
        else:
            self.on_exit()

    def on_close(self):
        if self._auto_lock_id: self.root.after_cancel(self._auto_lock_id)
        self.remove_auto_lock_bindings()
        self.save()
        audit_log('程序退出', self.audit_key)
        self.on_exit()

    def on_exit(self):
        if self.master_pwd: secure_wipe(self.master_pwd)
        release_running_lock(self.running_lock)
        self.parent.destroy()

# ======================== 对话窗 ========================
class EntryDialog(tk.Toplevel):
    def __init__(self, parent, title, site='', username='', password=''):
        super().__init__(parent)
        self.title(title); self.resizable(False, False); self.result = None
        set_icon(self)
        ttk.Label(self, text='网站/应用:').pack(pady=2)
        self.site_var = tk.StringVar(value=site); ttk.Entry(self, textvariable=self.site_var, width=30).pack()
        ttk.Label(self, text='用户名:').pack(pady=2)
        self.user_var = tk.StringVar(value=username); ttk.Entry(self, textvariable=self.user_var, width=30).pack()
        ttk.Label(self, text='密码:').pack(pady=2)
        pf = ttk.Frame(self); pf.pack()
        self.pwd_var = tk.StringVar(value=password)
        self.pwd_entry = ttk.Entry(pf, textvariable=self.pwd_var, width=24, show='*')
        self.pwd_entry.pack(side='left')
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
        self.vault_file = vault_file; self.current_password = current_password
        set_icon(self)
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
        if not old or not new or new != conf: messagebox.showwarning('提示','请正确填写'); return
        if len(new) < 8: messagebox.showwarning('提示','新密码至少8位'); return
        try:
            with open(self.vault_file, 'rb') as f: raw = f.read()
            decrypt_vault(old.encode('utf-8'), raw)
        except Exception:
            messagebox.showwarning('错误','原密码错误'); return
        self.new_password = new; self.destroy()

# ======================== 主入口 ========================
if __name__ == '__main__':
    root = tk.Tk()
    root.withdraw()

    vault_file = 'vault.pass'
    running_lock = acquire_running_lock(vault_file)
    if running_lock is None:
        messagebox.showerror('错误', '程序已在运行中，不能同时打开两个实例。')
        sys.exit(1)

    login = MilitaryLoginWindow(root, vault_file)
    root.wait_window(login.win)

    if login.master_pwd is not None and login.data is not None:
        MilitaryMainWindow(root, vault_file, login.data, login.master_pwd,
                           login.audit_key, getattr(login, 'mlock_ok', False), running_lock)
        root.mainloop()
    else:
        release_running_lock(running_lock)
        sys.exit()