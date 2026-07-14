# -*- coding: utf-8 -*-
"""
Auto Reset DB Tool - Core v4.9.1 (Dark Slate Modern)
- UI Tkinter quản lý cấu hình DB (lưu/ sửa/ xóa/ dùng)
- Reset kết nối PostgreSQL thủ công / tự động theo thời gian tùy chọn
- Log ra file TXT theo ngày: Log/db_reset_YYYYMMDD.txt
- Mã hóa password bằng Fernet (secret.key lưu trong thư mục app)
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext, Menu, Canvas, ttk
import json, os, time, threading, subprocess
from datetime import datetime
import psycopg2
from cryptography.fernet import Fernet

# ===================== WIN32 API DECLARATIONS =====================
if sys.platform.startswith('win'):
    import ctypes
    user32 = ctypes.windll.user32
    GWL_STYLE = -16
    WS_CHILD = 0x40000000
    WS_CAPTION = 0x00C00000
    WS_THICKFRAME = 0x00040000
    WS_MINIMIZEBOX = 0x00020000
    WS_MAXIMIZEBOX = 0x00010000
    WS_SYSMENU = 0x00080000
    SWP_NOZORDER = 0x0004
    SWP_FRAMECHANGED = 0x0020
else:
    user32 = None

# ===================== CONFIG =====================
CONFIG_FILE = "db_config.json"
LOG_DIR = "Log"
SECRET_KEY_FILE = "secret.key"
APP_DIR = os.path.dirname(os.path.abspath(__file__))
SECRET_KEY_PATH = os.path.join(APP_DIR, SECRET_KEY_FILE)

running = False
reset_thread = None
CONFIG_CACHE = []
edit_mode = False
selected_label = None
last_selected_name = ""

# ===================== ENCRYPTION =====================
def load_or_create_key():
    try:
        if not os.path.exists(SECRET_KEY_PATH):
            key = Fernet.generate_key()
            with open(SECRET_KEY_PATH, "wb") as f: f.write(key)
        else:
            with open(SECRET_KEY_PATH, "rb") as f: key = f.read()
        return Fernet(key)
    except Exception as e:
        messagebox.showerror("Lỗi tạo key", str(e))
        raise SystemExit

fernet = load_or_create_key()
def encrypt_password(p): return fernet.encrypt(p.encode()).decode()
def decrypt_password(p):
    try: return fernet.decrypt(p.encode()).decode()
    except: return "•••••"

# ===================== LOGGING =====================
def get_log_file():
    today = datetime.now().strftime("%Y%m%d")
    log_dir = os.path.join(APP_DIR, LOG_DIR)
    if not os.path.exists(log_dir): os.makedirs(log_dir)
    return os.path.join(log_dir, f"db_reset_{today}.txt")

def log_message(msg):
    try:
        log_area.insert(tk.END, msg + "\n")
        log_area.yview(tk.END)
    except Exception:
        pass
    try:
        with open(get_log_file(), "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}\n")
    except Exception:
        pass

def clear_log_display():
    log_area.delete(1.0, tk.END)
    log_message("🧹 Log hiển thị đã được làm mới (file log vẫn giữ nguyên).")

# ===================== CONFIG MANAGEMENT =====================
def load_config_cache():
    global CONFIG_CACHE
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                CONFIG_CACHE = json.load(f).get("configs", [])
        except Exception:
            CONFIG_CACHE = []
    else:
        CONFIG_CACHE = []

def save_config_cache():
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump({"configs": CONFIG_CACHE}, f, indent=2, ensure_ascii=False)

def set_entry_state(readonly=True):
    state = "readonly" if readonly else "normal"
    for e in [entry_host, entry_port, entry_db, entry_user, entry_pass, entry_server]:
        e.config(state=state)

def set_placeholder(entry, text):
    entry.delete(0, tk.END)
    entry.insert(0, text)
    entry.config(fg="#a1a1aa")
    def on_focus_in(event):
        if entry.get() == text and entry.cget("state") == "normal":
            entry.delete(0, "end")
            entry.config(fg="#ffffff")
    def on_focus_out(event):
        if entry.get() == "" and entry.cget("state") == "normal":
            entry.insert(0, text)
            entry.config(fg="#a1a1aa")
    entry.bind("<FocusIn>", on_focus_in)
    entry.bind("<FocusOut>", on_focus_out)

def clear_form():
    global edit_mode, selected_label, last_selected_name
    for e in [entry_host, entry_port, entry_db, entry_user, entry_pass, entry_server]:
        e.config(state="normal")
        e.delete(0, tk.END)
        e.config(fg="#ffffff")
    set_placeholder(entry_host, "localhost hoặc 192.168.x.x")
    set_placeholder(entry_port, "7001,6688")
    set_placeholder(entry_db, "Nhập tên database")
    entry_user.insert(0, "postgres")
    set_placeholder(entry_server, "servername")
    
    # reset interval fields
    entry_interval.config(state="normal")
    entry_interval.delete(0, tk.END)
    entry_interval.insert(0, "1")
    combo_unit.config(state="readonly")
    combo_unit.set("Giờ")

    selected_config.set("")
    selected_label = None
    last_selected_name = ""
    edit_mode = False
    btn_edit.config(text="✏️ Sửa", bg="#f59e0b", command=toggle_edit_mode)
    btn_save.config(state="normal")
    hide_action_buttons()

def add_new_config():
    name = entry_server.get().strip()
    if not name or entry_server.cget("fg") == "#a1a1aa":
        messagebox.showwarning("Thiếu thông tin", "Vui lòng nhập tên Server."); return
    if any(c["name"].lower() == name.lower() for c in CONFIG_CACHE):
        messagebox.showerror("Trùng tên", f"Cấu hình '{name}' đã tồn tại!"); return
    required = [
        entry_host.get().strip() if entry_host.cget("fg") != "#a1a1aa" else "",
        entry_port.get().strip() if entry_port.cget("fg") != "#a1a1aa" else "",
        entry_db.get().strip()   if entry_db.cget("fg") != "#a1a1aa" else "",
        entry_user.get().strip()
    ]
    if any(v == "" for v in required):
        messagebox.showwarning("Thiếu thông tin", "Vui lòng nhập đầy đủ Host, Port, DB, User."); return
    cfg = {
        "name": name,
        "host": entry_host.get(),
        "port": entry_port.get(),
        "db": entry_db.get(),
        "user": entry_user.get(),
        "password": encrypt_password(entry_pass.get()),
        "interval_val": entry_interval.get().strip(),
        "interval_unit": combo_unit.get(),
        "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    CONFIG_CACHE.append(cfg)
    save_config_cache()
    refresh_data_list()
    messagebox.showinfo("Thành công", f"Đã thêm cấu hình '{name}'.")

def on_select_config(cfg_name):
    global selected_label, last_selected_name
    if last_selected_name == cfg_name:
        hide_action_buttons()
        last_selected_name = ""
        selected_config.set("")
        if selected_label and selected_label.winfo_exists():
            selected_label.config(bg="#27272a", fg="#f4f4f5")
        btn_save.config(state="normal")
        return

    last_selected_name = cfg_name
    cfg = next((c for c in CONFIG_CACHE if c["name"] == cfg_name), None)
    if not cfg: return

    for w in scroll_frame.winfo_children(): w.config(bg="#27272a", fg="#f4f4f5")
    selected_label = [w for w in scroll_frame.winfo_children() if w.cget("text") == cfg_name][0]
    selected_label.config(bg="#4f46e5", fg="#ffffff")

    set_entry_state(False)
    for e in (entry_host, entry_port, entry_db, entry_user, entry_server):
        e.config(fg="#ffffff")
    entry_host.delete(0, tk.END); entry_host.insert(0, cfg["host"])
    entry_port.delete(0, tk.END); entry_port.insert(0, cfg["port"])
    entry_db.delete(0, tk.END); entry_db.insert(0, cfg["db"])
    entry_user.delete(0, tk.END); entry_user.insert(0, cfg["user"])
    entry_pass.delete(0, tk.END); entry_pass.insert(0, decrypt_password(cfg["password"]))
    entry_server.delete(0, tk.END); entry_server.insert(0, cfg["name"])
    
    entry_interval.delete(0, tk.END)
    entry_interval.insert(0, cfg.get("interval_val", "1"))
    combo_unit.set(cfg.get("interval_unit", "Giờ"))
    set_entry_state(True)

    show_action_buttons()
    btn_save.config(state="disabled")

def toggle_edit_mode():
    global edit_mode
    if not last_selected_name:
        messagebox.showinfo("Thông báo", "Vui lòng chọn cấu hình để sửa."); return
    if not edit_mode:
        set_entry_state(False)
        edit_mode = True
        btn_edit.config(text="💾 Lưu", bg="#3b82f6", command=save_edit_changes)

def save_edit_changes():
    global edit_mode
    old_name = last_selected_name
    new_name = entry_server.get().strip()
    if any(c["name"].lower() == new_name.lower() and c["name"].lower() != old_name.lower() for c in CONFIG_CACHE):
        messagebox.showerror("Tên bị trùng", f"Tên '{new_name}' đã tồn tại!"); return
    for i, c in enumerate(CONFIG_CACHE):
        if c["name"].lower() == old_name.lower():
            CONFIG_CACHE[i] = {
                "name": new_name,
                "host": entry_host.get(),
                "port": entry_port.get(),
                "db": entry_db.get(),
                "user": entry_user.get(),
                "password": encrypt_password(entry_pass.get()),
                "interval_val": entry_interval.get().strip(),
                "interval_unit": combo_unit.get(),
                "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            break
    save_config_cache()
    refresh_data_list()
    edit_mode = False
    btn_edit.config(text="✏️ Sửa", bg="#f59e0b", command=toggle_edit_mode)
    btn_save.config(state="normal")

def delete_config():
    global last_selected_name
    name = last_selected_name
    if not name: return
    if not messagebox.askyesno("Xác nhận", f"Bạn có chắc chắn muốn xóa '{name}'? \nCác thông tin sau khi xoá sẽ không thể khôi phục lại được."): return
    CONFIG_CACHE[:] = [c for c in CONFIG_CACHE if c["name"] != name]
    save_config_cache()
    refresh_data_list()
    clear_form()

def refresh_data_list():
    for w in scroll_frame.winfo_children(): w.destroy()
    for cfg in CONFIG_CACHE:
        lbl = tk.Label(scroll_frame, text=cfg["name"], bg="#27272a", fg="#f4f4f5", 
                       anchor="w", font=("Segoe UI", 10), padx=8, pady=4, cursor="hand2")
        lbl.bind("<Enter>", lambda e, b=lbl: b.config(bg="#3f3f46") if b.cget("bg") == "#27272a" else None)
        lbl.bind("<Leave>", lambda e, b=lbl: b.config(bg="#27272a") if b.cget("bg") == "#3f3f46" else None)
        lbl.bind("<Button-1>", lambda e, name=cfg["name"]: on_select_config(name))
        lbl.pack(fill="x", padx=5, pady=2)
    hide_action_buttons()

# ===================== CONNECTION & RESET =====================
def test_connection():
    try:
        conn = psycopg2.connect(
            host=entry_host.get(),
            port=int(entry_port.get().split(",")[0]),
            database=entry_db.get(),
            user=entry_user.get(),
            password=entry_pass.get(),
            connect_timeout=5)
        conn.close()
        log_message("✅ Test connection OK.")
    except Exception as e:
        log_message(f"❌ Test connection failed: {e}")

def reset_connection(manual=False):
    host, ports, db, user, pw, name = (
        entry_host.get(),
        entry_port.get().split(","),
        entry_db.get(),
        entry_user.get(),
        entry_pass.get(),
        entry_server.get()
    )

    for p in ports:
        try:
            conn = psycopg2.connect(
                host=host,
                port=int(p.strip()),
                database=db,
                user=user,
                password=pw,
                connect_timeout=5
            )
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT pg_terminate_backend(pid)
                    FROM pg_stat_activity
                    WHERE pid <> pg_backend_pid()
                    AND state = 'idle'
                    AND state_change < current_timestamp - INTERVAL '1' MINUTE;
                """)
            conn.commit()
            conn.close()
            log_message(f"🔄 [{name}] Successful DB reset \nPort {p.strip()} ({'Manual' if manual else 'Auto'})")
        except Exception as e:
            log_message(f"❌ [{name}] Reset failed: {e}")

def start_auto_reset():
    global running, reset_thread
    if running: return
    running = True
    reset_thread = threading.Thread(target=auto_reset_loop, daemon=True)
    reset_thread.start()
    log_message("▶️ Auto reset started.")
    btn_auto.config(state="disabled", bg="#27272a", cursor="arrow")
    btn_stop.config(state="normal", bg="#ef4444", cursor="hand2")
    entry_interval.config(state="readonly")
    combo_unit.config(state="disabled")

def auto_reset_loop():
    global running
    while running:
        try:
            try:
                val = float(entry_interval.get().strip())
            except ValueError:
                val = 1.0
                log_message("⚠️ Thời gian lặp không hợp lệ, sử dụng mặc định 1 giờ.")
            
            unit = combo_unit.get()
            if unit == "Giờ":
                reset_interval = int(val * 3600)
                time_str = f"{val:.1f}".rstrip('0').rstrip('.') + " giờ"
            elif unit == "Phút":
                reset_interval = int(val * 60)
                time_str = f"{val:.1f}".rstrip('0').rstrip('.') + " phút"
            else:
                reset_interval = int(val)
                time_str = f"{val:.1f}".rstrip('0').rstrip('.') + " giây"
                
            reset_connection()
            log_message(f"⏰ Chờ {time_str} trước lần reset tiếp theo...\n")
        except Exception as e:
            import traceback
            log_message(f"❌ Lỗi luồng Auto Reset: {e}\n{traceback.format_exc()}")
            reset_interval = 60
        time.sleep(reset_interval)

def stop_auto_reset():
    global running
    running = False
    log_message("🛑 Auto reset stopped.")
    btn_auto.config(state="normal", bg="#10b981", cursor="hand2")
    btn_stop.config(state="disabled", bg="#27272a", cursor="arrow")
    entry_interval.config(state="normal")
    combo_unit.config(state="readonly")

electron_process = None
electron_hwnd = None
is_launching = False

def find_hwnd_by_title(title_substring):
    if not user32:
        return None
    hwnd_found = []
    def enum_windows_callback(hwnd, lParam):
        if user32.IsWindowVisible(hwnd):
            length = user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                if title_substring.lower() in buf.value.lower():
                    hwnd_found.append(hwnd)
                    return False
        return True
    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    user32.EnumWindows(WNDENUMPROC(enum_windows_callback), 0)
    return hwnd_found[0] if hwnd_found else None

def resize_electron(event=None):
    global electron_hwnd
    if user32 and electron_hwnd:
        try:
            w = frame_embed.winfo_width()
            h = frame_embed.winfo_height()
            user32.MoveWindow(electron_hwnd, 0, 0, w, h, True)
        except Exception:
            pass

def embed_electron_window(hwnd):
    global lbl_loading, electron_hwnd
    electron_hwnd = hwnd
    try:
        lbl_loading.pack_forget()
    except Exception:
        pass
    
    try:
        style = user32.GetWindowLongW(hwnd, GWL_STYLE)
        style &= ~(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU)
        style |= WS_CHILD
        user32.SetWindowLongW(hwnd, GWL_STYLE, style)
        
        parent_hwnd = frame_embed.winfo_id()
        user32.SetParent(hwnd, parent_hwnd)
        
        resize_electron()
        user32.SetWindowPos(hwnd, 0, 0, 0, frame_embed.winfo_width(), frame_embed.winfo_height(), SWP_NOZORDER | SWP_FRAMECHANGED)
    except Exception as e:
        log_message(f"❌ Lỗi khi nhúng cửa sổ: {e}")

def launch_signature_cropper():
    global electron_process, electron_hwnd, is_launching
    
    try:
        switch_tab(1)
    except Exception:
        pass

    if electron_hwnd and user32 and user32.IsWindow(electron_hwnd):
        resize_electron()
        return

    if is_launching:
        return

    root_dir = os.path.dirname(APP_DIR)
    add_chuky_dir = os.path.join(root_dir, "AddChuKy")
    if not os.path.exists(add_chuky_dir):
        messagebox.showerror(
            "Không tìm thấy thư mục",
            f"Không tìm thấy thư mục 'AddChuKy' tại:\n{add_chuky_dir}"
        )
        return

    is_launching = True
    
    try:
        lbl_loading.pack(pady=50)
        lbl_loading.config(text="Đang khởi chạy Signature Cropper...")
    except Exception:
        pass

    exe_path = os.path.join(
        add_chuky_dir,
        "release",
        "Tool Cut Image-win32-x64",
        "Tool Cut Image.exe"
    )

    try:
        if os.path.exists(exe_path):
            log_message("🖋️ Khởi chạy Signature Cropper (bản đóng gói)...")
            electron_process = subprocess.Popen([exe_path])
        else:
            log_message("🖋️ Khởi chạy Signature Cropper (bản dev)...")
            if sys.platform.startswith('win'):
                electron_process = subprocess.Popen("npm run electron:dev", shell=True, cwd=add_chuky_dir)
            else:
                electron_process = subprocess.Popen(["npm", "run", "electron:dev"], cwd=add_chuky_dir)
    except Exception as e:
        is_launching = False
        messagebox.showerror("Lỗi khởi chạy", f"Không thể khởi chạy:\n{e}")
        return

    def poll_hwnd(retries=0):
        global electron_hwnd, is_launching
        if retries > 60:
            is_launching = False
            try:
                lbl_loading.config(text="⚠️ Khởi chạy quá giờ hoặc lỗi. Hãy thử chuyển lại tab.")
            except Exception:
                pass
            return
        
        hwnd = find_hwnd_by_title("Signature Cropper")
        if hwnd:
            embed_electron_window(hwnd)
            is_launching = False
        else:
            app.after(200, lambda: poll_hwnd(retries + 1))

    app.after(500, poll_hwnd)

# ===================== UI =====================
def create_modern_button(parent, text, bg, hover_bg, command, fg="#ffffff", font_size=10, font_weight="bold"):
    btn = tk.Button(parent, text=text, bg=bg, fg=fg, activebackground=hover_bg, 
                    activeforeground=fg, relief="flat", bd=0, 
                    font=("Segoe UI", font_size, font_weight), cursor="hand2",
                    disabledforeground="#71717a")
    btn.bind("<Enter>", lambda e: btn.config(bg=hover_bg, cursor="hand2") if btn.cget("state") == "normal" else btn.config(cursor="arrow"))
    btn.bind("<Leave>", lambda e: btn.config(bg=bg) if btn.cget("state") == "normal" else None)
    btn.config(command=command)
    return btn

app = tk.Tk()
app.title("Auto Reset DB Tool")
app.geometry("1200x800")
app.configure(bg="#121214")

# Cấu hình thanh điều hướng trên cùng (Custom Navigation Bar)
frame_navbar = tk.Frame(app, bg="#1a1a24", height=45)
frame_navbar.pack(fill="x", side="top")
frame_navbar.pack_propagate(False)

# Đường kẻ phân tách mỏng
divider = tk.Frame(app, bg="#2d2d3a", height=1)
divider.pack(fill="x", side="top")

# Khung chứa nội dung chính
frame_content = tk.Frame(app, bg="#121214")
frame_content.pack(fill="both", expand=True)

# Tab 1: Reset Connect
tab_reset = tk.Frame(frame_content, bg="#121214")
tab_reset.pack(fill="both", expand=True)

# Tab 2: Signature Cropper
tab_signature = tk.Frame(frame_content, bg="#121214")

# Khung chứa nhúng cho Tab 2
frame_embed = tk.Frame(tab_signature, bg="#121214")
frame_embed.pack(fill="both", expand=True)
frame_embed.bind("<Configure>", resize_electron)

lbl_loading = tk.Label(frame_embed, text="Đang khởi chạy Signature Cropper...", fg="#6366f1", bg="#121214", font=("Segoe UI", 12, "bold"))

# Nút tab điều khiển
btn_tab_reset = tk.Button(frame_navbar, text="🔌 Reset Connect", 
                          bg="#6366f1", fg="#ffffff", activebackground="#4f46e5", activeforeground="#ffffff",
                          relief="flat", bd=0, font=("Segoe UI", 10, "bold"), cursor="hand2", padx=20)
btn_tab_reset.pack(side="left", fill="y")

btn_tab_sig = tk.Button(frame_navbar, text="🖋️ Signature Cropper", 
                        bg="#1a1a24", fg="#a1a1aa", activebackground="#27272a", activeforeground="#ffffff",
                        relief="flat", bd=0, font=("Segoe UI", 10, "bold"), cursor="hand2", padx=20)
btn_tab_sig.pack(side="left", fill="y")

def refresh_tab_headers(active_tab):
    if active_tab == 0:
        btn_tab_reset.config(bg="#6366f1", fg="#ffffff")
        btn_tab_reset.bind("<Enter>", lambda e: None)
        btn_tab_reset.bind("<Leave>", lambda e: None)
        
        btn_tab_sig.config(bg="#1a1a24", fg="#a1a1aa")
        btn_tab_sig.bind("<Enter>", lambda e: btn_tab_sig.config(bg="#27272a", fg="#ffffff"))
        btn_tab_sig.bind("<Leave>", lambda e: btn_tab_sig.config(bg="#1a1a24", fg="#a1a1aa"))
    else:
        btn_tab_sig.config(bg="#6366f1", fg="#ffffff")
        btn_tab_sig.bind("<Enter>", lambda e: None)
        btn_tab_sig.bind("<Leave>", lambda e: None)
        
        btn_tab_reset.config(bg="#1a1a24", fg="#a1a1aa")
        btn_tab_reset.bind("<Enter>", lambda e: btn_tab_reset.config(bg="#27272a", fg="#ffffff"))
        btn_tab_reset.bind("<Leave>", lambda e: btn_tab_reset.config(bg="#1a1a24", fg="#a1a1aa"))

def switch_tab(tab_index):
    if tab_index == 0:
        refresh_tab_headers(0)
        tab_signature.pack_forget()
        tab_reset.pack(fill="both", expand=True)
    else:
        refresh_tab_headers(1)
        tab_reset.pack_forget()
        tab_signature.pack(fill="both", expand=True)
        if not electron_hwnd:
            launch_signature_cropper()
        else:
            resize_electron()

# Gán sự kiện click cho các Tab button
btn_tab_reset.config(command=lambda: switch_tab(0))
btn_tab_sig.config(command=lambda: switch_tab(1))

# Thiết lập hover mặc định cho tab inactive ban đầu
refresh_tab_headers(0)

# Cấu hình grid cho Tab Reset
tab_reset.columnconfigure(0, weight=1)
tab_reset.columnconfigure(1, weight=1)
tab_reset.rowconfigure(0, weight=1)
tab_reset.rowconfigure(2, weight=1)

# LEFT FORM (CARD)
frame_left = tk.Frame(tab_reset, bg="#1a1a24", padx=20, pady=15, highlightthickness=1, highlightbackground="#2d2d3a")
frame_left.grid(row=0, column=0, padx=15, pady=15, sticky="nsew")

# Row 0: Labels Host and Port
lbl_host = tk.Label(frame_left, text="Host DB:", bg="#1a1a24", fg="#a1a1aa", font=("Segoe UI", 9, "bold"), anchor="w")
lbl_host.grid(row=0, column=0, sticky="w", pady=(6, 2), padx=(0, 5))
lbl_port = tk.Label(frame_left, text="Port DB:", bg="#1a1a24", fg="#a1a1aa", font=("Segoe UI", 9, "bold"), anchor="w")
lbl_port.grid(row=0, column=1, sticky="w", pady=(6, 2), padx=(5, 0))

# Row 1: Entries Host and Port
entry_host = tk.Entry(frame_left, bg="#27272a", fg="#ffffff", insertbackground="#ffffff", 
                      readonlybackground="#27272a", disabledbackground="#1a1a24",
                      highlightthickness=1, highlightbackground="#3f3f46", highlightcolor="#6366f1", 
                      relief="flat", font=("Segoe UI", 10), width=18)
entry_host.grid(row=1, column=0, sticky="we", pady=(0, 6), padx=(0, 5), ipady=3)

entry_port = tk.Entry(frame_left, bg="#27272a", fg="#ffffff", insertbackground="#ffffff", 
                      readonlybackground="#27272a", disabledbackground="#1a1a24",
                      highlightthickness=1, highlightbackground="#3f3f46", highlightcolor="#6366f1", 
                      relief="flat", font=("Segoe UI", 10), width=18)
entry_port.grid(row=1, column=1, sticky="we", pady=(0, 6), padx=(5, 0), ipady=3)

# Row 2: Labels Database and User
lbl_db = tk.Label(frame_left, text="Database name:", bg="#1a1a24", fg="#a1a1aa", font=("Segoe UI", 9, "bold"), anchor="w")
lbl_db.grid(row=2, column=0, sticky="w", pady=(6, 2), padx=(0, 5))
lbl_user = tk.Label(frame_left, text="User DB:", bg="#1a1a24", fg="#a1a1aa", font=("Segoe UI", 9, "bold"), anchor="w")
lbl_user.grid(row=2, column=1, sticky="w", pady=(6, 2), padx=(5, 0))

# Row 3: Entries Database and User
entry_db = tk.Entry(frame_left, bg="#27272a", fg="#ffffff", insertbackground="#ffffff", 
                     readonlybackground="#27272a", disabledbackground="#1a1a24",
                     highlightthickness=1, highlightbackground="#3f3f46", highlightcolor="#6366f1", 
                     relief="flat", font=("Segoe UI", 10), width=18)
entry_db.grid(row=3, column=0, sticky="we", pady=(0, 6), padx=(0, 5), ipady=3)

entry_user = tk.Entry(frame_left, bg="#27272a", fg="#ffffff", insertbackground="#ffffff", 
                      readonlybackground="#27272a", disabledbackground="#1a1a24",
                      highlightthickness=1, highlightbackground="#3f3f46", highlightcolor="#6366f1", 
                      relief="flat", font=("Segoe UI", 10), width=18)
entry_user.grid(row=3, column=1, sticky="we", pady=(0, 6), padx=(5, 0), ipady=3)

# Row 4: Labels Password and Server name
lbl_pass = tk.Label(frame_left, text="Password DB:", bg="#1a1a24", fg="#a1a1aa", font=("Segoe UI", 9, "bold"), anchor="w")
lbl_pass.grid(row=4, column=0, sticky="w", pady=(6, 2), padx=(0, 5))
lbl_server = tk.Label(frame_left, text="Server name (Tên cấu hình):", bg="#1a1a24", fg="#a1a1aa", font=("Segoe UI", 9, "bold"), anchor="w")
lbl_server.grid(row=4, column=1, sticky="w", pady=(6, 2), padx=(5, 0))

# Row 5: Entries Password and Server name
entry_pass = tk.Entry(frame_left, show="*", bg="#27272a", fg="#ffffff", insertbackground="#ffffff", 
                      readonlybackground="#27272a", disabledbackground="#1a1a24",
                      highlightthickness=1, highlightbackground="#3f3f46", highlightcolor="#6366f1", 
                      relief="flat", font=("Segoe UI", 10), width=18)
entry_pass.grid(row=5, column=0, sticky="we", pady=(0, 6), padx=(0, 5), ipady=3)

entry_server = tk.Entry(frame_left, bg="#27272a", fg="#ffffff", insertbackground="#ffffff", 
                        readonlybackground="#27272a", disabledbackground="#1a1a24",
                        highlightthickness=1, highlightbackground="#3f3f46", highlightcolor="#6366f1", 
                        relief="flat", font=("Segoe UI", 10), width=18)
entry_server.grid(row=5, column=1, sticky="we", pady=(0, 6), padx=(5, 0), ipady=3)

# Expand columns equally
frame_left.columnconfigure(0, weight=1)
frame_left.columnconfigure(1, weight=1)

# Khởi tạo placeholder mặc định
set_placeholder(entry_host, "localhost hoặc 192.168.x.x")
set_placeholder(entry_port, "7001,6688")
set_placeholder(entry_db, "Nhập tên database")
entry_user.insert(0, "postgres")
set_placeholder(entry_server, "servername")

# Cấu hình Style cho Combobox của ttk
style = ttk.Style()
style.theme_use('clam')
style.configure("TCombobox", fieldbackground="#27272a", background="#3f3f46", foreground="#ffffff", bordercolor="#3f3f46")
style.map("TCombobox", 
          fieldbackground=[("readonly", "#27272a"), ("disabled", "#1a1a24")],
          foreground=[("readonly", "#ffffff"), ("disabled", "#71717a")],
          background=[("readonly", "#3f3f46"), ("disabled", "#27272a")],
          bordercolor=[("readonly", "#3f3f46"), ("disabled", "#2d2d3a")])
app.option_add("*TCombobox*Listbox.background", "#27272a")
app.option_add("*TCombobox*Listbox.foreground", "#ffffff")
app.option_add("*TCombobox*Listbox.selectBackground", "#6366f1")
app.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")

# Khung nhập thời gian lặp (Row 6)
frame_interval = tk.Frame(frame_left, bg="#1a1a24", pady=5)
frame_interval.grid(row=6, column=0, columnspan=2, sticky="we", pady=(8, 2))

lbl_interval = tk.Label(frame_interval, text="Tự động lặp lại mỗi:", bg="#1a1a24", fg="#a1a1aa", font=("Segoe UI", 9, "bold"))
lbl_interval.pack(side="left", padx=(0, 5))

entry_interval = tk.Entry(frame_interval, bg="#27272a", fg="#ffffff", insertbackground="#ffffff", 
                          readonlybackground="#27272a", disabledbackground="#1a1a24",
                          highlightthickness=1, highlightbackground="#3f3f46", highlightcolor="#6366f1", 
                          relief="flat", font=("Segoe UI", 10), width=6, justify="center")
entry_interval.pack(side="left", padx=5, ipady=1)
entry_interval.insert(0, "1")

combo_unit = ttk.Combobox(frame_interval, values=["Giờ", "Phút", "Giây"], width=6, state="readonly")
combo_unit.pack(side="left", padx=5)
combo_unit.set("Giờ")

# Bố cục nút bấm cho LEFT FORM
frame_form_buttons = tk.Frame(frame_left, bg="#1a1a24", pady=5)
frame_form_buttons.grid(row=7, column=0, columnspan=2, sticky="we")
frame_form_buttons.columnconfigure(0, weight=1)
frame_form_buttons.columnconfigure(1, weight=1)

btn_refresh = create_modern_button(frame_form_buttons, "🔄 Làm mới", "#4b5563", "#374151", clear_form)
btn_refresh.grid(row=0, column=0, sticky="we", padx=4, pady=3, ipady=1)

btn_save = create_modern_button(frame_form_buttons, "💾 Lưu cấu hình", "#3b82f6", "#2563eb", add_new_config)
btn_save.grid(row=0, column=1, sticky="we", padx=4, pady=3, ipady=1)

btn_test = create_modern_button(frame_form_buttons, "🔌 Test kết nối", "#06b6d4", "#0891b2", test_connection)
btn_test.grid(row=1, column=0, sticky="we", padx=4, pady=3, ipady=1)

btn_reset = create_modern_button(frame_form_buttons, "⚡ Reset ngay", "#f59e0b", "#d97706", lambda: reset_connection(True))
btn_reset.grid(row=1, column=1, sticky="we", padx=4, pady=3, ipady=1)

btn_auto = create_modern_button(frame_form_buttons, "▶️ Auto Reset", "#10b981", "#059669", start_auto_reset)
btn_auto.grid(row=2, column=0, sticky="we", padx=4, pady=3, ipady=1)

btn_stop = create_modern_button(frame_form_buttons, "🛑 Dừng", "#27272a", "#dc2626", stop_auto_reset)
btn_stop.grid(row=2, column=1, sticky="we", padx=4, pady=3, ipady=1)
btn_stop.config(state="disabled", cursor="arrow")

btn_signature = create_modern_button(frame_form_buttons, "🖋️ Signature Cropper", "#6366f1", "#4f46e5", launch_signature_cropper)
btn_signature.grid(row=3, column=0, columnspan=2, sticky="we", padx=4, pady=3, ipady=1)

# RIGHT PANEL (CARD)
frame_right = tk.Frame(tab_reset, bg="#1a1a24", padx=25, pady=20, highlightthickness=1, highlightbackground="#2d2d3a")
frame_right.grid(row=0, column=1, padx=15, pady=15, sticky="nsew")

lbl_right_title = tk.Label(frame_right, text="Danh sách cấu hình:", bg="#1a1a24", fg="#f4f4f5", font=("Segoe UI", 11, "bold"), anchor="w")
lbl_right_title.pack(anchor="w", pady=(0, 10))

canvas = Canvas(frame_right, height=220, width=280, bg="#27272a", highlightthickness=0)
scrollbar = tk.Scrollbar(frame_right, orient="vertical", command=canvas.yview, troughcolor="#1a1a24", bg="#27272a")
scroll_frame = tk.Frame(canvas, bg="#27272a")
scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
canvas.configure(yscrollcommand=scrollbar.set)
canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

selected_config = tk.StringVar()
frame_buttons = tk.Frame(frame_right, bg="#1a1a24")
frame_buttons.pack(pady=15)

btn_use = create_modern_button(frame_buttons, "▶ Dùng", "#3b82f6", "#2563eb", lambda: on_select_config(last_selected_name))
btn_edit = create_modern_button(frame_buttons, "✏️ Sửa", "#f59e0b", "#d97706", toggle_edit_mode)
btn_delete = create_modern_button(frame_buttons, "❌ Xóa", "#ef4444", "#dc2626", delete_config)

def hide_action_buttons():
    btn_use.grid_remove()
    btn_edit.grid_remove()
    btn_delete.grid_remove()

def show_action_buttons():
    btn_use.grid(row=0, column=0, padx=6)
    btn_edit.grid(row=0, column=1, padx=6)
    btn_delete.grid(row=0, column=2, padx=6)

# LOG UI (TERMINAL LOG)
lbl_log_title = tk.Label(tab_reset, text="Log hoạt động:", bg="#121214", fg="#f4f4f5", font=("Segoe UI", 11, "bold"), anchor="w")
lbl_log_title.grid(row=1, column=0, columnspan=2, padx=15, pady=(15, 5), sticky="w")

log_area = scrolledtext.ScrolledText(tab_reset, width=120, height=8, bg="#09090b", fg="#22c55e", 
                                     insertbackground="#ffffff", font=("Consolas", 10), 
                                     relief="flat", highlightthickness=1, highlightbackground="#2d2d3a")
log_area.grid(row=2, column=0, columnspan=2, padx=15, pady=(0, 15), sticky="nsew")

log_menu = Menu(tab_reset, tearoff=0)
log_menu.add_command(label="🧹 Xóa log hiển thị", command=clear_log_display)
log_area.bind("<Button-3>", lambda e: log_menu.tk_popup(e.x_root, e.y_root))

def on_app_close():
    global electron_process
    if electron_process:
        try:
            electron_process.terminate()
        except Exception:
            pass
    app.destroy()

app.protocol("WM_DELETE_WINDOW", on_app_close)

# INIT
load_config_cache()
refresh_data_list()
app.mainloop()
