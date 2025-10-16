# -*- coding: utf-8 -*-
"""
Auto Reset DB Tool + Auto-Updater (Full) v5.0
- UI Tkinter quản lý cấu hình DB (lưu/ sửa/ xóa/ dùng)
- Reset kết nối PostgreSQL thủ công/ tự động mỗi 1 giờ
- Log ra file TXT theo ngày: Log/db_reset_YYYYMMDD.txt
- Mã hóa password bằng Fernet (secret.key lưu trong thư mục app)
- Danh sách cấu hình hiển thị dạng list highlight (không radio)
- Nút Lưu bị disable khi đang chọn cấu hình
- Auto-Updater: kiểm tra version trên GitHub, tải file core/... mới (nếu có)
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext, Menu, Canvas
import json, os, time, threading
from datetime import datetime
import psycopg2
from cryptography.fernet import Fernet
import requests  # dùng cho auto-updater

# ===================== CONFIG CHUNG =====================
APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(APP_DIR, "db_config.json")
LOG_DIR = os.path.join(APP_DIR, "Log")
SECRET_KEY_FILE = "secret.key"
SECRET_KEY_PATH = os.path.join(APP_DIR, SECRET_KEY_FILE)

running = False
reset_thread = None
CONFIG_CACHE = []
edit_mode = False
selected_label = None
last_selected_name = ""

# ===================== AUTO UPDATER =====================
CURRENT_VERSION = "5.0.0"  # Cập nhật số này mỗi khi build tool mới
VERSION_URL = "https://raw.githubusercontent.com/BeKienhaikhongba/AutoResetConn/refs/heads/main/version.txt"
FILES_TO_UPDATE = {
    # key = đường local cần ghi, value = URL raw trên GitHub
    "core/AutoResetConn.py": "https://raw.githubusercontent.com/BeKienhaikhongba/AutoResetConn/refs/heads/main/core/AutoResetConn.py"
}
UPDATE_LOG = os.path.join(APP_DIR, "update_log.txt")

# Buffer tạm để hiển thị log auto-update vào UI sau khi UI sẵn sàng
_UPDATE_UI_BUFFER = []
def _buf(msg: str):
    _UPDATE_UI_BUFFER.append(msg)

def log_update(msg: str):
    """Ghi log auto-update ra file + buffer hiển thị lên UI sau khi UI có."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    try:
        with open(UPDATE_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line)
    _buf(line)

def check_for_update(auto_restart=False):
    """Kiểm tra version.txt trên GitHub; nếu khác CURRENT_VERSION thì tải FILES_TO_UPDATE."""
    try:
        log_update(f"🔍 Kiểm tra cập nhật (hiện tại: {CURRENT_VERSION})...")
        r = requests.get(VERSION_URL, timeout=7)
        if r.status_code != 200:
            log_update("⚠️ Không lấy được version từ server.")
            return False

        remote_ver = r.text.strip()
        if remote_ver == CURRENT_VERSION:
            log_update("✅ Đang dùng bản mới nhất.")
            return False

        log_update(f"🔔 Phát hiện bản mới: v{remote_ver} → bắt đầu tải...")
        download_and_replace(remote_ver, auto_restart)
        return True
    except Exception as e:
        log_update(f"❌ Lỗi khi kiểm tra cập nhật: {e}")
        return False

def download_and_replace(remote_ver: str, auto_restart: bool):
    """Tải các file trong FILES_TO_UPDATE và ghi đè an toàn."""
    try:
        for local_rel, url in FILES_TO_UPDATE.items():
            dst = os.path.join(APP_DIR, local_rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            log_update(f"⏬ Tải {local_rel} từ {url}")
            r = requests.get(url, timeout=15)
            if r.status_code != 200:
                log_update(f"❌ Không tải được {url} (status={r.status_code})")
                continue
            with open(dst, "w", encoding="utf-8") as f:
                f.write(r.text)
            log_update(f"✅ Cập nhật thành công: {local_rel}")

        # Ghi lại version tải được (tham khảo)
        with open(os.path.join(APP_DIR, "version_local.txt"), "w", encoding="utf-8") as f:
            f.write(remote_ver)
        log_update(f"🎉 Hoàn tất cập nhật → phiên bản {remote_ver}")

        if auto_restart:
            log_update("🔁 Khởi động lại để áp dụng cập nhật...")
            time.sleep(1)
            os.execl(os.sys.executable, os.sys.executable, *os.sys.argv)

    except Exception as e:
        log_update(f"❌ Lỗi khi cập nhật: {e}")

# Gọi auto updater NGAY khi khởi động (log sẽ buffer, UI xuất hiện sẽ flush ra log UI)
check_for_update(auto_restart=False)

# ===================== ENCRYPTION (Fernet) =====================
def load_or_create_key():
    try:
        if not os.path.exists(SECRET_KEY_PATH):
            key = Fernet.generate_key()
            with open(SECRET_KEY_PATH, "wb") as f:
                f.write(key)
        else:
            with open(SECRET_KEY_PATH, "rb") as f:
                key = f.read()
        return Fernet(key)
    except Exception as e:
        messagebox.showerror("Lỗi tạo key", str(e))
        raise SystemExit

fernet = load_or_create_key()
def encrypt_password(p): return fernet.encrypt(p.encode()).decode()
def decrypt_password(p):
    try:
        return fernet.decrypt(p.encode()).decode()
    except Exception:
        return "•••••"

# ===================== LOGGING (TXT/ngày) =====================
def get_log_file():
    today = datetime.now().strftime("%Y%m%d")
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    return os.path.join(LOG_DIR, f"db_reset_{today}.txt")

def log_message(msg):
    # Ghi UI
    log_area.insert(tk.END, msg + "\n")
    log_area.yview(tk.END)
    # Ghi file
    try:
        with open(get_log_file(), "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}\n")
    except Exception:
        pass

def clear_log_display():
    log_area.delete(1.0, tk.END)
    log_message("🧹 Log hiển thị đã được làm mới (file log vẫn giữ nguyên).")

def flush_update_buffer_to_ui():
    """Đưa những dòng log auto-update đã buffer vào khu vực log UI."""
    if _UPDATE_UI_BUFFER:
        for line in _UPDATE_UI_BUFFER:
            log_message(f"[AutoUpdate] {line}")
        _UPDATE_UI_BUFFER.clear()

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
    entry.config(fg="gray")
    def on_focus_in(event):
        if entry.get() == text and entry.cget("state") == "normal":
            entry.delete(0, "end")
            entry.config(fg="black")
    def on_focus_out(event):
        if entry.get() == "" and entry.cget("state") == "normal":
            entry.insert(0, text)
            entry.config(fg="gray")
    entry.bind("<FocusIn>", on_focus_in)
    entry.bind("<FocusOut>", on_focus_out)

def clear_form():
    global edit_mode, selected_label, last_selected_name
    for e in [entry_host, entry_port, entry_db, entry_user, entry_pass, entry_server]:
        e.config(state="normal")
        e.delete(0, tk.END)
        e.config(fg="black")
    set_placeholder(entry_host, "localhost hoặc 192.168.x.x")
    set_placeholder(entry_port, "7001,6688")
    set_placeholder(entry_db, "Nhập tên database")
    entry_user.insert(0, "postgres")
    set_placeholder(entry_server, "servername")

    selected_config.set("")
    selected_label = None
    last_selected_name = ""
    edit_mode = False
    btn_edit.config(text="✏️ Sửa", bg="#f4a460", command=toggle_edit_mode)
    btn_save.config(state="normal")  # bật lại Lưu cấu hình
    hide_action_buttons()
    log_message("🧹 Làm mới form (chế độ nhập mới).")

def add_new_config():
    name = entry_server.get().strip()
    if not name or entry_server.cget("fg") == "gray":
        messagebox.showwarning("Thiếu thông tin", "Vui lòng nhập tên Server."); return
    if any(c["name"].lower() == name.lower() for c in CONFIG_CACHE):
        messagebox.showerror("Trùng tên", f"Cấu hình '{name}' đã tồn tại!"); return
    required = [
        entry_host.get().strip() if entry_host.cget("fg") != "gray" else "",
        entry_port.get().strip() if entry_port.cget("fg") != "gray" else "",
        entry_db.get().strip()   if entry_db.cget("fg") != "gray" else "",
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
        "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    CONFIG_CACHE.append(cfg)
    save_config_cache()
    refresh_data_list()
    log_message(f"💾 Thêm cấu hình mới: {name}")
    messagebox.showinfo("Thành công", f"Đã thêm cấu hình '{name}'.")

def on_select_config(cfg_name):
    global selected_label, last_selected_name
    # Toggle ẩn/hiện khi click lại cùng cấu hình
    if last_selected_name == cfg_name:
        hide_action_buttons()
        last_selected_name = ""
        selected_config.set("")
        if selected_label: selected_label.config(bg="white")
        btn_save.config(state="normal")
        return

    last_selected_name = cfg_name
    cfg = next((c for c in CONFIG_CACHE if c["name"] == cfg_name), None)
    if not cfg: return

    # highlight dòng chọn
    for w in scroll_frame.winfo_children(): w.config(bg="white")
    selected_label = [w for w in scroll_frame.winfo_children() if w.cget("text") == cfg_name][0]
    selected_label.config(bg="#cce5ff")

    # đổ dữ liệu & khóa form (read-only)
    set_entry_state(False)
    entry_host.config(fg="black"); entry_port.config(fg="black")
    entry_db.config(fg="black"); entry_user.config(fg="black")
    entry_server.config(fg="black")
    entry_host.delete(0, tk.END); entry_host.insert(0, cfg["host"])
    entry_port.delete(0, tk.END); entry_port.insert(0, cfg["port"])
    entry_db.delete(0, tk.END); entry_db.insert(0, cfg["db"])
    entry_user.delete(0, tk.END); entry_user.insert(0, cfg["user"])
    entry_pass.delete(0, tk.END); entry_pass.insert(0, decrypt_password(cfg["password"]))
    entry_server.delete(0, tk.END); entry_server.insert(0, cfg["name"])
    set_entry_state(True)

    show_action_buttons()
    btn_save.config(state="disabled")
    log_message(f"📄 Hiển thị cấu hình: {cfg_name}")

def toggle_edit_mode():
    global edit_mode
    if not last_selected_name:
        messagebox.showinfo("Thông báo", "Vui lòng chọn cấu hình để sửa."); return
    if not edit_mode:
        set_entry_state(False)
        edit_mode = True
        btn_edit.config(text="💾 Lưu", bg="#77b5fe", command=save_edit_changes)
        log_message("✏️ Đang chỉnh sửa cấu hình...")

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
                "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            break
    save_config_cache()
    refresh_data_list()
    log_message(f"✅ Cập nhật cấu hình '{old_name}' → '{new_name}'.")
    edit_mode = False
    btn_edit.config(text="✏️ Sửa", bg="#f4a460", command=toggle_edit_mode)
    btn_save.config(state="normal")

def delete_config():
    global last_selected_name
    name = last_selected_name
    if not name: return
    if not messagebox.askyesno("Xác nhận",
                               f"Bạn có chắc chắn muốn xóa '{name}'?\nSau khi xóa sẽ không thể khôi phục."):
        return
    CONFIG_CACHE[:] = [c for c in CONFIG_CACHE if c["name"] != name]
    save_config_cache()
    refresh_data_list()
    clear_form()
    log_message(f"🗑 Đã xóa cấu hình: {name}")

def refresh_data_list():
    for w in scroll_frame.winfo_children(): w.destroy()
    for cfg in CONFIG_CACHE:
        lbl = tk.Label(scroll_frame, text=cfg["name"], bg="white", anchor="w", font=("Segoe UI", 10), padx=5)
        lbl.bind("<Enter>", lambda e, b=lbl: b.config(bg="#e6f2ff") if b.cget("bg") == "white" else None)
        lbl.bind("<Leave>", lambda e, b=lbl: b.config(bg="white") if b.cget("bg") == "#e6f2ff" else None)
        lbl.bind("<Button-1>", lambda e, name=cfg["name"]: on_select_config(name))
        lbl.pack(fill="x", padx=5, pady=1)
    hide_action_buttons()

# ===================== KẾT NỐI & RESET =====================
def test_connection():
    try:
        conn = psycopg2.connect(
            host=entry_host.get(),
            port=int(entry_port.get().split(",")[0]),
            database=entry_db.get(),
            user=entry_user.get(),
            password=entry_pass.get(),
            connect_timeout=5
        )
        conn.close()
        log_message("✅ Test connection OK.")
    except Exception as e:
        log_message(f"❌ Test connection failed: {e}")

def reset_connection(manual=False):
    """Reset: kill mọi session trừ session hiện tại. Log chi tiết từng port."""
    host, ports, db, user, pw, name = (
        entry_host.get(),
        entry_port.get().split(","),
        entry_db.get(),
        entry_user.get(),
        entry_pass.get(),
        entry_server.get()
    )

    log_message(f"🟦 Bắt đầu reset cho server [{name}]...")

    success_count = 0
    fail_count = 0

    for p in [x.strip() for x in ports if x.strip()]:
        try:
            conn = psycopg2.connect(
                host=host, port=int(p), database=db,
                user=user, password=pw, connect_timeout=5
            )
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT pg_terminate_backend(pid)
                    FROM pg_stat_activity
                    WHERE pid <> pg_backend_pid();
                """)
            conn.commit()
            conn.close()
            success_count += 1
            log_message(f"✅ [{name}] Reset DB port {p} thành công.")
        except Exception as e:
            fail_count += 1
            log_message(f"❌ [{name}] Reset DB port {p} thất bại: {e}")

    total = success_count + fail_count
    log_message(f"🏁 Hoàn tất reset [{name}] ({'Thủ công' if manual else 'Tự động'}) - "
                f"Tổng: {total} | OK: {success_count} | Lỗi: {fail_count}\n")

def start_auto_reset():
    global running, reset_thread
    if running: return
    running = True
    reset_thread = threading.Thread(target=auto_reset_loop, daemon=True)
    reset_thread.start()
    log_message("▶️ Auto reset started.")

def auto_reset_loop():
    global running
    while running:
        reset_connection()
        log_message("⏰ Chờ 1 giờ trước lần reset tiếp theo...\n")
        time.sleep(3600)

def stop_auto_reset():
    global running
    running = False
    log_message("🛑 Auto reset stopped.")

# ===================== UI =====================
app = tk.Tk()
app.title(f"Auto Reset DB Tool v{CURRENT_VERSION}")
app.geometry("980x630")

# LEFT FORM
frame_left = tk.Frame(app)
frame_left.grid(row=0, column=0, padx=10, pady=10, sticky="n")

labels = ["Host:", "Port:", "Database name:", "User DB:", "Password DB:", "Server name:"]
entries = []
for i, text in enumerate(labels):
    tk.Label(frame_left, text=text).grid(row=i, column=0, sticky="e")
    e = tk.Entry(frame_left, width=30, show="*" if "Password" in text else None)
    e.grid(row=i, column=1)
    entries.append(e)

entry_host, entry_port, entry_db, entry_user, entry_pass, entry_server = entries
# placeholder mặc định
set_placeholder(entry_host, "localhost hoặc 192.168.x.x")
set_placeholder(entry_port, "7001,6688")
set_placeholder(entry_db, "Nhập tên database")
entry_user.insert(0, "postgres")
set_placeholder(entry_server, "servername")

tk.Button(frame_left, text="🔄 Làm mới", bg="#77dd77", command=clear_form)\
    .grid(row=7, column=0, sticky="e", pady=10)
btn_save = tk.Button(frame_left, text="💾 Lưu cấu hình", bg="#77b5fe", command=add_new_config)
btn_save.grid(row=7, column=1, sticky="w", pady=10)
tk.Button(frame_left, text="🔌 Kiểm tra kết nối", bg="#a1eafb", command=test_connection)\
    .grid(row=8, column=1, sticky="e", pady=5)
tk.Button(frame_left, text="⚡ Reset ngay", bg="#ffd966", command=lambda: reset_connection(True))\
    .grid(row=9, column=1, sticky="e", pady=5)
tk.Button(frame_left, text="▶️ Auto Reset", bg="#44c767", command=start_auto_reset)\
    .grid(row=10, column=1, sticky="e", pady=5)
tk.Button(frame_left, text="🛑 Dừng", bg="#e06666", command=stop_auto_reset)\
    .grid(row=11, column=1, sticky="e", pady=5)

# RIGHT LIST
frame_right = tk.Frame(app)
frame_right.grid(row=0, column=1, padx=10, pady=10, sticky="n")
tk.Label(frame_right, text="Danh sách cấu hình:").pack()

canvas = Canvas(frame_right, height=220, width=260)
scrollbar = tk.Scrollbar(frame_right, orient="vertical", command=canvas.yview)
scroll_frame = tk.Frame(canvas, bg="white")
scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
canvas.configure(yscrollcommand=scrollbar.set)
canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

selected_config = tk.StringVar()
frame_buttons = tk.Frame(frame_right); frame_buttons.pack(pady=10)
btn_use = tk.Button(frame_buttons, text="▶ Dùng", bg="#c2dfff",
                    command=lambda: on_select_config(last_selected_name))
btn_edit = tk.Button(frame_buttons, text="✏️ Sửa", bg="#f4a460", command=toggle_edit_mode)
btn_delete = tk.Button(frame_buttons, text="❌ Xóa", bg="#ff6961", command=delete_config)
def hide_action_buttons():
    btn_use.grid_remove(); btn_edit.grid_remove(); btn_delete.grid_remove()
def show_action_buttons():
    btn_use.grid(row=0, column=0, padx=5); btn_edit.grid(row=0, column=1, padx=5); btn_delete.grid(row=0, column=2, padx=5)

# LOG UI
tk.Label(app, text="Log hoạt động:").grid(row=1, column=0, columnspan=2)
log_area = scrolledtext.ScrolledText(app, width=120, height=16)
log_area.grid(row=2, column=0, columnspan=2, padx=10, pady=5)
log_menu = Menu(app, tearoff=0)
log_menu.add_command(label="🧹 Xóa log hiển thị", command=clear_log_display)
log_area.bind("<Button-3>", lambda e: log_menu.tk_popup(e.x_root, e.y_root))

# INIT
load_config_cache()
refresh_data_list()
flush_update_buffer_to_ui()  # đưa log auto-update đã buffer vào UI
log_message(f"🚀 Tool v{CURRENT_VERSION} khởi động thành công.")
app.mainloop()