import os
import sys
import datetime
import subprocess
import zipfile

# Đảm bảo in unicode ra console Windows không bị lỗi
if sys.platform.startswith('win'):
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Đường dẫn thư mục dự án
APP_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION_FILE = os.path.join(APP_DIR, "version.txt")
VERSION_LOCAL_FILE = os.path.join(APP_DIR, "version_local.txt")

def get_next_version():
    now = datetime.datetime.now()
    today_str = f"{now.year}.{now.month}.{now.strftime('%d')}"
    next_ver = f"{today_str}.1"
    
    if os.path.exists(VERSION_FILE):
        try:
            with open(VERSION_FILE, "r", encoding="utf-8") as f:
                current_ver = f.read().strip()
            
            parts = current_ver.split(".")
            if len(parts) == 4:
                curr_year = int(parts[0])
                curr_month = int(parts[1])
                curr_day = int(parts[2])
                curr_x = int(parts[3])
                
                if curr_year == now.year and curr_month == now.month and curr_day == now.day:
                    next_ver = f"{today_str}.{curr_x + 1}"
        except Exception as e:
            print(f"⚠️ Cảnh báo khi đọc version.txt: {e}")
            
    return next_ver

def create_offline_packages(next_ver):
    print(f"\n📦 Đang tạo gói nén cập nhật Core Offline (.rar) cho v{next_ver}...")
    dist_dir = os.path.join(APP_DIR, "dist")
    os.makedirs(dist_dir, exist_ok=True)

    # Dọn dẹp các file zip cũ nếu có
    for f in os.listdir(dist_dir):
        if f.endswith(".zip"):
            try:
                os.remove(os.path.join(dist_dir, f))
            except Exception:
                pass

    # Bảo mật: Không đóng gói file .py mã nguồn gốc vào gói nén .rar
    files_to_pack = [
        #("version.txt", os.path.join(APP_DIR, "version.txt")),
        # ("version_local.txt", os.path.join(APP_DIR, "version_local.txt")),
        ("AutoResetConn.dat", os.path.join(dist_dir, "AutoResetConn.dat")),
        ("secret.key", os.path.join(dist_dir, "secret.key")),
        ("AutoResetConn.exe", os.path.join(dist_dir, "AutoResetConn.exe")),
    ]

    rar_filename = f"Core_{next_ver}.rar"
    rar_path = os.path.join(dist_dir, rar_filename)

    winrar_paths = [
        r"C:\Program Files\WinRAR\WinRAR.exe",
        r"C:\Program Files (x86)\WinRAR\WinRAR.exe"
    ]
    winrar_exe = next((p for p in winrar_paths if os.path.exists(p)), None)
    if winrar_exe:
        try:
            if os.path.exists(rar_path):
                os.remove(rar_path)
            valid_files = [abs_path for _, abs_path in files_to_pack if os.path.exists(abs_path)]
            cmd = [winrar_exe, "a", "-ep", "-afrar", rar_path] + valid_files
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"  ✅ Đã tạo gói nén RAR offline: {rar_path}")
        except Exception as e:
            print(f"  ⚠️ Cảnh báo tạo file RAR: {e}")
    else:
        print("  ⚠️ Không tìm thấy WinRAR.exe trên hệ thống để tạo file RAR.")

def main():
    next_ver = get_next_version()
    print(f"🔄 Chuẩn bị cập nhật phiên bản mới: {next_ver}")
    
    # 1. Ghi đè version.txt và version_local.txt
    try:
        with open(VERSION_FILE, "w", encoding="utf-8") as f:
            f.write(next_ver)
        with open(VERSION_LOCAL_FILE, "w", encoding="utf-8") as f:
            f.write(next_ver)
        
        dist_dir = os.path.join(APP_DIR, "dist")
        os.makedirs(dist_dir, exist_ok=True)
        dist_ver_file = os.path.join(dist_dir, "version_local.txt")
        with open(dist_ver_file, "w", encoding="utf-8") as f:
            f.write(next_ver)
            
        py_path = os.path.join(APP_DIR, "AutoResetConn.py")
        dat_path = os.path.join(dist_dir, "AutoResetConn.dat")
        key_path = os.path.join(APP_DIR, "secret.key")
        dist_key_path = os.path.join(dist_dir, "secret.key")
        
        if os.path.exists(py_path):
            try:
                from cryptography.fernet import Fernet
                if os.path.exists(key_path):
                    with open(key_path, "rb") as f:
                        key = f.read()
                else:
                    key = Fernet.generate_key()
                    with open(key_path, "wb") as f:
                        f.write(key)
                
                with open(dist_key_path, "wb") as f:
                    f.write(key)

                with open(py_path, "r", encoding="utf-8") as f:
                    code = f.read()

                cipher = Fernet(key)
                encrypted = cipher.encrypt(code.encode("utf-8"))
                with open(dat_path, "wb") as f:
                    f.write(encrypted)
                print("🔒 Đã cập nhật bản mã hóa dist/AutoResetConn.dat")
            except Exception as ex:
                print(f"⚠️ Không thể cập nhật AutoResetConn.dat: {ex}")

        print("✅ Đã cập nhật version.txt và version_local.txt")
    except Exception as e:
        print(f"❌ Lỗi ghi file version: {e}")
        sys.exit(1)

    # 2. Tạo gói cài đặt nén Offline (.rar / .zip)
    create_offline_packages(next_ver)

    # 3. Chạy các lệnh Git Push
    print("\n📦 Đang tiến hành push bản build mới lên Git...")
    commands = [
        ["git", "add", "version.txt", "version_local.txt", "core/AutoResetConn.py", "AutoResetConn.py", "release.py", "README.md"],
        ["git", "add", "-f", "dist/"],
        ["git", "commit", "-m", f"Release v{next_ver}"],
        ["git", "push"]
    ]
    
    git_failed = False
    for cmd in commands:
        try:
            print(f"   Chạy: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if result.stdout:
                print(result.stdout.strip())
        except FileNotFoundError:
            print(f"❌ Không tìm thấy chương trình 'git' trên hệ thống của bạn (có thể chưa cài hoặc chưa cấu hình PATH).")
            git_failed = True
            break
        except subprocess.CalledProcessError as e:
            print(f"❌ Lỗi khi thực hiện lệnh git: {e.stderr.strip()}")
            git_failed = True
            break
            
    if git_failed:
        print("\n⚠️ Không thể tự động push Git. Vui lòng chạy thủ công các lệnh sau:")
        print(f"  git add version.txt version_local.txt core/AutoResetConn.py AutoResetConn.py release.py dist/")
        print(f"  git commit -m \"Release v{next_ver}\"")
        print(f"  git push")
    else:
        print(f"\n🎉 Thành công! Phiên bản mới v{next_ver} đã được cập nhật & đẩy lên GitHub.")

if __name__ == "__main__":
    main()
