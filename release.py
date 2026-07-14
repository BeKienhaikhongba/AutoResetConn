import os
import sys
import datetime
import subprocess

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
    today_str = datetime.datetime.now().strftime("%Y.%m.%d")
    
    # Phiên bản mặc định đầu tiên trong ngày
    next_ver = f"{today_str}.1"
    
    if os.path.exists(VERSION_FILE):
        try:
            with open(VERSION_FILE, "r", encoding="utf-8") as f:
                current_ver = f.read().strip()
            
            # Định dạng: YYYY.MM.DD.X
            parts = current_ver.split(".")
            if len(parts) == 4:
                curr_date = ".".join(parts[:3])
                curr_x = int(parts[3])
                
                # Nếu trùng ngày hôm nay thì tăng chỉ số x lên 1
                if curr_date == today_str:
                    next_ver = f"{today_str}.{curr_x + 1}"
        except Exception as e:
            print(f"⚠️ Cảnh báo khi đọc version.txt: {e}")
            
    return next_ver

def main():
    next_ver = get_next_version()
    print(f"🔄 Chuẩn bị cập nhật phiên bản mới: {next_ver}")
    
    # 1. Ghi đè version.txt và version_local.txt
    try:
        with open(VERSION_FILE, "w", encoding="utf-8") as f:
            f.write(next_ver)
        with open(VERSION_LOCAL_FILE, "w", encoding="utf-8") as f:
            f.write(next_ver)
        print("✅ Đã cập nhật version.txt và version_local.txt")
    except Exception as e:
        print(f"❌ Lỗi ghi file version: {e}")
        sys.exit(1)
        
    # 2. Chạy các lệnh Git
    print("\n📦 Đang tiến hành push lên Git...")
    commands = [
        ["git", "add", "version.txt", "version_local.txt", "core/AutoResetConn.py", "AutoResetConn.py", "release.py"],
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
        print(f"  git add version.txt version_local.txt core/AutoResetConn.py AutoResetConn.py")
        print(f"  git commit -m \"Release v{next_ver}\"")
        print(f"  git push")
    else:
        print(f"\n🎉 Thành công! Phiên bản mới v{next_ver} đã được đẩy lên GitHub.")

if __name__ == "__main__":
    main()
