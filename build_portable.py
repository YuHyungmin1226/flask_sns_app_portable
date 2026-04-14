import os
import sys
import platform
import PyInstaller.__main__

def build():
    # 현재 운영체제 확인
    current_os = platform.system()
    print(f"[*] Detected OS: {current_os}")

    # OS별 데이터 구분자 설정 (Window: ; / Unix: :)
    separator = ';' if current_os == 'Windows' else ':'
    
    # 빌드 옵션 구성
    params = [
        'FlaskSNS.py',
        '--onefile',
        '--clean',
        '--distpath', 'dist',
        '--add-data', f"templates{separator}templates",
        '--collect-all', 'charset_normalizer',
        '--collect-all', 'filetype',
        '--collect-all', 'pytz',
        '--hidden-import', '81d243bd2c585b0f4821__mypyc',
    ]
    
    # 윈도우의 경우 실행 파일 뒤에 .exe 추가 (자동으로 처리되지만 명시적 확인용)
    binary_name = "FlaskSNS.exe" if current_os == 'Windows' else "FlaskSNS"
    print(f"[*] Building {binary_name} for {current_os}...")

    # PyInstaller 실행
    try:
        PyInstaller.__main__.run(params)
        print(f"\n[+] Build successful! The executable is located in: {os.path.abspath('dist')}")
    except Exception as e:
        print(f"\n[-] Build failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    build()
