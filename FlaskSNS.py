import sys
import socket
from app import app, create_database_and_admin
from waitress import serve
import logging

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def find_free_port(start_port):
    """사용 가능한 포트를 찾는 함수"""
    port = start_port
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('localhost', port)) != 0:
                return port
            port += 1

def get_all_local_ips():
    """모든 가능한 유효한 LAN IP 목록을 반환하는 함수"""
    ips = set()
    
    # 방법 1: 외부 연결 시도 (기본 게이트웨이 인터페이스)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        ips.add(s.getsockname()[0])
    except Exception:
        pass
    finally:
        s.close()
        
    # 방법 2: 호스트네임 기반 조회
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            ips.add(ip)
    except Exception:
        pass
        
    # 127.0.0.1 제외 및 정렬
    return sorted([ip for ip in ips if ip != '127.0.0.1'])

def main():
    """애플리케이션 메인 실행 함수"""
    # 데이터베이스 및 관리자 계정 생성
    try:
        create_database_and_admin()
        logging.info("Database and admin user checked/created successfully.")
    except Exception as e:
        logging.error(f"Error during database initialization: {e}")
        sys.exit(1)

    # 호스트 및 포트 설정
    host = '0.0.0.0'
    start_port = 5001
    
    try:
        port = find_free_port(start_port)
        
        # 모든 가용 로컬 IP 찾기
        local_ips = get_all_local_ips()

        logging.info("Starting Flask SNS server...")
        logging.info(f" * Local access: http://localhost:{port}")
        
        if local_ips:
            for ip in local_ips:
                logging.info(f" * Network access: http://{ip}:{port}")
        else:
            logging.info(f" * Network access: http://127.0.0.1:{port}")
        logging.info("Press CTRL+C to quit")
        
        serve(app, host=host, port=port)

    except Exception as e:
        logging.error(f"Failed to start the server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Server stopped by user.")
        sys.exit(0)
