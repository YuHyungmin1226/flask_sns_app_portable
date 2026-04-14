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

def get_local_ip():
    """보다 안정적으로 로컬 LAN IP를 찾는 함수"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # 실제 연결을 시도하지 않고 라우팅 테이블만 참조함
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

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
        
        # 로컬 LAN IP 찾기
        local_ip = get_local_ip()

        logging.info("Starting Flask SNS server...")
        logging.info(f" * Local access: http://localhost:{port}")
        logging.info(f" * Network access: http://{local_ip}:{port}")
        logging.info("Press CTRL+C to quit")
        
        serve(app, host=host, port=port)

    except Exception as e:
        logging.error(f"Failed to start the server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
