import os
import sys
import uuid
import time
from datetime import datetime, timezone, timedelta
from werkzeug.utils import secure_filename
from PIL import Image
import filetype
import json

# 한국 시간대 설정
KST = timezone(timedelta(hours=9))

def get_korean_time():
    """한국 시간 반환"""
    return datetime.now(KST)

# 파일 업로드 설정
UPLOAD_FOLDER = 'uploads'
MAX_FILE_SIZE = 5000 * 1024 * 1024  # 5000MB
THUMBNAIL_SIZE = (300, 300)

# 허용된 파일 타입
ALLOWED_EXTENSIONS = {
    'image': {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'},
    'document': {'pdf', 'doc', 'docx', 'txt', 'rtf'},
    'video': {'mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv'},
    'audio': {'mp3', 'wav', 'flac', 'ogg', 'm4a'},
    'archive': {'zip', 'rar', '7z', 'tar', 'gz'}
}

# 파일 타입별 아이콘
FILE_ICONS = {
    'image': 'bi-image',
    'document': 'bi-file-text',
    'video': 'bi-camera-video',
    'audio': 'bi-music-note',
    'archive': 'bi-archive',
    'unknown': 'bi-file-earmark'
}

def get_application_path():
    """실행 파일 또는 스크립트의 경로 반환 (PyInstaller 대응)"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def get_file_type(filename):
    """파일 확장자로부터 파일 타입을 반환"""
    if '.' not in filename:
        return 'unknown'
    
    ext = filename.rsplit('.', 1)[1].lower()
    
    for file_type, extensions in ALLOWED_EXTENSIONS.items():
        if ext in extensions:
            return file_type
    
    return 'unknown'

def allowed_file(filename):
    """파일이 허용된 확장자인지 확인"""
    if '.' not in filename:
        return False
    
    ext = filename.rsplit('.', 1)[1].lower()
    return any(ext in extensions for extensions in ALLOWED_EXTENSIONS.values())

def get_file_icon(file_type):
    """파일 타입에 따른 아이콘 반환"""
    return FILE_ICONS.get(file_type, FILE_ICONS['unknown'])

def create_upload_folder():
    """업로드 폴더 생성"""
    upload_path = os.path.join(get_application_path(), UPLOAD_FOLDER)
    
    if not os.path.exists(upload_path):
        os.makedirs(upload_path)
    
    # 하위 폴더들 생성
    for folder in ['images', 'documents', 'videos', 'audio', 'archives']:
        folder_path = os.path.join(upload_path, folder)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

def generate_unique_filename(original_filename):
    """고유한 파일명 생성"""
    ext = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
    unique_id = str(uuid.uuid4())
    timestamp = get_korean_time().strftime('%Y%m%d_%H%M%S')
    
    if ext:
        return f"{timestamp}_{unique_id}.{ext}"
    else:
        return f"{timestamp}_{unique_id}"

def save_file(file, filename):
    """파일을 저장하고 정보 반환"""
    create_upload_folder()
    
    file_type = get_file_type(filename)
    unique_filename = generate_unique_filename(filename)
    
    type_folders = {
        'image': 'images',
        'document': 'documents', 
        'video': 'videos',
        'audio': 'audio',
        'archive': 'archives'
    }
    
    folder = type_folders.get(file_type, 'documents')
    file_path = os.path.join(get_application_path(), UPLOAD_FOLDER, folder, unique_filename)
    
    # 폴더 존재 확인
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    # 파일 저장
    file.save(file_path)
    
    # MIME 타입 확인
    mime_type = 'application/octet-stream'
    try:
        kind = filetype.guess(file_path)
        if kind:
            mime_type = kind.mime
    except:
        pass
    
    # 이미지 파일인 경우 썸네일 생성
    thumbnail_path = None
    if file_type == 'image':
        thumbnail_path = create_thumbnail(file_path, unique_filename)
    
    return {
        'original_name': filename,
        'saved_name': unique_filename,
        'file_path': os.path.join(UPLOAD_FOLDER, folder, unique_filename).replace('\\', '/'),
        'file_type': file_type,
        'file_size': os.path.getsize(file_path),
        'mime_type': mime_type,
        'upload_time': get_korean_time().isoformat(),
        'thumbnail_path': thumbnail_path.replace('\\', '/') if thumbnail_path else None
    }

def create_thumbnail(image_path, filename):
    """이미지 썸네일 생성"""
    try:
        thumbnail_name = f"thumb_{filename}"
        thumbnail_path = os.path.join(get_application_path(), UPLOAD_FOLDER, 'images', thumbnail_name)
        
        with Image.open(image_path) as img:
            # 이미지 모드 변환 (PNG/RGBA -> RGB)
            if img.mode in ('RGBA', 'LA'):
                background = Image.new('RGB', img.size, (255, 255, 255))
                background.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
                img = background
            elif img.mode != 'RGB':
                img = img.convert('RGB')
                
            img.thumbnail(THUMBNAIL_SIZE, Image.Resampling.LANCZOS)
            img.save(thumbnail_path, 'JPEG', quality=85)
            
        return os.path.join(UPLOAD_FOLDER, 'images', thumbnail_name)
    except Exception as e:
        print(f"Thumbnail creation error: {e}")
        return None

def get_file_size_display(size_bytes):
    """파일 크기를 읽기 쉬운 형태로 변환"""
    if size_bytes == 0: return "0B"
    size_names = ["B", "KB", "MB", "GB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    return f"{size_bytes:.1f}{size_names[i]}"

def validate_file(file):
    """파일 유효성 검사"""
    errors = []
    if file.content_length and file.content_length > MAX_FILE_SIZE:
        errors.append(f"파일 크기가 너무 큽니다. 최대 {get_file_size_display(MAX_FILE_SIZE)}까지 가능합니다.")
    if file.filename and not allowed_file(file.filename):
        errors.append("허용되지 않는 파일 형식입니다.")
    return errors

def delete_file(relative_path):
    """파일 삭제 (안전한 재시도 포함)"""
    file_path = os.path.join(get_application_path(), relative_path)
    if not os.path.exists(file_path):
        return True
        
    for _ in range(3):
        try:
            os.remove(file_path)
            return True
        except:
            time.sleep(0.5)
    return False

def get_file_info_from_json(json_str):
    """JSON 문자열에서 파일 정보 리스트 추출"""
    if not json_str: return []
    try:
        return json.loads(json_str)
    except:
        return []
