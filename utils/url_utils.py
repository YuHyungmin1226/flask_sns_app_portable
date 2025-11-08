import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, urljoin

def get_url_preview(text):
    """
    텍스트에서 첫 번째 URL을 찾아 미리보기 정보를 생성합니다.
    Open Graph 태그를 우선적으로 사용합니다.
    """
    # 정규표현식으로 URL 찾기
    url_regex = r'https?://[^\s/$.?#].[^\s]*'
    match = re.search(url_regex, text)
    if not match:
        return None

    url = match.group(0)
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, 'html.parser')

        # Open Graph(og) 태그 우선 사용
        title = soup.find('meta', property='og:title')
        description = soup.find('meta', property='og:description')
        image = soup.find('meta', property='og:image')
        
        # og 태그가 없을 경우 일반 태그 사용
        if not title:
            title = soup.find('title')
        if not description:
            description = soup.find('meta', attrs={'name': 'description'})
        
        # content 속성에서 텍스트 추출
        title_text = title['content'] if title and 'content' in title.attrs else (title.string if title else "제목 없음")
        description_text = description['content'] if description and 'content' in description.attrs else ""
        image_url = image['content'] if image and 'content' in image.attrs else None

        # 상대 경로인 경우 절대 경로로 변환
        if image_url and not image_url.startswith('http'):
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            image_url = urljoin(base_url, image_url)

        # YouTube 특별 처리
        if 'youtube.com' in url or 'youtu.be' in url:
            image_url = get_youtube_thumbnail(url)

        return {
            'url': url,
            'title': title_text.strip(),
            'description': description_text.strip(),
            'image': image_url
        }

    except requests.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
        return None
    except Exception as e:
        print(f"Error parsing URL preview for {url}: {e}")
        return None

def get_youtube_thumbnail(url):
    """YouTube URL에서 썸네일 이미지 URL을 추출합니다."""
    video_id = None
    # 표준 YouTube URL (youtube.com/watch?v=...)
    match = re.search(r'watch\?v=([^&]+)', url)
    if match:
        video_id = match.group(1)
    else:
        # 짧은 URL (youtu.be/...)
        match = re.search(r'youtu\.be/([^?]+)', url)
        if match:
            video_id = match.group(1)
        else:
            # 임베드 URL (youtube.com/embed/...)
            match = re.search(r'embed/([^?]+)', url)
            if match:
                video_id = match.group(1)

    if video_id:
        # 고화질 썸네일 우선, 없으면 기본 썸네일
        return f'https://img.youtube.com/vi/{video_id}/hqdefault.jpg'
    
    return None
