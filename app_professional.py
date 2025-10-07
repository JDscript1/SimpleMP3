#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
© 2025 SimpleMP3 Converter
All Rights Reserved.

This software is proprietary and confidential.
Unauthorized copying, distribution, or modification
is strictly prohibited.

SimpleMP3 Converter
Aplicație completă cu interfață modernă, teme, setări avansate și funcționalități profesionale
"""

import os
import uuid
import threading
import time
import json
import yt_dlp
import re
import hashlib
import secrets
from flask import Flask, render_template, request, jsonify, send_file, url_for, send_from_directory, make_response, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import shutil
import subprocess
from functools import wraps
import logging
import concurrent.futures
# Check if running locally or on Railway
import os
IS_RAILWAY = os.environ.get('RAILWAY_ENVIRONMENT') is not None

if IS_RAILWAY:
    # Railway deployment - disable modules
    PSUTIL_AVAILABLE = False
    PERFORMANCE_OPTIMIZER_AVAILABLE = False
    print("WARNING: Running on Railway - modules disabled")
else:
    # Local development - enable modules
    try:
        import psutil
        PSUTIL_AVAILABLE = True
    except ImportError:
        PSUTIL_AVAILABLE = False
        print("WARNING: psutil not available locally")
    
    try:
        from performance_optimizer import PerformanceOptimizer
        PERFORMANCE_OPTIMIZER_AVAILABLE = True
    except ImportError:
        PERFORMANCE_OPTIMIZER_AVAILABLE = False
        print("WARNING: performance_optimizer not available locally")

app = Flask(__name__)

# Configure logging
if IS_RAILWAY:
    # Production logging
    logging.basicConfig(level=logging.INFO)
    app.logger.setLevel(logging.INFO)
else:
    # Development logging
    logging.basicConfig(level=logging.DEBUG)
    app.logger.setLevel(logging.DEBUG)

# Configurare Securitate
# Folosește un secret key fix pentru a păstra session-urile
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'simplemp3_converter_2025_secure_key_32_chars')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Platforme suportate
SUPPORTED_PLATFORMS = {
    'youtube.com': {
        'name': 'YouTube',
        'icon': 'fab fa-youtube',
        'color': '#ff0000',
        'domains': ['youtube.com', 'youtu.be', 'm.youtube.com', 'www.youtube.com']
    },
    'vimeo.com': {
        'name': 'Vimeo',
        'icon': 'fab fa-vimeo',
        'color': '#1ab7ea',
        'domains': ['vimeo.com', 'player.vimeo.com']
    },
    'dailymotion.com': {
        'name': 'Dailymotion',
        'icon': 'fab fa-dailymotion',
        'color': '#0066dc',
        'domains': ['dailymotion.com', 'www.dailymotion.com']
    },
    'twitch.tv': {
        'name': 'Twitch',
        'icon': 'fab fa-twitch',
        'color': '#9146ff',
        'domains': ['twitch.tv', 'www.twitch.tv', 'clips.twitch.tv']
    },
    'tiktok.com': {
        'name': 'TikTok',
        'icon': 'fab fa-tiktok',
        'color': '#000000',
        'domains': ['tiktok.com', 'www.tiktok.com', 'vm.tiktok.com']
    },
    'instagram.com': {
        'name': 'Instagram',
        'icon': 'fab fa-instagram',
        'color': '#e4405f',
        'domains': ['instagram.com', 'www.instagram.com']
    },
    'facebook.com': {
        'name': 'Facebook',
        'icon': 'fab fa-facebook',
        'color': '#1877f2',
        'domains': ['facebook.com', 'www.facebook.com', 'fb.watch']
    },
    'twitter.com': {
        'name': 'Twitter/X',
        'icon': 'fab fa-twitter',
        'color': '#1da1f2',
        'domains': ['twitter.com', 'x.com', 't.co']
    },
    'soundcloud.com': {
        'name': 'SoundCloud',
        'icon': 'fab fa-soundcloud',
        'color': '#ff5500',
        'domains': ['soundcloud.com', 'www.soundcloud.com']
    },
    'bandcamp.com': {
        'name': 'Bandcamp',
        'icon': 'fas fa-music',
        'color': '#629aa0',
        'domains': ['bandcamp.com', 'www.bandcamp.com']
    }
}

# Rate Limiting
if IS_RAILWAY:
    # Pe Railway - folosește storage în memorie (nu avem Redis)
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["200 per day", "100 per hour", "30 per minute"],
        storage_uri="memory://"
    )
else:
    # Local - folosește storage în memorie
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["200 per day", "100 per hour", "30 per minute"],
        storage_uri="memory://"
    )
limiter.init_app(app)

# Logging pentru securitate
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)
security_logger = logging.getLogger('security')

# Directoare
DOWNLOADS_DIR = 'downloads'
TEMP_DIR = 'temp'
os.makedirs(DOWNLOADS_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)

# Stocare conversii - dictionar global pentru toate conversiile
conversions = {}

# Gestionare conversii per utilizator pentru suport multi-user
user_conversions = {}

# Performance optimizer
if PERFORMANCE_OPTIMIZER_AVAILABLE:
    performance_optimizer = PerformanceOptimizer()
else:
    performance_optimizer = None

# Thread pool pentru conversii paralele
try:
    thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)  # Reduced for Railway
    print("Thread pool initialized successfully")
except Exception as e:
    print(f"Error initializing thread pool: {e}")
    thread_pool = None

# Securitate - Rate limiting per IP
ip_requests = {}
ip_blocks = set()
MAX_REQUESTS_PER_MINUTE = 10
MAX_REQUESTS_PER_HOUR = 100
BLOCK_DURATION = 3600  # 1 oră

# Securitate - Validare URL
ALLOWED_DOMAINS = ['youtube.com', 'youtu.be', 'm.youtube.com']
MALICIOUS_PATTERNS = [
    r'<script.*?>.*?</script>',
    r'javascript:',
    r'data:',
    r'vbscript:',
    r'on\w+\s*=',
    r'<iframe.*?>',
    r'<object.*?>',
    r'<embed.*?>'
]

# Default settings
DEFAULT_SETTINGS = {
    'audio_quality': '192kbps',
    'audio_format': 'mp3',
    'bitrate': 192,
    'sample_rate': 44100,
    'channels': 'stereo',
    'normalize': True,
    'download_folder': DOWNLOADS_DIR,
    'auto_cleanup': True,
    'cleanup_days': 7,
    'theme': 'dark',
    'language': 'ro'
}

# Multi-user support functions
def get_user_id(request):
    """Generează un ID unic pentru utilizator bazat pe session (Railway poate schimba IP-ul)"""
    session_id = session.get('session_id')
    if not session_id:
        session_id = str(uuid.uuid4())
        session['session_id'] = session_id
    # Folosește doar session_id pentru Railway (IP-ul se poate schimba)
    return session_id

def get_user_conversions(user_id):
    """Returnează conversiile pentru un utilizator specific"""
    if user_id not in user_conversions:
        user_conversions[user_id] = {}
    return user_conversions[user_id]

def cleanup_old_conversions():
    """Curăță conversiile vechi pentru a economisi memorie"""
    current_time = time.time()
    cleanup_threshold = 3600  # 1 oră
    
    # Curăță conversiile globale
    to_remove = []
    for conv_id, conv_data in conversions.items():
        if 'started_at' in conv_data:
            try:
                start_time = datetime.fromisoformat(conv_data['started_at']).timestamp()
                if current_time - start_time > cleanup_threshold:
                    to_remove.append(conv_id)
            except:
                to_remove.append(conv_id)
    
    for conv_id in to_remove:
        del conversions[conv_id]
        print(f"Cleaned up old conversion: {conv_id}")
    
    # Curăță conversiile per utilizator
    for user_id, user_conv in user_conversions.items():
        to_remove_user = []
        for conv_id, conv_data in user_conv.items():
            if 'started_at' in conv_data:
                try:
                    start_time = datetime.fromisoformat(conv_data['started_at']).timestamp()
                    if current_time - start_time > cleanup_threshold:
                        to_remove_user.append(conv_id)
                except:
                    to_remove_user.append(conv_id)
        
        for conv_id in to_remove_user:
            del user_conv[conv_id]
            print(f"Cleaned up old user conversion: {user_id} - {conv_id}")

# Security functions
def is_ip_blocked(ip):
    """Verifică dacă IP-ul este blocat"""
    if ip in ip_blocks:
        return True
    return False

def check_rate_limit(ip):
    """Verifică rate limiting pentru IP"""
    current_time = time.time()
    
    if ip not in ip_requests:
        ip_requests[ip] = []
    
    # Curăță request-urile vechi
    ip_requests[ip] = [req_time for req_time in ip_requests[ip] 
                      if current_time - req_time < 3600]  # Ultima oră
    
    # Verifică limitele
    if len(ip_requests[ip]) >= MAX_REQUESTS_PER_HOUR:
        ip_blocks.add(ip)
        security_logger.warning(f"IP {ip} blocked for exceeding hourly limit")
        return False
    
    # Adaugă request-ul curent
    ip_requests[ip].append(current_time)
    return True

def validate_url_security(url):
    """Validează și sanitizează URL-ul pentru multiple platforme"""
    if not url or not isinstance(url, str):
        return False, "URL invalid", None
    
    # Verifică lungimea
    if len(url) > 2048:
        return False, "URL prea lung", None
    
    # Verifică pattern-uri malicioase
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            security_logger.warning(f"Malicious pattern detected in URL: {pattern}")
            return False, "URL contains suspicious content", None
    
    # Verifică domeniul și identifică platforma
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Verifică domeniile suportate
        for platform, config in SUPPORTED_PLATFORMS.items():
            if any(domain.endswith(d) for d in config['domains']):
                return True, f"URL valid pentru {config['name']}", platform
        
        return False, "Unsupported platform", None
            
    except Exception as e:
        security_logger.error(f"URL parsing error: {e}")
        return False, "URL invalid", None

def sanitize_input(text):
    """Sanitizează input-ul utilizatorului"""
    if not text:
        return ""
    
    # Elimină caractere periculoase
    dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '{', '}', '[', ']']
    for char in dangerous_chars:
        text = text.replace(char, '')
    
    # Limitează lungimea
    if len(text) > 1000:
        text = text[:1000]
    
    return text.strip()

def security_headers(response):
    """Adaugă header-uri de securitate"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    return response

def log_security_event(event_type, ip, details=""):
    """Loghează evenimente de securitate"""
    security_logger.info(f"SECURITY_EVENT: {event_type} from IP {ip} - {details}")

def require_security_check(f):
    """Decorator pentru verificări de securitate"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = get_remote_address()
        
        # Verifică dacă IP-ul este blocat
        if is_ip_blocked(client_ip):
            log_security_event("BLOCKED_IP_ACCESS", client_ip)
            return jsonify({'error': 'Acces blocat'}), 403
        
        # Verifică rate limiting
        if not check_rate_limit(client_ip):
            log_security_event("RATE_LIMIT_EXCEEDED", client_ip)
            return jsonify({'error': 'Prea multe request-uri'}), 429
        
        return f(*args, **kwargs)
    return decorated_function

# Available audio qualities
AUDIO_QUALITIES = {
    '128kbps': {'bitrate': 128, 'description': 'Calitate standard'},
    '192kbps': {'bitrate': 192, 'description': 'Calitate bună (recomandat)'},
    '256kbps': {'bitrate': 256, 'description': 'Calitate înaltă'},
    '320kbps': {'bitrate': 320, 'description': 'Calitate maximă'}
}

# Formate audio disponibile
AUDIO_FORMATS = {
    'mp3': {'description': 'Compatibil universal', 'extension': 'mp3'},
    'aac': {'description': 'Calitate înaltă, fișier mic', 'extension': 'aac'},
    'flac': {'description': 'Calitate lossless', 'extension': 'flac'},
    'ogg': {'description': 'Open source, bună calitate', 'extension': 'ogg'}
}

def cleanup_old_files():
    """Șterge fișierele vechi"""
    try:
        cutoff_time = datetime.now() - timedelta(days=DEFAULT_SETTINGS['cleanup_days'])
        for filename in os.listdir(DOWNLOADS_DIR):
            file_path = os.path.join(DOWNLOADS_DIR, filename)
            if os.path.isfile(file_path):
                file_time = datetime.fromtimestamp(os.path.getctime(file_path))
                if file_time < cutoff_time:
                    os.remove(file_path)
                    print(f"Deleted old file: {filename}")
    except Exception as e:
        print(f"ERROR: Cleanup error: {e}")

def get_video_info(url, conversion_id=None):
    """Extrage informații despre video"""
    try:
        ydl_opts = {
            'quiet': True,
            'no_warnings': True,
            'extract_flat': False
        }
        
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            video_info = {
                'title': info.get('title', 'Necunoscut'),
                'duration': info.get('duration', 0),
                'uploader': info.get('uploader', 'Necunoscut'),
                'view_count': info.get('view_count', 0),
                'thumbnail': info.get('thumbnail', ''),
                'description': info.get('description', '')[:200] + '...' if info.get('description') else '',
                'upload_date': info.get('upload_date', ''),
                'webpage_url': info.get('webpage_url', url)
            }
            
            # Actualizează duration în conversie dacă există
            if conversion_id and conversion_id in conversions:
                conversions[conversion_id]['duration'] = video_info['duration']
            
            return video_info
    except Exception as e:
        print(f"ERROR: Information extraction error: {e}")
        return None

def convert_video_to_audio(url, conversion_id, settings):
    """Convertește video-ul în audio cu setările specificate"""
    start_time = time.time()  # Define start_time at the beginning
    try:
        # Obține informațiile video pentru duration
        video_info = get_video_info(url, conversion_id)
        if video_info and 'duration' in video_info:
            conversions[conversion_id]['duration'] = video_info['duration']
        
        # Verifică cache-ul pentru conversii existente
        quality = settings.get('audio_quality', '192kbps')
        format_type = settings.get('audio_format', 'mp3')
        
        if performance_optimizer:
            cached_file, file_size, conversion_time = performance_optimizer.check_cache(url, quality, format_type)
        else:
            cached_file, file_size, conversion_time = None, 0, 0
        if cached_file and os.path.exists(cached_file):
            # Fișierul există în cache, copiază-l
            new_filename = f"{conversion_id}_{os.path.basename(cached_file)}"
            new_file_path = os.path.join(DOWNLOADS_DIR, new_filename)
            shutil.copy2(cached_file, new_file_path)
            
            conversions[conversion_id].update({
                'status': 'completed',
                'progress': 100,
                'file_path': new_file_path,
                'filename': new_filename,
                'file_size': file_size,
                'conversion_time': conversion_time,
                'cached': True
            })
            return
        
        # Obține setările optimizate
        if performance_optimizer:
            ydl_opts = performance_optimizer.optimize_yt_dlp_settings(
                url, quality, format_type, 
                duration=conversions[conversion_id].get('duration', 0)
            )
        else:
            # Setări de bază optimizate pentru conversie MP3
            ydl_opts = {
                'format': 'bestaudio[ext=m4a]/bestaudio/best',
                'quiet': IS_RAILWAY,  # Quiet în producție, verbose în development
                'no_warnings': IS_RAILWAY,  # Fără warning-uri în producție
                'extract_flat': False,
                'writethumbnail': False,
                'writeinfojson': False,
                'writesubtitles': False,
                'writeautomaticsub': False,
                'ignoreerrors': True,
                'no_check_certificate': True,
                'prefer_insecure': False,
                'socket_timeout': 30,  # Mărit pentru fișiere mari
                'retries': 3,  # Mărit pentru fișiere mari
                'fragment_retries': 3,  # Mărit pentru fișiere mari
                'http_chunk_size': 1048576,  # 1MB chunks
                'force_json': False,  # Nu salva JSON
                'writeautomaticsub': False,  # Nu salva subtitrări
                'writesubtitles': False,  # Nu salva subtitrări
                'noplaylist': True,  # Nu descărca playlist-uri
                'extractaudio': True,  # Forțează extragerea audio
                'download_archive': None,  # Nu folosi archive
                'force_download': True,  # Forțează descărcarea
                # Anti-bot measures
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                'referer': 'https://www.youtube.com/',
                'origin': 'https://www.youtube.com',
                'cookiesfrombrowser': None,  # Nu folosi cookies
                'extractor_retries': 5,  # Increased retry pentru extractors
                'sleep_interval': 1,  # Pauză între cereri
                'max_sleep_interval': 5,  # Pauză maximă
                'sleep_interval_subtitles': 1,  # Pauză pentru subtitrări
                'sleep_interval_requests': 1,  # Pauză pentru cereri
                'sleep_interval_fragments': 1,  # Pauză pentru fragmente
                'retries': 5,  # Increased retries for better reliability
                'fragment_retries': 5,  # Increased fragment retries
            }
        
        # Adaugă path-ul de output cu extensia corectă (fără conversion_id în nume)
        output_ext = settings['audio_format']
        ydl_opts['outtmpl'] = os.path.join(DOWNLOADS_DIR, f'%(title)s.{output_ext}')
        ydl_opts['progress_hooks'] = [lambda d: update_progress(conversion_id, d)]
        
        # Configurare FFmpeg pentru Railway și local
        if IS_RAILWAY:
            # Pe Railway - folosește FFmpeg din sistem
            os.environ['FFMPEG_BINARY'] = 'ffmpeg'
            os.environ['FFPROBE_BINARY'] = 'ffprobe'
        else:
            # Local - folosește FFmpeg local
            ffmpeg_path = os.path.join(os.getcwd(), 'ffmpeg', 'ffmpeg-master-latest-win64-gpl', 'bin', 'ffmpeg.exe')
            ffprobe_path = os.path.join(os.getcwd(), 'ffmpeg', 'ffmpeg-master-latest-win64-gpl', 'bin', 'ffprobe.exe')
            
            # Verifică dacă FFmpeg local există
            if os.path.exists(ffmpeg_path):
                ydl_opts['ffmpeg_location'] = ffmpeg_path
                os.environ['FFMPEG_BINARY'] = ffmpeg_path
                os.environ['FFPROBE_BINARY'] = ffprobe_path
            else:
                os.environ['FFMPEG_BINARY'] = 'ffmpeg'
                os.environ['FFPROBE_BINARY'] = 'ffprobe'
        
        if settings['audio_format'] == 'mp3':
            # Forțează descărcarea audio și conversie MP3
            ydl_opts['format'] = 'bestaudio[ext=m4a]/bestaudio/best'
            ydl_opts['postprocessors'] = [{
                'key': 'FFmpegExtractAudio',
                'preferredcodec': 'mp3',
                'preferredquality': str(settings.get('bitrate', 192)),
            }]
            ydl_opts['postprocessor_args'] = [
                '-threads', '0',  # Folosește toate core-urile
                '-preset', 'medium',  # Calitate bună
                '-b:a', f"{settings.get('bitrate', 192)}k",  # Bitrate fix
                '-ac', '2',  # Stereo
                '-ar', '44100',  # Sample rate standard
                '-f', 'mp3',  # Forțează formatul MP3
                '-y'  # Overwrite files
            ]
            # Forțează descărcarea completă
            ydl_opts['extract_flat'] = False
            ydl_opts['writethumbnail'] = False
            ydl_opts['writeinfojson'] = False
            ydl_opts['force_download'] = True
            ydl_opts['download_archive'] = None
        elif settings['audio_format'] == 'aac':
            ydl_opts['postprocessors'] = [{
                'key': 'FFmpegExtractAudio',
                'preferredcodec': 'aac',
                'preferredquality': str(settings.get('bitrate', 192)),
            }]
            ydl_opts['postprocessor_args'] = [
                '-threads', '0',
                '-preset', 'medium',
                '-q:a', '0',
                '-ac', '2',
                '-ar', '44100'
            ]
        elif settings['audio_format'] == 'flac':
            ydl_opts['postprocessors'] = [{
                'key': 'FFmpegExtractAudio',
                'preferredcodec': 'flac',
            }]
            ydl_opts['postprocessor_args'] = [
                '-threads', '0',
                '-preset', 'medium',
                '-ac', '2',
                '-ar', '44100'
            ]
        elif settings['audio_format'] == 'ogg':
            ydl_opts['postprocessors'] = [{
                'key': 'FFmpegExtractAudio',
                'preferredcodec': 'vorbis',
            }]
            ydl_opts['postprocessor_args'] = [
                '-threads', '0',
                '-preset', 'medium',
                '-q:a', '10',  # Calitate maximă pentru Vorbis
                '-ac', '2',
                '-ar', '44100'
            ]
        
        # Optimizări pentru calitate înaltă
        if settings.get('normalize', False):
            # Normalizare pentru calitate înaltă
            if 'postprocessor_args' in ydl_opts:
                ydl_opts['postprocessor_args'].extend(['-af', 'loudnorm'])
            else:
                ydl_opts['postprocessor_args'] = ['-threads', '0', '-af', 'loudnorm']
        
        # Verifică dacă FFmpeg este disponibil
        ffmpeg_available = False
        try:
            import subprocess
            result = subprocess.run(['ffmpeg', '-version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                ffmpeg_available = True
        except Exception as e:
            ffmpeg_available = False
        
        # Pe Railway, dezactivează postprocessors pentru a evita erorile FFmpeg
        if IS_RAILWAY:
            ffmpeg_available = False
            if 'postprocessors' in ydl_opts:
                del ydl_opts['postprocessors']
            if 'postprocessor_args' in ydl_opts:
                del ydl_opts['postprocessor_args']
            print("Railway: FFmpeg postprocessors disabled to avoid filesystem errors")
        
        # Dacă FFmpeg nu este disponibil, elimină postprocessors
        if not ffmpeg_available:
            if 'postprocessors' in ydl_opts:
                del ydl_opts['postprocessors']
            if 'postprocessor_args' in ydl_opts:
                del ydl_opts['postprocessor_args']
        
        # Descărcare și conversie
        if IS_RAILWAY:
            print(f"Railway: FFmpeg available: {ffmpeg_available}")
            print(f"Railway: Postprocessors: {'Yes' if 'postprocessors' in ydl_opts else 'No'}")
            print(f"Railway: Format: {ydl_opts.get('format', 'Not set')}")
            print(f"Railway: Output template: {ydl_opts.get('outtmpl', 'Not set')}")
            print(f"Railway: Force download: {ydl_opts.get('force_download', 'Not set')}")
            print(f"Railway: Extract flat: {ydl_opts.get('extract_flat', 'Not set')}")
            print(f"Railway: Downloads directory: {DOWNLOADS_DIR}")
            print(f"Railway: User agent: {ydl_opts.get('user_agent', 'Not set')}")
        
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=True)
            if IS_RAILWAY:
                print(f"Railway: Download completed, info: {info.get('title', 'No title') if info else 'No info'}")
                if info:
                    print(f"Railway: File size: {info.get('filesize', 'Unknown')} bytes")
                    print(f"Railway: Duration: {info.get('duration', 'Unknown')} seconds")
                    print(f"Railway: Filename: {info.get('filename', 'Unknown')}")
            
            # Salvează thumbnail-ul și informațiile video pentru preview
            if info and 'thumbnail' in info and info['thumbnail']:
                try:
                    import requests
                    thumbnail_url = info['thumbnail']
                    thumbnail_filename = f"{conversion_id}_thumbnail.jpg"
                    thumbnail_path = os.path.join(DOWNLOADS_DIR, thumbnail_filename)
                    
                    # Descarcă thumbnail-ul
                    response = requests.get(thumbnail_url, timeout=10)
                    if response.status_code == 200:
                        with open(thumbnail_path, 'wb') as f:
                            f.write(response.content)
                        conversions[conversion_id]['thumbnail'] = thumbnail_path
                        print(f"Thumbnail saved: {thumbnail_path}")
                except Exception as e:
                    print(f"Could not save thumbnail: {e}")
            
            # Salvează informațiile video pentru preview
            if info:
                conversions[conversion_id]['video_info'] = {
                    'title': info.get('title', ''),
                    'uploader': info.get('uploader', ''),
                    'duration': info.get('duration', 0),
                    'view_count': info.get('view_count', 0),
                    'upload_date': info.get('upload_date', ''),
                    'description': info.get('description', '')[:200] + '...' if info.get('description') else ''
                }
                print(f"Video info saved for preview")
            
            # Găsește fișierul descărcat după titlul video-ului
            print(f"Looking for files in {DOWNLOADS_DIR} with extension {settings['audio_format']}")
            found_file = False
            expected_ext = settings['audio_format']
            
            # Get video title for file search
            video_title = info.get('title', '') if info else ''
            print(f"Video title: {video_title}")
            
            # Wait a moment for file operations to complete
            time.sleep(2)
            
            # Try to find file by title and extension
            if video_title:
                for file in os.listdir(DOWNLOADS_DIR):
                    if file.endswith(f'.{expected_ext}') and video_title in file:
                        file_path = os.path.join(DOWNLOADS_DIR, file)
                        
                        # Wait for file to be fully written
                        max_wait = 10
                        wait_count = 0
                        while wait_count < max_wait:
                            try:
                                # Try to open file to check if it's fully written
                                with open(file_path, 'rb') as f:
                                    f.seek(0, 2)  # Seek to end
                                    file_size = f.tell()
                                    if file_size > 0:
                                        break
                            except (OSError, IOError):
                                pass
                            time.sleep(1)
                            wait_count += 1
                        
                        conversions[conversion_id]['file_path'] = file_path
                        # Clean filename - remove conversion_id prefix and fix double extensions
                        clean_filename = file
                        if file.startswith(conversion_id):
                            clean_filename = file[len(conversion_id)+1:]  # Remove conversion_id + underscore
                        
                        # Fix double extensions (e.g., .mp3.mp3 -> .mp3)
                        if clean_filename.endswith(f'.{expected_ext}.{expected_ext}'):
                            clean_filename = clean_filename[:-len(f'.{expected_ext}')]
                        
                        # Clean up any other unwanted characters
                        clean_filename = clean_filename.replace('_', ' ').replace('  ', ' ').strip()
                        
                        conversions[conversion_id]['filename'] = clean_filename
                        print(f"Found file by title: {file_path}")
                        found_file = True
                        break
            
            # If not found by title, try any file with correct extension created recently
            if not found_file:
                for file in os.listdir(DOWNLOADS_DIR):
                    if file.endswith(f'.{expected_ext}'):
                        file_path = os.path.join(DOWNLOADS_DIR, file)
                        try:
                            file_mtime = os.path.getmtime(file_path)
                            if file_mtime > start_time - 60:  # Created in last minute
                                # Wait for file to be fully written
                                max_wait = 5
                                wait_count = 0
                                while wait_count < max_wait:
                                    try:
                                        with open(file_path, 'rb') as f:
                                            f.seek(0, 2)  # Seek to end
                                            file_size = f.tell()
                                            if file_size > 0:
                                                break
                                    except (OSError, IOError):
                                        pass
                                    time.sleep(1)
                                    wait_count += 1
                                
                                conversions[conversion_id]['file_path'] = file_path
                                # Clean filename - remove conversion_id prefix and fix double extensions
                                clean_filename = file
                                if file.startswith(conversion_id):
                                    clean_filename = file[len(conversion_id)+1:]  # Remove conversion_id + underscore
                                
                                # Fix double extensions (e.g., .mp3.mp3 -> .mp3)
                                if clean_filename.endswith(f'.{expected_ext}.{expected_ext}'):
                                    clean_filename = clean_filename[:-len(f'.{expected_ext}')]
                                
                                # Clean up any other unwanted characters
                                clean_filename = clean_filename.replace('_', ' ').replace('  ', ' ').strip()
                                
                                conversions[conversion_id]['filename'] = clean_filename
                                print(f"Found recent file: {file_path}")
                                found_file = True
                                break
                        except (OSError, IOError) as e:
                            print(f"Error accessing file {file_path}: {e}")
                            continue
            
            if not found_file:
                print(f"ERROR: No file found starting with {conversion_id}")
                # Try to find any recent files
                recent_files = []
                try:
                    for file in os.listdir(DOWNLOADS_DIR):
                        file_path = os.path.join(DOWNLOADS_DIR, file)
                        if os.path.isfile(file_path):
                            mtime = os.path.getmtime(file_path)
                            if mtime > start_time - 60:  # Files created in last minute
                                recent_files.append((file_path, mtime))
                    
                    if recent_files:
                        # Use the most recent file
                        recent_files.sort(key=lambda x: x[1], reverse=True)
                        file_path, _ = recent_files[0]
                        
                        # Wait for file to be fully written
                        max_wait = 5
                        wait_count = 0
                        while wait_count < max_wait:
                            try:
                                with open(file_path, 'rb') as f:
                                    f.seek(0, 2)  # Seek to end
                                    file_size = f.tell()
                                    if file_size > 0:
                                        break
                            except (OSError, IOError):
                                pass
                            time.sleep(1)
                            wait_count += 1
                        
                        conversions[conversion_id]['file_path'] = file_path
                        conversions[conversion_id]['filename'] = os.path.basename(file_path)
                        print(f"Using most recent file: {file_path}")
                        found_file = True
                    
                    if not found_file:
                        print("ERROR: No recent files found")
                        conversions[conversion_id]['status'] = 'error'
                        conversions[conversion_id]['error'] = 'No output file found after conversion'
                        return
                except Exception as e:
                    print(f"ERROR: Exception while looking for files: {e}")
                    conversions[conversion_id]['status'] = 'error'
                    conversions[conversion_id]['error'] = f'Error finding output file: {str(e)}'
                    return
            
            conversions[conversion_id]['status'] = 'completed'
            conversions[conversion_id]['progress'] = 100
            conversions[conversion_id]['completed_at'] = datetime.now().isoformat()
            
            # Adaugă în cache pentru reutilizare
            if performance_optimizer:
                try:
                    file_size = os.path.getsize(conversions[conversion_id]['file_path'])
                    conversion_time = time.time() - start_time
                    performance_optimizer.add_to_cache(
                        url, quality, format_type, conversions[conversion_id]['file_path'], file_size, conversion_time
                    )
                    
                    # Actualizează metricile
                    performance_optimizer.metrics['total_conversions'] += 1
                    performance_optimizer.metrics['conversions'].append(conversion_time)
                except (OSError, IOError) as e:
                    print(f"Could not add to cache: {e}")
            
            # Try to get file size for display
            try:
                file_path = conversions[conversion_id]['file_path']
                if file_path and os.path.exists(file_path):
                    file_size = os.path.getsize(file_path)
                    conversions[conversion_id]['file_size'] = file_size
                    print(f"File size: {file_size} bytes")
            except (OSError, IOError) as e:
                print(f"Could not get file size: {e}")
            
            print(f"Conversion completed: {conversion_id}")
            
    except Exception as e:
        print(f"ERROR: Conversion error: {e}")
        conversions[conversion_id]['status'] = 'error'
        conversions[conversion_id]['error'] = str(e)

def update_progress(conversion_id, d):
    """Actualizează progresul conversiei"""
    if conversion_id in conversions:
        # Update status based on yt-dlp status
        if d['status'] == 'downloading':
            conversions[conversion_id]['status'] = 'downloading'
            if 'total_bytes' in d and d['total_bytes'] and d['total_bytes'] > 0:
                progress = (d['downloaded_bytes'] / d['total_bytes']) * 100
                conversions[conversion_id]['progress'] = min(progress, 99)
                conversions[conversion_id]['downloaded_bytes'] = d['downloaded_bytes']
                conversions[conversion_id]['total_bytes'] = d['total_bytes']
            else:
                conversions[conversion_id]['progress'] = 50  # Default progress for downloading
        elif d['status'] == 'finished':
            conversions[conversion_id]['status'] = 'completed'  # Conversion is complete
            conversions[conversion_id]['progress'] = 100
            
            # Setează file_path și filename
            if 'filename' in d and d['filename']:
                file_path = d['filename']
                if IS_RAILWAY:
                    print(f"Railway: Finished callback - filename: {file_path}")
                if os.path.exists(file_path):
                    conversions[conversion_id]['file_path'] = file_path
                    conversions[conversion_id]['filename'] = os.path.basename(file_path)
                    if IS_RAILWAY:
                        print(f"Railway: File found at: {file_path}")
                else:
                    # Caută fișierul în folderul downloads
                    filename = os.path.basename(file_path)
                    downloads_path = os.path.join(DOWNLOADS_DIR, filename)
                    if IS_RAILWAY:
                        print(f"Railway: Looking for file at: {downloads_path}")
                    if os.path.exists(downloads_path):
                        conversions[conversion_id]['file_path'] = downloads_path
                        conversions[conversion_id]['filename'] = filename
                        if IS_RAILWAY:
                            print(f"Railway: File found in downloads: {downloads_path}")
                    else:
                        conversions[conversion_id]['status'] = 'error'
                        conversions[conversion_id]['error'] = 'Output file not found'
                        if IS_RAILWAY:
                            print(f"Railway: File not found anywhere: {file_path}")
        elif d['status'] == 'error':
            conversions[conversion_id]['status'] = 'error'
            conversions[conversion_id]['error'] = d.get('error', 'Download failed')

@app.route('/')
def index():
    """Pagina principală"""
    # FORȚEAZĂ template-ul original pe toate platformele
    try:
        response = make_response(render_template('index_professional.html'))
        return security_headers(response)
    except Exception as e:
        if IS_RAILWAY:
            print(f"Template error on Railway: {e}")
            # Pe Railway - returnează eroare JSON în loc de HTML
            return jsonify({
                "error": "Template not found", 
                "message": "index_professional.html not found on Railway",
                "details": str(e)
            })
        else:
            app.logger.error(f"Template error: {e}")
            # Local - returnează eroare JSON
            return jsonify({
                "error": "Template not found", 
                "message": "index_professional.html not found locally",
                "details": str(e)
            })

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({"status": "ok", "message": "Application is running"})


@app.route('/legal-policies')
def legal_policies():
    """Pagina cu politicile legale"""
    if IS_RAILWAY:
        # Pe Railway - returnează mesaj simplu
        return jsonify({"message": "Legal policies not available on Railway deployment"})
    else:
        # Local development - folosește template-ul original
        try:
            response = make_response(render_template('legal_policies.html'))
            return security_headers(response)
        except Exception as e:
            app.logger.error(f"Legal policies template error: {e}")
            return jsonify({"error": "Legal policies template not found"})

@app.route('/static/<path:filename>')
def static_files(filename):
    """Servește fișierele statice pentru PWA cu cache headers"""
    response = send_from_directory('static', filename)
    
    # Add cache headers for static files
    if filename.endswith(('.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg')):
        response.headers['Cache-Control'] = 'public, max-age=31536000'  # 1 year
    elif filename.endswith(('.json', '.xml')):
        response.headers['Cache-Control'] = 'public, max-age=3600'  # 1 hour
    else:
        response.headers['Cache-Control'] = 'public, max-age=86400'  # 1 day
    
    return response

@app.route('/api/validate', methods=['POST'])
@require_security_check
def validate_url():
    """Validează URL-ul video"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'success': False, 'error': 'URL-ul este gol'})
        
        # Validare securitate URL și identificare platformă
        is_valid, error_msg, platform = validate_url_security(url)
        if not is_valid:
            log_security_event("INVALID_URL", get_remote_address(), f"URL: {url}")
            return jsonify({'success': False, 'error': error_msg})
        
        # Verifică dacă platforma este suportată
        if not platform or platform not in SUPPORTED_PLATFORMS:
            return jsonify({'success': False, 'error': 'Unsupported platform'})
        
        # Extrage informații despre video
        video_info = get_video_info(url)
        if not video_info:
            return jsonify({'success': False, 'error': 'Could not extract video information'})
        
        # Don't return platform information to avoid legal issues
        return jsonify({
            'success': True,
            'video_info': video_info
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Validation error: {str(e)}'})

@app.route('/api/convert', methods=['POST'])
@require_security_check
def convert_video():
    """Începe conversia video-ului"""
    try:
        # Check human verification first
        print(f"Session data: {dict(session)}")
        print(f"Human verified: {session.get('human_verified')}")
        
        if not session.get('human_verified'):
            print("Human verification required - user not verified")
            return jsonify({'success': False, 'error': 'Human verification required'}), 403
        
        data = request.get_json()
        url = data.get('url', '').strip()
        settings = data.get('settings', DEFAULT_SETTINGS)
        
        if not url:
            return jsonify({'success': False, 'error': 'URL-ul este gol'})
        
        # Validare securitate URL
        is_valid, error_msg, _ = validate_url_security(url)
        if not is_valid:
            log_security_event("INVALID_URL_CONVERT", get_remote_address(), f"URL: {url}")
            return jsonify({'success': False, 'error': error_msg})
        
        # Generează ID unic pentru conversie
        conversion_id = str(uuid.uuid4())
        user_id = get_user_id(request)
        
        # Inițializează conversia
        conversion_data = {
            'id': conversion_id,
            'url': url,
            'status': 'starting',
            'progress': 0,
            'duration': 0,  # Default duration
            'started_at': datetime.now().isoformat(),
            'settings': settings,
            'file_path': None,
            'filename': None,
            'error': None,
            'user_id': user_id
        }
        
        # Adaugă conversia în ambele locuri
        conversions[conversion_id] = conversion_data
        user_conversions[user_id] = user_conversions.get(user_id, {})
        user_conversions[user_id][conversion_id] = conversion_data
        
        print(f"Started conversion {conversion_id} for user {user_id}")
        
        # Pornește conversia în thread pool pentru performanță optimă
        if thread_pool:
            future = thread_pool.submit(convert_video_to_audio, url, conversion_id, settings)
        else:
            # Fallback: run in current thread if thread pool is not available
            print("Thread pool not available, running conversion in current thread")
            convert_video_to_audio(url, conversion_id, settings)
            return jsonify({
                'success': True,
                'conversion_id': conversion_id,
                'message': 'Conversion started (single thread)'
            })
        
        # Adaugă future-ul la conversie pentru tracking
        conversions[conversion_id]['future'] = future
        
        return jsonify({
            'success': True,
            'conversion_id': conversion_id,
            'message': 'Conversion started'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Conversion error: {str(e)}'})

@app.route('/api/status/<conversion_id>')
def get_status(conversion_id):
    """Returnează statusul conversiei"""
    try:
        if conversion_id not in conversions:
            return jsonify({'success': False, 'error': 'Conversion does not exist'})
        
        conversion = conversions[conversion_id]
        user_id = get_user_id(request)
        
        # Verifică dacă utilizatorul are acces la această conversie
        if conversion.get('user_id') != user_id:
            print(f"Access denied: user {user_id} tried to access conversion {conversion_id} owned by {conversion.get('user_id')}")
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        
        response = {
            'success': True,
            'status': conversion['status'],
            'progress': conversion.get('progress', 0),
            'started_at': conversion.get('started_at'),
            'completed_at': conversion.get('completed_at'),
            'error': conversion.get('error')
        }
        
        # Adaugă URL-ul de descărcare dacă conversia este completă
        if conversion['status'] == 'completed' and conversion.get('file_path'):
            response['download_url'] = f'/api/download/{conversion_id}'
            response['filename'] = conversion.get('filename', '')
            response['file_size'] = os.path.getsize(conversion['file_path']) if os.path.exists(conversion['file_path']) else 0
            
            print(f"Status response - download_url: {response['download_url']}")
            print(f"Status response - filename: {response['filename']}")
            print(f"Status response - file_size: {response['file_size']}")
            
            # Adaugă thumbnail-ul și informațiile video pentru preview
            if conversion.get('thumbnail'):
                response['thumbnail_url'] = f'/api/thumbnail/{conversion_id}'
            if conversion.get('video_info'):
                response['video_info'] = conversion['video_info']
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Status error: {str(e)}'})

@app.route('/api/download/<conversion_id>')
@require_security_check
def download_file(conversion_id):
    """Descarcă fișierul convertit"""
    try:
        print(f"Download request for conversion_id: {conversion_id}")
        
        if conversion_id not in conversions:
            print(f"Conversion {conversion_id} not found in conversions")
            return jsonify({'error': 'Conversion does not exist'}), 404
        
        conversion = conversions[conversion_id]
        user_id = get_user_id(request)
        
        # Verifică dacă utilizatorul are acces la această conversie
        if conversion.get('user_id') != user_id:
            print(f"Download access denied: user {user_id} tried to download conversion {conversion_id} owned by {conversion.get('user_id')}")
            return jsonify({'error': 'Access denied'}), 403
        
        print(f"Conversion status: {conversion['status']}")
        
        if conversion['status'] != 'completed':
            print(f"Conversion not completed: {conversion['status']}")
            return jsonify({'error': 'Conversion is not complete'}), 400
        
        file_path = conversion.get('file_path')
        print(f"File path: {file_path}")
        
        if not file_path:
            print("File path is not set")
            return jsonify({'error': 'File path is not set'}), 404
            
        if not os.path.exists(file_path):
            print(f"File does not exist: {file_path}")
            return jsonify({'error': 'File does not exist'}), 404
        
        filename = conversion.get('filename', 'download')
        print(f"Sending file: {file_path} as {filename}")
        
        return send_file(file_path, as_attachment=True, download_name=filename)
        
    except Exception as e:
        print(f"Download error: {e}")
        return jsonify({'error': f'Download error: {str(e)}'}), 500

@app.route('/api/thumbnail/<conversion_id>')
def get_thumbnail(conversion_id):
    """Returnează thumbnail-ul pentru conversie"""
    try:
        if conversion_id not in conversions:
            return jsonify({'error': 'Conversion does not exist'}), 404
        
        conversion = conversions[conversion_id]
        thumbnail_path = conversion.get('thumbnail')
        
        if not thumbnail_path or not os.path.exists(thumbnail_path):
            return jsonify({'error': 'Thumbnail not found'}), 404
        
        return send_file(thumbnail_path, mimetype='image/jpeg')
        
    except Exception as e:
        return jsonify({'error': f'Thumbnail error: {str(e)}'}), 500

@app.route('/api/settings', methods=['GET', 'POST'])
def handle_settings():
    """Gestionează setările aplicației"""
    try:
        if request.method == 'GET':
            return jsonify({
                'success': True,
                'settings': DEFAULT_SETTINGS,
                'audio_qualities': AUDIO_QUALITIES,
                'audio_formats': AUDIO_FORMATS
            })
        
        elif request.method == 'POST':
            data = request.get_json()
            new_settings = data.get('settings', {})
            
            # Actualizează setările
            DEFAULT_SETTINGS.update(new_settings)
            
            return jsonify({
                'success': True,
                'message': 'Settings have been updated',
                'settings': DEFAULT_SETTINGS
            })
            
    except Exception as e:
        return jsonify({'success': False, 'error': f'Settings error: {str(e)}'})

@app.route('/api/cleanup', methods=['POST'])
def cleanup_files():
    """Curăță fișierele vechi"""
    try:
        cleanup_old_files()
        return jsonify({
            'success': True,
            'message': 'Cleanup completed'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': f'Cleanup error: {str(e)}'})



# Platform route removed to avoid legal issues

@app.route('/api/verify-human', methods=['POST'])
@limiter.limit("5 per minute")
def verify_human():
    """Verifică dacă utilizatorul este uman - versiune simplificată"""
    try:
        data = request.get_json()
        verified = data.get('verified')
        
        print(f"Verification request: {data}")
        print(f"Verified flag: {verified}")
        
        if verified:
            # Log successful verification
            log_security_event('human_verification_success', request.remote_addr, f'User verified successfully')
            
            # Set session flag for verified user
            session['human_verified'] = True
            session['verification_time'] = time.time()
            
            print(f"Session set - human_verified: {session.get('human_verified')}")
            
            return jsonify({
                'success': True,
                'message': 'Human verification successful'
            })
        else:
            return jsonify({'success': False, 'error': 'Verification required'}), 400
            
    except Exception as e:
        log_security_event('human_verification_error', request.remote_addr, f'Error: {str(e)}')
        return jsonify({'success': False, 'error': f'Verification error: {str(e)}'}), 500


if __name__ == '__main__':
    print("Starting SimpleMP3 Converter...")
    print("Open browser at: http://localhost:5000")
    print("Professional features activated")
    print("Advanced settings available")
    print("Dark/Light themes")
    print("Performance optimizations activated")
    print("Intelligent cache activated")
    print("To stop: Press Ctrl+C")
    
    # Curăță fișierele vechi la pornire
    cleanup_old_files()
    
    # Curăță conversiile vechi la pornire
    cleanup_old_conversions()
    
    # Pornește monitorizarea resurselor
    if performance_optimizer:
        performance_optimizer.start_resource_monitoring()
    
    # Production vs Development configuration
    if IS_RAILWAY:
        debug_mode = False
        host = '0.0.0.0'
        port = int(os.environ.get('PORT', 5000))
    else:
        debug_mode = True  # Enable debug mode locally
        host = '127.0.0.1'  # Localhost for local development
        port = 5000
    
    # Only run if this is the main module (not imported)
    if __name__ == '__main__':
        try:
            print(f"Starting Flask app on {host}:{port}, debug={debug_mode}")
            print(f"IS_RAILWAY: {IS_RAILWAY}")
            app.run(host=host, port=port, debug=debug_mode)
        except KeyboardInterrupt:
            print("\nStopping application...")
            if performance_optimizer:
                performance_optimizer.stop_resource_monitoring()
            if thread_pool:
                thread_pool.shutdown(wait=True)
            print("Application stopped successfully")
        except Exception as e:
            print(f"Error starting Flask app: {e}")
            import traceback
            traceback.print_exc()
