# config.py - Sadece konfigürasyon sabitleri
import os

# Veritabanı konfigürasyonu
DB_CONFIG = {
    'host': 'localhost',
    'database': 'chatapp',
    'user': 'root',
    'password': '',  # Kendi şifrenizle değiştirin
    'charset': 'utf8mb4',
    'use_unicode': True,
    'autocommit': True
}

# JWT için gizli anahtar (çok önemli!)
SECRET_KEY = 'cok-gizli-anahtar-buraya-en-az-32-byte-olsun'

# Uygulama ayarları
UPLOAD_FOLDER = 'uploads'
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}

# Socket.IO ayarları
SOCKET_IO_SETTINGS = {
    'cors_allowed_origins': '*',
    'ping_timeout': 60,
    'ping_interval': 25
}
