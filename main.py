from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit, join_room
import mysql.connector
from mysql.connector import Error
import jwt
import datetime
from functools import wraps
import os
import uuid
import hashlib
from config import DB_CONFIG, SECRET_KEY, UPLOAD_FOLDER, SOCKET_IO_SETTINGS

app = Flask(__name__,
            template_folder='templates',  # templates klasörünü belirt
            static_folder='static')  # static klasörünü belirt

app.config['SECRET_KEY'] = SECRET_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

socketio = SocketIO(app, **SOCKET_IO_SETTINGS)

# Upload klasörünü oluştur
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs('templates', exist_ok=True)  # templates klasörünü oluştur
os.makedirs('static', exist_ok=True)  # static klasörünü oluştur


# JWT Token decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token missing!'}), 401
        try:
            token = token.split(' ')[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = get_user_by_id(data['user_id'])
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
        return f(current_user, *args, **kwargs)

    return decorated


# Veritabanı yardımcı fonksiyonları
def get_db_connection():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error as e:
        print(f"Veritabanı bağlantı hatası: {e}")
        return None


def init_database():
    conn = get_db_connection()
    if not conn:
        print("❌ Veritabanına bağlanılamadı!")
        print("Lütfen MySQL'in çalıştığından emin olun ve config.py'deki DB_CONFIG ayarlarını kontrol edin.")
        return False

    cursor = conn.cursor()

    try:
        # Users tablosu
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                name VARCHAR(50),
                surname VARCHAR(50),
                public_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL,
                is_active BOOLEAN DEFAULT TRUE,
                INDEX idx_username (username),
                INDEX idx_email (email)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        # Messages tablosu
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                message_id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                sender_id INT NOT NULL,
                encrypted_message TEXT NOT NULL,
                encrypted_aes_key TEXT NOT NULL,
                message_type ENUM('text', 'file') DEFAULT 'text',
                file_id INT NULL,
                is_read BOOLEAN DEFAULT FALSE,
                read_at TIMESTAMP NULL,
                status ENUM('sent', 'delivered', 'read') DEFAULT 'sent',
                parent_message_id INT NULL,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                FOREIGN KEY (sender_id) REFERENCES users(user_id) ON DELETE CASCADE,
                INDEX idx_receiver (user_id),
                INDEX idx_sender (sender_id),
                INDEX idx_sent_at (sent_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        # Files tablosu
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                file_id INT PRIMARY KEY AUTO_INCREMENT,
                file_uuid VARCHAR(36) UNIQUE NOT NULL,
                user_id INT NOT NULL,
                sender_id INT NOT NULL,
                original_file_name VARCHAR(255) NOT NULL,
                encrypted_file_path VARCHAR(500) NOT NULL,
                encrypted_aes_key TEXT NOT NULL,
                file_size BIGINT NOT NULL,
                mime_type VARCHAR(100),
                file_hash VARCHAR(64),
                download_count INT DEFAULT 0,
                last_downloaded_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                FOREIGN KEY (sender_id) REFERENCES users(user_id) ON DELETE CASCADE,
                INDEX idx_user (user_id),
                INDEX idx_uuid (file_uuid)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        conn.commit()
        print("✅ Veritabanı tabloları hazır!")
        return True
    except Error as e:
        print(f"❌ Tablo oluşturma hatası: {e}")
        return False
    finally:
        cursor.close()
        conn.close()


def get_user_by_id(user_id):
    conn = get_db_connection()
    if not conn:
        return None

    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT user_id, username, email, name, surname, public_key 
        FROM users WHERE user_id = %s
    """, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user


def get_user_by_username(username):
    conn = get_db_connection()
    if not conn:
        return None

    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT user_id, username, email, name, surname, public_key 
        FROM users WHERE username = %s
    """, (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user


# HTML sayfaları
@app.route('/')
def index_page():
    return render_template('index.html')


@app.route('/register')
def register_page():
    return render_template('register.html')


@app.route('/login')
def login_page():
    return render_template('login.html')


@app.route('/chat')
def chat_page():
    return render_template('chat.html')


# API endpoints
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json

    username = data.get('username')
    email = data.get('email')
    name = data.get('name', '')
    surname = data.get('surname', '')
    public_key = data.get('public_key')

    if not username or not email or not public_key:
        return jsonify({'error': 'Username, email ve public_key zorunludur!'}), 400

    if len(username) < 3 or len(username) > 50:
        return jsonify({'error': 'Username 3-50 karakter arası olmalıdır!'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Veritabanı bağlantı hatası!'}), 500

    try:
        cursor = conn.cursor()

        cursor.execute("SELECT user_id FROM users WHERE username = %s OR email = %s", (username, email))
        if cursor.fetchone():
            return jsonify({'error': 'Bu kullanıcı adı veya email zaten kayıtlı!'}), 400

        query = """
        INSERT INTO users (username, email, name, surname, public_key)
        VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(query, (username, email, name, surname, public_key))
        conn.commit()

        user_id = cursor.lastrowid

        token = jwt.encode({
            'user_id': user_id,
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({
            'message': 'Kayıt başarılı!',
            'user_id': user_id,
            'username': username,
            'token': token
        }), 201

    except Error as e:
        return jsonify({'error': f'Veritabanı hatası: {str(e)}'}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')

    if not username:
        return jsonify({'error': 'Username gerekli!'}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({'error': 'Kullanıcı bulunamadı!'}), 404

    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_login = NOW() WHERE user_id = %s", (user['user_id'],))
        conn.commit()
        cursor.close()
        conn.close()

    token = jwt.encode({
        'user_id': user['user_id'],
        'username': user['username'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({
        'message': 'Giriş başarılı!',
        'user_id': user['user_id'],
        'username': user['username'],
        'name': user['name'],
        'surname': user['surname'],
        'public_key': user['public_key'],
        'token': token
    })


@app.route('/api/users/search', methods=['GET'])
@token_required
def search_users(current_user):
    query = request.args.get('q', '')

    if not query or len(query) < 1:
        return jsonify([])

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Veritabanı bağlantı hatası!'}), 500

    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT user_id, username, name, surname 
        FROM users 
        WHERE username LIKE %s AND user_id != %s
        LIMIT 20
    """, (f'%{query}%', current_user['user_id']))

    users = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify(users)


@app.route('/api/users/<int:user_id>/public-key', methods=['GET'])
@token_required
def get_public_key(current_user, user_id):
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'error': 'Kullanıcı bulunamadı!'}), 404

    return jsonify({
        'user_id': user['user_id'],
        'username': user['username'],
        'public_key': user['public_key']
    })

socketio = SocketIO(app,
                   cors_allowed_origins="*",
                   ping_timeout=60,
                   ping_interval=25,
                   logger=True,  # Logları aç
                   engineio_logger=True)
@app.route('/api/messages/send', methods=['POST'])
@token_required
def send_message(current_user):
    data = request.json
    receiver_id = data.get('receiver_id')
    encrypted_message = data.get('encrypted_message')
    encrypted_aes_key = data.get('encrypted_aes_key')
    message_type = data.get('message_type', 'text')

    if not all([receiver_id, encrypted_message, encrypted_aes_key]):
        return jsonify({'error': 'Eksik bilgi! receiver_id, encrypted_message ve encrypted_aes_key gerekli'}), 400

    receiver = get_user_by_id(receiver_id)
    if not receiver:
        return jsonify({'error': 'Alıcı bulunamadı!'}), 404

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Veritabanı bağlantı hatası!'}), 500

    try:
        cursor = conn.cursor()

        query = """
        INSERT INTO messages 
        (user_id, sender_id, encrypted_message, encrypted_aes_key, message_type)
        VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(query, (receiver_id, current_user['user_id'],
                               encrypted_message, encrypted_aes_key, message_type))
        conn.commit()

        message_id = cursor.lastrowid

        socketio.emit('new_message', {
            'message_id': message_id,
            'sender_id': current_user['user_id'],
            'sender_username': current_user['username'],
            'message_type': message_type
        }, room=f"user_{receiver_id}")

        return jsonify({
            'message': 'Mesaj gönderildi!',
            'message_id': message_id
        }), 201

    except Error as e:
        return jsonify({'error': f'Veritabanı hatası: {str(e)}'}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/messages', methods=['GET'])
@token_required
def get_messages(current_user):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Veritabanı bağlantı hatası!'}), 500

    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT m.*, 
               u1.username as sender_username,
               u2.username as receiver_username
        FROM messages m
        JOIN users u1 ON m.sender_id = u1.user_id
        JOIN users u2 ON m.user_id = u2.user_id
        WHERE m.user_id = %s OR m.sender_id = %s
        ORDER BY m.sent_at DESC
        LIMIT 100
    """, (current_user['user_id'], current_user['user_id']))

    messages = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify(messages)


@app.route('/api/messages/<int:message_id>/read', methods=['POST'])
@token_required
def mark_as_read(current_user, message_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Veritabanı bağlantı hatası!'}), 500

    cursor = conn.cursor()
    cursor.execute("""
        UPDATE messages 
        SET is_read = TRUE, read_at = NOW(), status = 'read'
        WHERE message_id = %s AND user_id = %s
    """, (message_id, current_user['user_id']))
    conn.commit()

    affected = cursor.rowcount
    cursor.close()
    conn.close()

    if affected > 0:
        socketio.emit('message_read', {
            'message_id': message_id,
            'reader_id': current_user['user_id']
        })
        return jsonify({'message': 'Okundu olarak işaretlendi'})
    else:
        return jsonify({'error': 'Mesaj bulunamadı veya size ait değil'}), 404


@app.route('/api/files/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    receiver_id = request.form.get('receiver_id')
    encrypted_aes_key = request.form.get('encrypted_aes_key')
    file = request.files.get('file')

    if not all([receiver_id, encrypted_aes_key, file]):
        return jsonify({'error': 'Eksik bilgi! receiver_id, encrypted_aes_key ve file gerekli'}), 400

    receiver = get_user_by_id(receiver_id)
    if not receiver:
        return jsonify({'error': 'Alıcı bulunamadı!'}), 404

    file_uuid = str(uuid.uuid4())
    file_extension = os.path.splitext(file.filename)[1]
    saved_filename = f"{file_uuid}{file_extension}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)

    file.save(file_path)
    file_size = os.path.getsize(file_path)

    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    file_hash = sha256_hash.hexdigest()

    conn = get_db_connection()
    if not conn:
        os.remove(file_path)
        return jsonify({'error': 'Veritabanı bağlantı hatası!'}), 500

    try:
        cursor = conn.cursor()

        query = """
        INSERT INTO files 
        (file_uuid, user_id, sender_id, original_file_name, encrypted_file_path, 
         encrypted_aes_key, file_size, mime_type, file_hash)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (
            file_uuid, receiver_id, current_user['user_id'],
            file.filename, file_path, encrypted_aes_key,
            file_size, file.mimetype, file_hash
        ))
        conn.commit()

        file_id = cursor.lastrowid

        socketio.emit('new_file', {
            'file_id': file_id,
            'file_uuid': file_uuid,
            'sender_id': current_user['user_id'],
            'sender_username': current_user['username'],
            'file_name': file.filename,
            'file_size': file_size
        }, room=f"user_{receiver_id}")

        return jsonify({
            'message': 'Dosya yüklendi!',
            'file_id': file_id,
            'file_uuid': file_uuid
        }), 201

    except Error as e:
        os.remove(file_path)
        return jsonify({'error': f'Veritabanı hatası: {str(e)}'}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/files/<file_uuid>', methods=['GET'])
@token_required
def download_file(current_user, file_uuid):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Veritabanı bağlantı hatası!'}), 500

    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT * FROM files 
        WHERE file_uuid = %s AND user_id = %s
    """, (file_uuid, current_user['user_id']))

    file_info = cursor.fetchone()
    cursor.close()
    conn.close()

    if not file_info:
        return jsonify({'error': 'Dosya bulunamadı veya erişim yetkiniz yok!'}), 404

    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE files 
            SET download_count = download_count + 1, last_downloaded_at = NOW()
            WHERE file_id = %s
        """, (file_info['file_id'],))
        conn.commit()
        cursor.close()
        conn.close()

    from flask import send_file
    return send_file(
        file_info['encrypted_file_path'],
        download_name=file_info['original_file_name'],
        as_attachment=True
    )


# SocketIO olayları
@socketio.on('connect')
def handle_connect():
    print(f"🟢 İstemci bağlandı: {request.sid}")


@socketio.on('authenticate')
def handle_authenticate(data):
    token = data.get('token')
    try:
        token_data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = token_data['user_id']
        username = token_data['username']

        room = f"user_{user_id}"
        join_room(room)

        print(f"🔐 Kullanıcı doğrulandı: {username} (ID: {user_id})")
        emit('authenticated', {'status': 'success'})
    except Exception as e:
        print(f"❌ Kimlik doğrulama hatası: {e}")
        emit('authenticated', {'status': 'error'})


@socketio.on('disconnect')
def handle_disconnect():
    print(f"🔴 İstemci ayrıldı: {request.sid}")


if __name__ == '__main__':
    print("=" * 60)
    print("🔐 GÜVENLİ MESAJLAŞMA SUNUCUSU".center(60))
    print("=" * 60)

    print("\n📦 Veritabanı başlatılıyor...")
    if init_database():
        print("✅ Veritabanı hazır!")
    else:
        print("❌ Veritabanı başlatılamadı!")
        print("Lütfen MySQL sunucusunun çalıştığından emin olun.")
        print("MySQL kurulu değilse: brew install mysql")
        print("MySQL başlat: brew services start mysql")
        exit(1)

    import socket

    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except:
        local_ip = "127.0.0.1"

    print(f"\n🌐 Yerel ağ adresi: http://{local_ip}:5001")
    print("🌍 Localhost: http://localhost:5001")
    print("\n🚀 Sunucu başlatılıyor...")
    print("-" * 60)
    print("📢 NOT: Bu sunucu geliştirme amaçlıdır.")
    print("🔴 Durdurmak için Ctrl+C'ye basın")
    print("-" * 60)

    # allow_unsafe_werkzeug=True ekledik!
    socketio.run(app, host='0.0.0.0', port=5001, debug=True, allow_unsafe_werkzeug=True)