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

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = SECRET_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

socketio = SocketIO(app, **SOCKET_IO_SETTINGS)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)


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

        # File Info tablosu (YENİ TASARIM)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_info (
                file_id INT PRIMARY KEY AUTO_INCREMENT,
                file_uuid VARCHAR(36) UNIQUE NOT NULL,
                sender_id INT NOT NULL,
                receiver_id INT NOT NULL,
                file_name VARCHAR(255) NOT NULL,
                file_size BIGINT NOT NULL,
                encrypted_aes_key TEXT NOT NULL,
                status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
                total_pieces INT NOT NULL,
                download_count INT DEFAULT 0,
                last_downloaded_at TIMESTAMP NULL,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP NULL,
                FOREIGN KEY (sender_id) REFERENCES users(user_id) ON DELETE CASCADE,
                FOREIGN KEY (receiver_id) REFERENCES users(user_id) ON DELETE CASCADE,
                INDEX idx_sender (sender_id),
                INDEX idx_receiver (receiver_id),
                INDEX idx_status (status),
                INDEX idx_uuid (file_uuid)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)

        # File Pieces tablosu (YENİ TASARIM)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_pieces (
                piece_id INT PRIMARY KEY AUTO_INCREMENT,
                file_id INT NOT NULL,
                piece_number INT NOT NULL,
                encrypted_piece LONGBLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (file_id) REFERENCES file_info(file_id) ON DELETE CASCADE,
                UNIQUE KEY unique_piece (file_id, piece_number),
                INDEX idx_file (file_id),
                INDEX idx_piece_number (piece_number)
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
    cursor.execute("SELECT user_id, username, email, name, surname, public_key FROM users WHERE user_id = %s",
                   (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user


def get_user_by_username(username):
    conn = get_db_connection()
    if not conn:
        return None
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT user_id, username, email, name, surname, public_key FROM users WHERE username = %s",
                   (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user


def update_file_status(file_id):
    """Parça sayısı kontrol edip status'ü güncelle"""
    conn = get_db_connection()
    if not conn:
        return

    cursor = conn.cursor(dictionary=True)

    # Dosya bilgilerini al
    cursor.execute("SELECT total_pieces FROM file_info WHERE file_id = %s", (file_id,))
    file_info = cursor.fetchone()

    if not file_info:
        cursor.close()
        conn.close()
        return

    # Yüklenen parça sayısını bul
    cursor.execute("SELECT COUNT(*) as piece_count FROM file_pieces WHERE file_id = %s", (file_id,))
    piece_count = cursor.fetchone()['piece_count']

    # Status'ü güncelle
    if piece_count >= file_info['total_pieces']:
        cursor.execute("""
            UPDATE file_info 
            SET status = 'completed', completed_at = NOW() 
            WHERE file_id = %s AND status != 'completed'
        """, (file_id,))
        conn.commit()
        if cursor.rowcount > 0:
            print(f"✅ Dosya {file_id} tamamlandı ({piece_count}/{file_info['total_pieces']})")

    cursor.close()
    conn.close()


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

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Veritabanı bağlantı hatası!'}), 500

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM users WHERE username = %s OR email = %s", (username, email))
        if cursor.fetchone():
            return jsonify({'error': 'Bu kullanıcı adı veya email zaten kayıtlı!'}), 400

        cursor.execute("INSERT INTO users (username, email, name, surname, public_key) VALUES (%s, %s, %s, %s, %s)",
                       (username, email, name, surname, public_key))
        conn.commit()
        user_id = cursor.lastrowid

        token = jwt.encode(
            {'user_id': user_id, 'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)},
            app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({'message': 'Kayıt başarılı!', 'user_id': user_id, 'username': username, 'token': token}), 201
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

    token = jwt.encode({'user_id': user['user_id'], 'username': user['username'],
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)},
                       app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'message': 'Giriş başarılı!', 'user_id': user['user_id'], 'username': user['username'],
                    'name': user['name'], 'surname': user['surname'], 'public_key': user['public_key'], 'token': token})


@app.route('/api/users/search', methods=['GET'])
@token_required
def search_users(current_user):
    query = request.args.get('q', '')

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Veritabanı bağlantı hatası!'}), 500

    cursor = conn.cursor(dictionary=True)

    if not query:
        cursor.execute("""
            SELECT user_id, username, name, surname 
            FROM users 
            WHERE user_id != %s
            ORDER BY username
            LIMIT 50
        """, (current_user['user_id'],))
    else:
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
    return jsonify({'user_id': user['user_id'], 'username': user['username'], 'public_key': user['public_key']})


@app.route('/api/messages/send', methods=['POST'])
@token_required
def send_message(current_user):
    data = request.json
    receiver_id = data.get('receiver_id')
    encrypted_message = data.get('encrypted_message')
    encrypted_aes_key = data.get('encrypted_aes_key')
    message_type = data.get('message_type', 'text')

    if not all([receiver_id, encrypted_message, encrypted_aes_key]):
        return jsonify({'error': 'Eksik bilgi!'}), 400

    receiver = get_user_by_id(receiver_id)
    if not receiver:
        return jsonify({'error': 'Alıcı bulunamadı!'}), 404

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Veritabanı bağlantı hatası!'}), 500

    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO messages (user_id, sender_id, encrypted_message, encrypted_aes_key, message_type)
            VALUES (%s, %s, %s, %s, %s)
        """, (receiver_id, current_user['user_id'], encrypted_message, encrypted_aes_key, message_type))
        conn.commit()
        message_id = cursor.lastrowid

        socketio.emit('new_message', {
            'message_id': message_id,
            'sender_id': current_user['user_id'],
            'sender_username': current_user['username'],
            'message_type': message_type
        }, room=f"user_{receiver_id}")

        return jsonify({'message': 'Mesaj gönderildi!', 'message_id': message_id}), 201
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
        SELECT m.*, u1.username as sender_username, u2.username as receiver_username
        FROM messages m
        JOIN users u1 ON m.sender_id = u1.user_id
        JOIN users u2 ON m.user_id = u2.user_id
        WHERE m.user_id = %s OR m.sender_id = %s
        ORDER BY m.sent_at DESC LIMIT 100
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
    cursor.execute(
        "UPDATE messages SET is_read = TRUE, read_at = NOW(), status = 'read' WHERE message_id = %s AND user_id = %s",
        (message_id, current_user['user_id']))
    conn.commit()
    affected = cursor.rowcount
    cursor.close()
    conn.close()

    if affected > 0:
        socketio.emit('message_read', {'message_id': message_id, 'reader_id': current_user['user_id']})
        return jsonify({'message': 'Okundu olarak işaretlendi'})
    return jsonify({'error': 'Mesaj bulunamadı veya size ait değil'}), 404


# ==================== YENİ DOSYA YÜKLEME API'LERİ ====================

@app.route('/api/files/upload', methods=['POST'])
@token_required
def upload_file_piece(current_user):
    """Dosya parçasını yükle"""

    receiver_id = request.form.get('receiver_id', type=int)
    encrypted_aes_key = request.form.get('encrypted_aes_key')
    total_pieces = request.form.get('total_pieces', type=int)
    current_piece = request.form.get('current_piece', type=int)
    file_uuid = request.form.get('file_uuid')
    file_name = request.form.get('file_name')
    file_size = request.form.get('file_size', type=int)
    encrypted_piece = request.files.get('piece')

    if not all([receiver_id, encrypted_aes_key, encrypted_piece]):
        return jsonify({'error': 'Eksik bilgi! receiver_id, encrypted_aes_key ve piece gerekli'}), 400

    receiver = get_user_by_id(receiver_id)
    if not receiver:
        return jsonify({'error': 'Alıcı bulunamadı!'}), 404

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Veritabanı bağlantı hatası!'}), 500

    try:
        cursor = conn.cursor()

        # İlk parça ise file_info kaydı oluştur
        if current_piece == 0:
            file_uuid = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO file_info 
                (file_uuid, sender_id, receiver_id, file_name, file_size, encrypted_aes_key, total_pieces, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending')
            """, (
            file_uuid, current_user['user_id'], receiver_id, file_name, file_size, encrypted_aes_key, total_pieces))
            conn.commit()
            file_id = cursor.lastrowid
            print(f"📁 Yeni dosya kaydı oluşturuldu: ID={file_id}, UUID={file_uuid}, Parça={total_pieces}")
        else:
            # File UUID ile file_id bul
            cursor.execute("SELECT file_id FROM file_info WHERE file_uuid = %s", (file_uuid,))
            result = cursor.fetchone()
            if not result:
                return jsonify({'error': 'Dosya kaydı bulunamadı!'}), 404
            file_id = result[0]

        # Parçayı kaydet
        piece_data = encrypted_piece.read()
        cursor.execute("""
            INSERT INTO file_pieces (file_id, piece_number, encrypted_piece)
            VALUES (%s, %s, %s)
        """, (file_id, current_piece, piece_data))
        conn.commit()
        print(f"💾 Parça {current_piece + 1}/{total_pieces} kaydedildi - Dosya ID: {file_id}")

        # Status'ü kontrol et ve güncelle
        update_file_status(file_id)

        # Dosyanın durumunu kontrol et
        cursor.execute("SELECT status FROM file_info WHERE file_id = %s", (file_id,))
        status = cursor.fetchone()[0]

        completed = (status == 'completed')

        # Tüm parçalar tamamlandıysa alıcıya bildirim gönder
        if completed:
            cursor.execute("SELECT file_uuid, file_name, file_size FROM file_info WHERE file_id = %s", (file_id,))
            file_data = cursor.fetchone()
            socketio.emit('new_file', {
                'file_uuid': file_data[0],
                'sender_id': current_user['user_id'],
                'sender_username': current_user['username'],
                'file_name': file_data[1],
                'file_size': file_data[2]
            }, room=f"user_{receiver_id}")
            print(f"✅ Dosya tamamlandı ve bildirim gönderildi: {file_data[1]}")

        return jsonify({
            'message': 'Parça yüklendi!',
            'file_uuid': file_uuid,
            'piece': current_piece,
            'total_pieces': total_pieces,
            'completed': completed
        }), 201

    except Error as e:
        print(f"❌ Veritabanı hatası: {e}")
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

    # Dosyayı bul (alıcı kontrolü)
    cursor.execute("""
        SELECT * FROM file_info 
        WHERE file_uuid = %s AND receiver_id = %s AND status = 'completed'
    """, (file_uuid, current_user['user_id']))

    file_info = cursor.fetchone()

    if not file_info:
        cursor.close()
        conn.close()
        return jsonify({'error': 'Dosya bulunamadı!'}), 404

    # Parçaları al
    cursor.execute("""
        SELECT encrypted_piece 
        FROM file_pieces 
        WHERE file_id = %s 
        ORDER BY piece_number ASC
    """, (file_info['file_id'],))

    pieces = cursor.fetchall()
    cursor.close()

    # Birleştir
    combined_data = b''
    for piece in pieces:
        combined_data += piece['encrypted_piece']

    # İndirme sayısını güncelle
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE file_info 
        SET download_count = download_count + 1, last_downloaded_at = NOW() 
        WHERE file_id = %s
    """, (file_info['file_id'],))
    conn.commit()
    cursor.close()
    conn.close()

    from flask import send_file
    import io
    return send_file(
        io.BytesIO(combined_data),
        download_name=file_info['file_name'],
        as_attachment=True,
        mimetype='application/octet-stream'
    )
@app.route('/api/files/<file_uuid>/status', methods=['GET'])
@token_required
def get_file_status(current_user, file_uuid):
    """Dosya durumunu kontrol et"""

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Veritabanı bağlantı hatası!'}), 500

    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT status, total_pieces, 
               (SELECT COUNT(*) FROM file_pieces WHERE file_id = file_info.file_id) as uploaded_pieces
        FROM file_info 
        WHERE file_uuid = %s AND (sender_id = %s OR receiver_id = %s)
    """, (file_uuid, current_user['user_id'], current_user['user_id']))

    result = cursor.fetchone()
    cursor.close()
    conn.close()

    if not result:
        return jsonify({'error': 'Dosya bulunamadı!'}), 404

    return jsonify(result)


# ==================== SOCKET.IO OLAYLARI ====================

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
        join_room(f"user_{user_id}")
        print(f"🔐 Kullanıcı doğrulandı: {username} (ID: {user_id})")
        emit('authenticated', {'status': 'success'})
    except Exception as e:
        print(f"❌ Kimlik doğrulama hatası: {e}")
        emit('authenticated', {'status': 'error'})


@socketio.on('disconnect')
def handle_disconnect():
    print(f"🔴 İstemci ayrıldı: {request.sid}")


@app.route('/api/files/<file_uuid>/info', methods=['GET'])
@token_required
def get_file_info(current_user, file_uuid):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Veritabanı bağlantı hatası!'}), 500

    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT file_id, file_uuid, file_name, file_size, encrypted_aes_key, status
        FROM file_info 
        WHERE file_uuid = %s AND receiver_id = %s
    """, (file_uuid, current_user['user_id']))

    file_info = cursor.fetchone()
    cursor.close()
    conn.close()

    if not file_info:
        return jsonify({'error': 'Dosya bulunamadı!'}), 404

    return jsonify(file_info)
# ==================== MAIN ====================

if __name__ == '__main__':
    print("=" * 60)
    print("🔐 GÜVENLİ MESAJLAŞMA SUNUCUSU".center(60))
    print("=" * 60)

    if init_database():
        print("✅ Veritabanı hazır!")
    else:
        print("❌ Veritabanı başlatılamadı!")
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

    socketio.run(app, host='0.0.0.0', port=5001, debug=True, allow_unsafe_werkzeug=True)