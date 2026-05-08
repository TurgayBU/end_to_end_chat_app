from flask import Blueprint, request, jsonify, render_template
from functools import wraps
import jwt
import datetime
import mysql.connector
from mysql.connector import Error
import os

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Admin secret key (güvenli bir yerde saklayın)
ADMIN_SECRET = os.environ.get('ADMIN_SECRET', 'your-super-secret-admin-key-change-this')


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Token'ı header veya query parameter'dan al
        token = request.headers.get('X-Admin-Token')
        if not token:
            token = request.args.get('admin_token')

        if not token:
            return jsonify({'error': 'Admin token required! Provide X-Admin-Token header or ?admin_token= param'}), 401

        try:
            # Token'ı decode et
            jwt.decode(token, ADMIN_SECRET, algorithms=['HS256'])
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid admin token!'}), 403

        return f(*args, **kwargs)

    return decorated


def get_db():
    """Veritabanı bağlantısı"""
    try:
        from config import DB_CONFIG
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error as e:
        print(f"Admin DB bağlantı hatası: {e}")
        return None


@admin_bp.route('/setup', methods=['POST'])
def admin_setup():
    """
    İlk kurulumda admin token üretir.
    Body: { "setup_key": "SETUP_KEY_ENV_VALUE" }
    """
    setup_key = os.environ.get('SETUP_KEY', 'initial_setup_key')
    body = request.json or {}

    if body.get('setup_key') != setup_key:
        return jsonify({'error': 'Wrong setup key'}), 403

    token = jwt.encode(
        {'role': 'admin', 'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)},
        ADMIN_SECRET, algorithm='HS256'
    )
    return jsonify({
        'admin_token': token,
        'note': 'Store this securely. Add X-Admin-Token header to all /admin/* requests.'
    })


@admin_bp.route('/api/conversations', methods=['GET'])
@admin_required
def get_conversations():
    """Tüm kullanıcı çiftlerini ve mesaj sayılarını döndür"""
    conn = get_db()
    if not conn:
        return jsonify({'error': 'DB connection failed'}), 500

    cursor = conn.cursor(dictionary=True)
    try:
        # DÜZELTİLMİŞ SORGU - GROUP BY sorununu çözen versiyon
        cursor.execute("""
            SELECT 
                conv.user_a_id,
                conv.user_b_id,
                u1.username AS user_a_name,
                u2.username AS user_b_name,
                conv.msg_count,
                conv.last_msg_at
            FROM (
                SELECT 
                    LEAST(m.sender_id, m.user_id) AS user_a_id,
                    GREATEST(m.sender_id, m.user_id) AS user_b_id,
                    COUNT(*) AS msg_count,
                    MAX(m.sent_at) AS last_msg_at
                FROM messages m
                GROUP BY user_a_id, user_b_id
            ) conv
            JOIN users u1 ON u1.user_id = conv.user_a_id
            JOIN users u2 ON u2.user_id = conv.user_b_id
            ORDER BY conv.last_msg_at DESC
            LIMIT 50
        """)
        conversations = cursor.fetchall()

        print(f"✅ Conversations found: {len(conversations)}")

        for c in conversations:
            if c.get('last_msg_at'):
                c['last_msg_at'] = str(c['last_msg_at'])

        return jsonify(conversations)
    except Exception as e:
        print(f"❌ Error in get_conversations: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()
@admin_bp.route('/api/messages', methods=['GET'])
@admin_required
def get_messages_between():
    user_a = request.args.get('user_a', type=int)
    user_b = request.args.get('user_b', type=int)
    limit = request.args.get('limit', 100, type=int)

    if not user_a or not user_b:
        return jsonify({'error': 'user_a and user_b required'}), 400

    conn = get_db()
    if not conn:
        return jsonify({'error': 'DB connection failed'}), 500

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT
                m.message_id,
                m.sender_id,
                m.user_id AS receiver_id,
                u1.username AS sender_name,
                u2.username AS receiver_name,
                m.encrypted_message,
                m.encrypted_aes_key,
                m.message_type,
                m.is_read,
                m.status,
                m.sent_at,
                LENGTH(m.encrypted_message)  AS enc_msg_bytes,
                LENGTH(m.encrypted_aes_key)  AS enc_key_bytes,
                LEFT(u1.public_key, 80) AS sender_pub_key_preview,
                LEFT(u2.public_key, 80) AS receiver_pub_key_preview
            FROM messages m
            JOIN users u1 ON u1.user_id = m.sender_id
            JOIN users u2 ON u2.user_id = m.user_id
            WHERE (m.sender_id = %s AND m.user_id = %s)
               OR (m.sender_id = %s AND m.user_id = %s)
            ORDER BY m.sent_at ASC
            LIMIT %s
        """, (user_a, user_b, user_b, user_a, limit))

        messages = cursor.fetchall()
        for msg in messages:
            if msg.get('sent_at'):
                msg['sent_at'] = str(msg['sent_at'])
            if msg.get('encrypted_message'):
                msg['enc_preview'] = msg['encrypted_message'][:80]
            if msg.get('encrypted_aes_key'):
                msg['aes_key_preview'] = msg['encrypted_aes_key'][:60]

        return jsonify(messages)
    except Exception as e:
        print(f"Error in get_messages_between: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@admin_bp.route('/api/users', methods=['GET'])
@admin_required
def get_all_users():
    conn = get_db()
    if not conn:
        return jsonify({'error': 'DB connection failed'}), 500

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT user_id, username, email, name, surname,
                   LEFT(public_key, 80) AS public_key_preview,
                   created_at, last_login, is_active,
                   (SELECT COUNT(*) FROM messages WHERE sender_id = users.user_id) AS sent_count,
                   (SELECT COUNT(*) FROM messages WHERE user_id   = users.user_id) AS recv_count
            FROM users
            ORDER BY created_at DESC
        """)
        users = cursor.fetchall()
        for u in users:
            if u.get('created_at'): u['created_at'] = str(u['created_at'])
            if u.get('last_login'):  u['last_login'] = str(u['last_login'])
        return jsonify(users)
    except Exception as e:
        print(f"Error in get_all_users: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@admin_bp.route('/api/stats', methods=['GET'])
@admin_required
def get_stats():
    conn = get_db()
    if not conn:
        return jsonify({'error': 'DB connection failed'}), 500

    cursor = conn.cursor(dictionary=True)
    try:
        stats = {}

        cursor.execute("SELECT COUNT(*) AS cnt FROM users")
        stats['total_users'] = cursor.fetchone()['cnt']

        cursor.execute("SELECT COUNT(*) AS cnt FROM messages")
        stats['total_messages'] = cursor.fetchone()['cnt']

        cursor.execute("SELECT COUNT(*) AS cnt FROM messages WHERE message_type='file'")
        stats['file_messages'] = cursor.fetchone()['cnt']

        cursor.execute("SELECT COUNT(*) AS cnt FROM messages WHERE DATE(sent_at) = CURDATE()")
        stats['messages_today'] = cursor.fetchone()['cnt']

        cursor.execute("""
            SELECT u.username, COUNT(*) AS cnt
            FROM messages m JOIN users u ON u.user_id = m.sender_id
            GROUP BY m.sender_id ORDER BY cnt DESC LIMIT 5
        """)
        stats['top_senders'] = cursor.fetchall()

        cursor.execute("""
            SELECT AVG(LENGTH(encrypted_message)) AS avg_bytes,
                   MAX(LENGTH(encrypted_message)) AS max_bytes
            FROM messages
        """)
        row = cursor.fetchone()
        stats['avg_encrypted_bytes'] = round(float(row['avg_bytes'] or 0), 1)
        stats['max_encrypted_bytes'] = int(row['max_bytes'] or 0)

        return jsonify(stats)
    except Exception as e:
        print(f"Error in get_stats: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@admin_bp.route('/test', methods=['GET'])
def admin_test():
    """Test endpoint - admin blueprint'in çalışıp çalışmadığını kontrol et"""
    return jsonify({
        'status': 'ok',
        'message': 'Admin blueprint is working!',
        'routes': ['/setup', '/monitor', '/api/stats', '/api/users', '/api/conversations', '/api/messages']
    })


@admin_bp.route('/monitor')
def admin_monitor_page():
    """
    Admin monitor sayfası.
    URL: http://localhost:5001/admin/monitor?admin_token=<token>
    """
    admin_token = request.args.get('admin_token', '')

    # Token kontrolü
    if not admin_token:
        return """
        <html>
        <body style="background:#060a12;color:#f87171;font-family:monospace;padding:40px">
        <h2>⛔ Access Denied</h2>
        <p>Admin token required. Please provide ?admin_token= parameter.</p>
        <hr>
        <p style="color:#64748b;font-size:12px">Get token first:<br>
        curl -X POST http://localhost:5001/admin/setup -H 'Content-Type: application/json' -d '{"setup_key": "initial_setup_key"}'
        </p>
        </body>
        </html>
        """, 403

    try:
        jwt.decode(admin_token, ADMIN_SECRET, algorithms=['HS256'])
    except jwt.InvalidTokenError:
        return """
        <html>
        <body style="background:#060a12;color:#f87171;font-family:monospace;padding:40px">
        <h2>⛔ Invalid Token</h2>
        <p>The provided admin token is invalid or expired.</p>
        <hr>
        <p style="color:#64748b;font-size:12px">Generate a new token:<br>
        curl -X POST http://localhost:5001/admin/setup -H 'Content-Type: application/json' -d '{"setup_key": "initial_setup_key"}'
        </p>
        </body>
        </html>
        """, 403

    # templates/admin_monitor.html dosyasını render et
    return render_template('admin_monitor.html', admin_token=admin_token)