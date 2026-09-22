import requests
import socketio
import os
import base64
import json
import time
from encryption import AES256Encrypt
from decrption import AES256Decrypt  # AES class'ları
from key_creations import key as RSAKey  # Sizin RSA class'ınız


class MessagingClient:
    def __init__(self, server_url="http://localhost:5000"):
        """
        İstemci sınıfı - Sizin RSA class'ınızı kullanır
        """
        self.server_url = server_url
        self.sio = socketio.Client()
        self.user_id = None
        self.username = None
        self.token = None
        self.rsa_keys = None  # RSA key objesi
        self.public_key = None
        self.private_key = None
        self.modulus = None

        # SocketIO olaylarını bağla
        self.setup_socket_events()

    def setup_socket_events(self):
        """SocketIO olaylarını ayarla"""

        @self.sio.on('connect')
        def on_connect():
            print("✅ Sunucuya bağlandı!")
            if self.token:
                self.sio.emit('authenticate', {'token': self.token})

        @self.sio.on('authenticated')
        def on_authenticated(data):
            if data['status'] == 'success':
                print("✅ Gerçek zamanlı mesajlar hazır!")
            else:
                print("❌ Kimlik doğrulama başarısız!")

        @self.sio.on('new_message')
        def on_new_message(data):
            print(f"\n🔔 Yeni mesaj! Gönderen: {data['sender_username']}")
            self.get_messages()

        @self.sio.on('new_file')
        def on_new_file(data):
            print(f"\n📁 Yeni dosya! Gönderen: {data['sender_username']}")
            print(f"Dosya: {data['file_name']}")

    def generate_rsa_keys(self):
        """Sizin RSA class'ınız ile key oluştur"""
        print("🔐 RSA anahtarları oluşturuluyor...")

        # RSA key objesi oluştur
        self.rsa_keys = RSAKey(None)  # DB bağlantısı yok, None gönder

        # Prime numbers ve key'leri oluştur
        key_data = self.rsa_keys.Prime_Number()

        # Key'leri al
        self.public_key = key_data['public_key']
        self.private_key = key_data['private_key']
        self.modulus = key_data['modulus']

        print(f"✅ RSA anahtarları oluşturuldu!")
        print(f"   Public Key: {str(self.public_key)[:50]}...")
        print(f"   Modulus: {str(self.modulus)[:50]}...")

        # Private key'i dosyaya kaydet
        self.save_private_key()

        # Public key'i PEM formatında hazırla (server'a göndermek için)
        public_key_pem = f"{self.public_key}:{self.modulus}"
        return public_key_pem

    def save_private_key(self, filename=None):
        """Private key'i dosyaya kaydet (sayısal değer olarak)"""
        if not filename:
            filename = f"private_key_{self.username}.txt"

        with open(filename, 'w') as f:
            f.write(f"PRIVATE KEY: {self.private_key}\n")
            f.write(f"MODULUS: {self.modulus}\n")
            f.write(f"PUBLIC KEY: {self.public_key}\n")

        print(f"✅ Private key '{filename}' dosyasına kaydedildi")
        print("⚠️  BU DOSYAYI KİMSEYLE PAYLAŞMA!")

    def load_private_key(self, username):
        """Private key'i dosyadan yükle"""
        filename = f"private_key_{username}.txt"
        try:
            with open(filename, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    if line.startswith("PRIVATE KEY:"):
                        self.private_key = int(line.split(":")[1].strip())
                    elif line.startswith("MODULUS:"):
                        self.modulus = int(line.split(":")[1].strip())
                    elif line.startswith("PUBLIC KEY:"):
                        self.public_key = int(line.split(":")[1].strip())

            print(f"✅ Private key '{filename}' dosyasından yüklendi")
            return True
        except FileNotFoundError:
            print(f"❌ Private key dosyası bulunamadı: {filename}")
            return False
        except Exception as e:
            print(f"❌ Key yüklenirken hata: {e}")
            return False

    def rsa_encrypt(self, message_int, public_key, modulus):
        """RSA şifreleme: c = m^e mod n"""
        return pow(message_int, public_key, modulus)

    def rsa_decrypt(self, cipher_int, private_key, modulus):
        """RSA şifre çözme: m = c^d mod n"""
        return pow(cipher_int, private_key, modulus)

    def int_to_bytes(self, n):
        """Integer'ı byte'a çevir"""
        return n.to_bytes((n.bit_length() + 7) // 8, 'big')

    def bytes_to_int(self, b):
        """Byte'ı integer'a çevir"""
        return int.from_bytes(b, 'big')

    def register(self, username, email, name, surname):
        """Sunucuya kayıt ol"""
        # RSA anahtarlarını oluştur
        public_key_pem = self.generate_rsa_keys()
        self.username = username

        data = {
            'username': username,
            'email': email,
            'name': name,
            'surname': surname,
            'public_key': public_key_pem  # "public_key:modulus" formatında
        }

        try:
            response = requests.post(f"{self.server_url}/api/register", json=data)
            if response.status_code == 201:
                result = response.json()
                self.user_id = result['user_id']
                self.token = result['token']
                print(f"✅ Kayıt başarılı! Kullanıcı ID: {self.user_id}")

                self.connect_socket()
                return True
            else:
                print(f"❌ Kayıt hatası: {response.json().get('error')}")
                return False
        except Exception as e:
            print(f"❌ Sunucuya bağlanılamadı: {e}")
            return False

    def login(self, username):
        """Sunucuya giriş yap"""
        # Önce private key'i yükle
        if not self.load_private_key(username):
            print("⚠️  Private key bulunamadı! Önce kayıt olmalısınız.")
            return False

        self.username = username
        data = {'username': username}

        try:
            response = requests.post(f"{self.server_url}/api/login", json=data)
            if response.status_code == 200:
                result = response.json()
                self.user_id = result['user_id']
                self.token = result['token']
                self.public_key_pem = result['public_key']
                print(f"✅ Giriş başarılı! Hoş geldin {self.username}")

                self.connect_socket()
                return True
            else:
                print(f"❌ Giriş hatası: {response.json().get('error')}")
                return False
        except Exception as e:
            print(f"❌ Sunucuya bağlanılamadı: {e}")
            return False

    def connect_socket(self):
        """SocketIO bağlantısını kur"""
        try:
            self.sio.connect(self.server_url)
            self.sio.emit('authenticate', {'token': self.token})
        except Exception as e:
            print(f"⚠️ Socket bağlantı hatası: {e}")

    def search_users(self, query):
        """Kullanıcı ara"""
        headers = {'Authorization': f'Bearer {self.token}'}
        response = requests.get(
            f"{self.server_url}/api/users/search?q={query}",
            headers=headers
        )
        return response.json()

    def parse_public_key(self, public_key_pem):
        """Public key string'inden public_key ve modulus'u ayır"""
        try:
            if ':' in public_key_pem:
                pub_key, modulus = public_key_pem.split(':')
                return int(pub_key), int(modulus)
            else:
                # Eğer sadece public key varsa (eski format)
                return int(public_key_pem), None
        except:
            return None, None

    def send_message(self, receiver_username, message_text):
        """Şifreli mesaj gönder - Sizin RSA'nız ile"""
        # 1. Alıcıyı bul
        users = self.search_users(receiver_username)
        receiver = next((u for u in users if u['username'] == receiver_username), None)

        if not receiver:
            print(f"❌ Kullanıcı bulunamadı: {receiver_username}")
            return False

        receiver_id = receiver['user_id']
        receiver_public_key_pem = receiver['public_key']

        # 2. Alıcının public key'ini parse et
        receiver_public_key, receiver_modulus = self.parse_public_key(receiver_public_key_pem)
        if not receiver_public_key or not receiver_modulus:
            print(f"❌ Alıcının public key'i geçersiz!")
            return False

        # 3. Rastgele AES key oluştur (32 byte = 256 bit)
        aes_key = os.urandom(32)

        # 4. AES encryption class'ını kullanarak mesajı şifrele
        aes_encryptor = AES256Encrypt(None, message_text)
        aes_encryptor.key = aes_key
        aes_encryptor.round_keys = aes_encryptor.key_expansion()
        encrypted_message = aes_encryptor.encrypt()

        # 5. AES key'i integer'a çevir ve RSA ile şifrele
        aes_key_int = self.bytes_to_int(aes_key)
        encrypted_aes_key_int = self.rsa_encrypt(aes_key_int, receiver_public_key, receiver_modulus)

        # 6. Şifrelenmiş AES key'i base64'e çevir
        encrypted_aes_key_bytes = self.int_to_bytes(encrypted_aes_key_int)
        encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key_bytes).decode()

        # 7. Sunucuya gönder
        data = {
            'receiver_id': receiver_id,
            'encrypted_message': encrypted_message,
            'encrypted_aes_key': encrypted_aes_key_b64,
            'message_type': 'text'
        }

        headers = {'Authorization': f'Bearer {self.token}'}
        response = requests.post(
            f"{self.server_url}/api/messages/send",
            json=data,
            headers=headers
        )

        if response.status_code == 201:
            print(f"✅ Mesaj {receiver_username}'e gönderildi!")
            return True
        else:
            print(f"❌ Mesaj gönderilemedi: {response.json().get('error')}")
            return False

    def get_messages(self):
        """Mesajları getir ve çöz - Sizin RSA'nız ile"""
        headers = {'Authorization': f'Bearer {self.token}'}
        response = requests.get(
            f"{self.server_url}/api/messages",
            headers=headers
        )

        if response.status_code == 200:
            messages = response.json()
            print("\n" + "=" * 60)
            print("📨 MESAJLAR".center(60))
            print("=" * 60)

            for msg in messages:
                # Gelen mesajları çöz (kendi private key'inle)
                if msg['user_id'] == self.user_id and msg.get('encrypted_aes_key'):
                    try:
                        # Base64'ten encrypted AES key'i al
                        encrypted_aes_key_bytes = base64.b64decode(msg['encrypted_aes_key'])
                        encrypted_aes_key_int = self.bytes_to_int(encrypted_aes_key_bytes)

                        # AES key'i RSA ile çöz (kendi private key'inle)
                        aes_key_int = self.rsa_decrypt(encrypted_aes_key_int, self.private_key, self.modulus)
                        aes_key = self.int_to_bytes(aes_key_int)

                        # Mesajı AES ile çöz
                        aes_decryptor = AES256Decrypt(None)
                        aes_decryptor.key = aes_key
                        aes_decryptor.round_keys = aes_decryptor.key_expansion()
                        decrypted = aes_decryptor.decrypt(msg['encrypted_message'])

                        # Tarihi formatla
                        sent_at = msg['sent_at'][:16] if msg['sent_at'] else "bilinmiyor"

                        print(f"\n📨 [{sent_at}] {msg['sender_username']}:")
                        print(f"   {decrypted}")

                        # Okundu olarak işaretle
                        if not msg['is_read']:
                            self.mark_as_read(msg['message_id'])

                    except Exception as e:
                        print(f"\n❌ [{msg['sent_at'][:16]}] {msg['sender_username']}:")
                        print(f"   [ŞİFRELİ MESAJ - ÇÖZÜLEMEDİ: {e}]")

                # Gönderdiğin mesajlar
                elif msg['sender_id'] == self.user_id:
                    sent_at = msg['sent_at'][:16] if msg['sent_at'] else "bilinmiyor"
                    receiver_name = msg.get('receiver_username', 'bilinmiyor')
                    status = "✓✓" if msg['is_read'] else "✓"
                    print(f"\n📤 [{sent_at}] Sen -> {receiver_name} {status}")

            return messages
        return []

    def mark_as_read(self, message_id):
        """Mesajı okundu işaretle"""
        headers = {'Authorization': f'Bearer {self.token}'}
        try:
            requests.post(
                f"{self.server_url}/api/messages/{message_id}/read",
                headers=headers
            )
        except:
            pass

    def send_file(self, receiver_username, file_path):
        """Şifreli dosya gönder"""
        # 1. Alıcıyı bul
        users = self.search_users(receiver_username)
        receiver = next((u for u in users if u['username'] == receiver_username), None)

        if not receiver:
            print(f"❌ Kullanıcı bulunamadı: {receiver_username}")
            return False

        receiver_id = receiver['user_id']
        receiver_public_key_pem = receiver['public_key']

        # 2. Alıcının public key'ini parse et
        receiver_public_key, receiver_modulus = self.parse_public_key(receiver_public_key_pem)
        if not receiver_public_key or not receiver_modulus:
            print(f"❌ Alıcının public key'i geçersiz!")
            return False

        # 3. Rastgele AES key oluştur
        aes_key = os.urandom(32)

        # 4. Dosyayı oku ve AES ile şifrele
        with open(file_path, 'rb') as f:
            file_data = f.read()

        # Basit XOR şifreleme (gerçekte dosya için de AES kullanın)
        encrypted_data = bytes([b ^ aes_key[i % len(aes_key)] for i, b in enumerate(file_data)])

        # Geçici şifreli dosya oluştur
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)

        # 5. AES key'i RSA ile şifrele
        aes_key_int = self.bytes_to_int(aes_key)
        encrypted_aes_key_int = self.rsa_encrypt(aes_key_int, receiver_public_key, receiver_modulus)
        encrypted_aes_key_bytes = self.int_to_bytes(encrypted_aes_key_int)
        encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key_bytes).decode()

        # 6. Sunucuya gönder
        headers = {'Authorization': f'Bearer {self.token}'}
        files = {'file': open(encrypted_file_path, 'rb')}
        data = {
            'receiver_id': receiver_id,
            'encrypted_aes_key': encrypted_aes_key_b64
        }

        response = requests.post(
            f"{self.server_url}/api/files/upload",
            headers=headers,
            data=data,
            files=files
        )

        # Geçici dosyayı sil
        files['file'].close()
        os.remove(encrypted_file_path)

        if response.status_code == 201:
            result = response.json()
            print(f"✅ Dosya gönderildi! UUID: {result['file_uuid']}")
            return True
        else:
            print(f"❌ Dosya gönderilemedi: {response.json().get('error')}")
            return False

    def disconnect(self):
        """Bağlantıyı kapat"""
        if self.sio.connected:
            self.sio.disconnect()
        print("👋 Bağlantı kapatıldı")


def main():
    print("=" * 60)
    print("🔐 GÜVENLİ MESAJLAŞMA UYGULAMASI".center(60))
    print("=" * 60)

    # Sunucu IP'sini sor
    server_ip = input("\n🌐 Sunucu IP adresi (Enter: localhost): ").strip()
    if not server_ip:
        server_ip = "localhost"

    server_url = f"http://{server_ip}:5000"
    print(f"📡 Sunucu: {server_url}")

    client = MessagingClient(server_url)

    while True:
        print("\n" + "-" * 40)
        print("1. 📝 Kayıt Ol")
        print("2. 🔑 Giriş Yap")
        print("3. 🚪 Çıkış")
        print("-" * 40)

        choice = input("Seçiminiz: ").strip()

        if choice == '1':
            username = input("Kullanıcı adı: ").strip()
            email = input("E-posta: ").strip()
            name = input("Ad: ").strip()
            surname = input("Soyad: ").strip()

            if client.register(username, email, name, surname):
                print("\n✅ Giriş başarılı! Ana menüye yönlendiriliyorsunuz...")
                time.sleep(1)
                break

        elif choice == '2':
            username = input("Kullanıcı adı: ").strip()
            if client.login(username):
                print("\n✅ Giriş başarılı! Ana menüye yönlendiriliyorsunuz...")
                time.sleep(1)
                break

        elif choice == '3':
            print("👋 Görüşmek üzere!")
            return

    # Ana menü
    while True:
        print("\n" + "=" * 60)
        print(f"👤 {client.username} - ANA MENÜ".center(60))
        print("=" * 60)
        print("1. 🔍 Kullanıcı Ara")
        print("2. 📨 Mesaj Gönder")
        print("3. 📥 Mesajları Getir")
        print("4. 📁 Dosya Gönder")
        print("5. 🔄 Bağlantıyı Yenile")
        print("6. 🚪 Çıkış")
        print("-" * 60)

        choice = input("Seçiminiz: ").strip()

        if choice == '1':
            query = input("Aranacak kullanıcı adı: ").strip()
            if query:
                users = client.search_users(query)
                if users:
                    print("\n📋 Bulunan kullanıcılar:")
                    for user in users:
                        print(f"   ID: {user['user_id']} - @{user['username']}")
                else:
                    print("❌ Kullanıcı bulunamadı.")

        elif choice == '2':
            receiver = input("Alıcı kullanıcı adı: ").strip()
            message = input("Mesaj: ").strip()
            if receiver and message:
                client.send_message(receiver, message)
            else:
                print("❌ Alıcı ve mesaj boş olamaz!")

        elif choice == '3':
            client.get_messages()

        elif choice == '4':
            receiver = input("Alıcı kullanıcı adı: ").strip()
            file_path = input("Dosya yolu: ").strip()
            if receiver and file_path:
                if os.path.exists(file_path):
                    client.send_file(receiver, file_path)
                else:
                    print("❌ Dosya bulunamadı!")
            else:
                print("❌ Alıcı ve dosya yolu boş olamaz!")

        elif choice == '5':
            print("🔄 Bağlantı yenileniyor...")
            client.disconnect()
            time.sleep(1)
            client.connect_socket()

        elif choice == '6':
            client.disconnect()
            print("👋 Görüşmek üzere!")
            break

        else:
            print("❌ Geçersiz seçim!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Program sonlandırıldı.")
    except Exception as e:
        print(f"\n❌ Hata: {e}")