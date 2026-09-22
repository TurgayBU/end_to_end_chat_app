from config import DB_CONFIG as DB
import os
import base64
import hashlib
import mysql.connector
from mysql.connector import Error
import math

class AES256FileEncrypt:
    def __init__(self, db_config):
        """
        AES-256 Dosya Şifreleme Sınıfı
        """
        self.db_config = db_config
        self.Nb = 4
        self.Nk = 8
        self.Nr = 14
        self.BLOCK_SIZE = 16  # 16 byte = 128 bit
        self.CHUNK_SIZE = 64 * 1024  # 64KB parçalar (okuma/yazma için ideal)

        # S-Box (öncekiyle aynı)
        self.s_box = [...]  # S-Box buraya gelecek

        # Rcon
        self.rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a]

    def _get_rsa_public_key_from_db(self, user_id):
        """Veritabanından RSA public key'i çek"""
        try:
            connection = mysql.connector.connect(**self.db_config)
            cursor = connection.cursor()
            query = "SELECT public_key FROM rsa_keys WHERE user_id = %s"
            cursor.execute(query, (user_id,))
            result = cursor.fetchone()
            return result[0] if result else None
        except Error as e:
            print(f"Veritabanı hatası: {e}")
            return None
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()

    def _create_aes_key_from_rsa(self, rsa_public_key):
        """RSA public key'den AES key üret"""
        hash_obj = hashlib.sha256(rsa_public_key.encode() if isinstance(rsa_public_key, str) else rsa_public_key)
        return hash_obj.digest()

    def _key_expansion(self, key):
        """Anahtar genişletme"""
        key_words = []
        for i in range(self.Nk):
            word = [
                key[i * 4] if i * 4 < len(key) else 0,
                key[i * 4 + 1] if i * 4 + 1 < len(key) else 0,
                key[i * 4 + 2] if i * 4 + 2 < len(key) else 0,
                key[i * 4 + 3] if i * 4 + 3 < len(key) else 0
            ]
            key_words.append(word)

        total_words = self.Nb * (self.Nr + 1)
        expanded_words = key_words.copy()

        for i in range(self.Nk, total_words):
            temp = expanded_words[i - 1].copy()

            if i % self.Nk == 0:
                temp = temp[1:] + temp[:1]
                temp = [self.s_box[b] for b in temp]
                temp[0] ^= self.rcon[i // self.Nk - 1]
            elif self.Nk > 6 and i % self.Nk == 4:
                temp = [self.s_box[b] for b in temp]

            prev_word = expanded_words[i - self.Nk]
            new_word = [prev_word[j] ^ temp[j] for j in range(4)]
            expanded_words.append(new_word)

        round_keys = []
        for i in range(self.Nr + 1):
            round_key = []
            for j in range(4):
                round_key.append(expanded_words[i * 4 + j])
            round_keys.append(round_key)

        return round_keys

    def _text_to_matrix(self, text):
        """Metni matrise çevir"""
        matrix = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                idx = i + 4 * j
                if idx < len(text):
                    matrix[i][j] = ord(text[idx])
        return matrix

    def _matrix_to_text(self, matrix):
        """Matrisi metne çevir"""
        text = ""
        for j in range(4):
            for i in range(4):
                if matrix[i][j] != 0:
                    text += chr(matrix[i][j] & 0xFF)
        return text

    def _sub_bytes(self, matrix):
        result = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                result[i][j] = self.s_box[matrix[i][j]]
        return result

    def _shift_rows(self, matrix):
        result = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                result[i][j] = matrix[i][(j + i) % 4]
        return result

    def _gmul(self, a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit = a & 0x80
            a = (a << 1) & 0xFF
            if hi_bit:
                a ^= 0x1b
            b >>= 1
        return p

    def _mix_columns(self, matrix):
        result = [[0 for _ in range(4)] for _ in range(4)]
        for j in range(4):
            result[0][j] = self._gmul(0x02, matrix[0][j]) ^ self._gmul(0x03, matrix[1][j]) ^ matrix[2][j] ^ matrix[3][j]
            result[1][j] = matrix[0][j] ^ self._gmul(0x02, matrix[1][j]) ^ self._gmul(0x03, matrix[2][j]) ^ matrix[3][j]
            result[2][j] = matrix[0][j] ^ matrix[1][j] ^ self._gmul(0x02, matrix[2][j]) ^ self._gmul(0x03, matrix[3][j])
            result[3][j] = self._gmul(0x03, matrix[0][j]) ^ matrix[1][j] ^ matrix[2][j] ^ self._gmul(0x02, matrix[3][j])
        return result

    def _add_round_key(self, matrix, round_key):
        result = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                result[i][j] = matrix[i][j] ^ round_key[i][j]
        return result

    def _encrypt_block(self, block, round_keys):
        """16 bytelık bloğu şifrele"""
        state = self._text_to_matrix(block)
        state = self._add_round_key(state, round_keys[0])

        for round_num in range(1, self.Nr):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, round_keys[round_num])

        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, round_keys[self.Nr])

        return self._matrix_to_text(state)

    def _add_padding(self, data):
        """PKCS#7 padding ekle"""
        pad_len = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        return data + bytes([pad_len] * pad_len)

    def _remove_padding(self, data):
        """PKCS#7 padding kaldır"""
        if not data:
            return data
        pad_len = data[-1]
        if pad_len <= self.BLOCK_SIZE:
            return data[:-pad_len]
        return data

    def encrypt_file(self, user_id, input_file_path, output_file_path=None):
        """
        Dosyayı şifrele ve şifrelenmiş halini kaydet

        Args:
            user_id: Kullanıcı ID
            input_file_path: Şifrelenecek dosya yolu
            output_file_path: Şifrelenmiş dosya yolu (None ise input_file_path + .enc)

        Returns:
            output_file_path: Şifrelenmiş dosya yolu
        """
        # Çıktı dosya yolunu belirle
        if not output_file_path:
            output_file_path = input_file_path + ".enc"

        # Veritabanından RSA public key'i al
        rsa_public_key = self._get_rsa_public_key_from_db(user_id)
        if not rsa_public_key:
            raise ValueError(f"User ID {user_id} için RSA public key bulunamadı")

        # RSA public key'den AES key üret
        aes_key = self._create_aes_key_from_rsa(rsa_public_key)

        # Round key'leri oluştur
        round_keys = self._key_expansion(aes_key)

        # Dosyayı oku ve şifrele
        file_size = os.path.getsize(input_file_path)
        total_chunks = math.ceil(file_size / self.CHUNK_SIZE)

        with open(input_file_path, 'rb') as infile, open(output_file_path, 'wb') as outfile:
            # Dosya başlığı: Şifreleme bilgileri
            header = {
                'user_id': user_id,
                'original_size': file_size,
                'chunk_size': self.CHUNK_SIZE,
                'block_size': self.BLOCK_SIZE
            }
            header_str = str(header).encode()
            header_len = len(header_str)
            outfile.write(header_len.to_bytes(4, 'big'))
            outfile.write(header_str)

            chunk_count = 0
            while True:
                chunk = infile.read(self.CHUNK_SIZE)
                if not chunk:
                    break

                # Chunk'a padding ekle
                padded_chunk = self._add_padding(chunk)

                # Blok blok şifrele
                encrypted_chunk = b''
                for i in range(0, len(padded_chunk), self.BLOCK_SIZE):
                    block = padded_chunk[i:i + self.BLOCK_SIZE].decode('latin-1')
                    encrypted_block = self._encrypt_block(block, round_keys)
                    encrypted_chunk += encrypted_block.encode('latin-1')

                # Şifrelenmiş chunk'ı yaz
                outfile.write(len(encrypted_chunk).to_bytes(4, 'big'))
                outfile.write(encrypted_chunk)

                chunk_count += 1
                print(f"İşlenen: {chunk_count}/{total_chunks} chunks", end='\r')

        print(f"\nDosya şifrelendi: {output_file_path}")
        return output_file_path

    def encrypt_file_to_base64(self, user_id, input_file_path):
        """
        Dosyayı şifrele ve base64 olarak döndür
        (Küçük dosyalar için - API ile gönderme)
        """
        # Veritabanından RSA public key'i al
        rsa_public_key = self._get_rsa_public_key_from_db(user_id)
        if not rsa_public_key:
            raise ValueError(f"User ID {user_id} için RSA public key bulunamadı")

        # AES key üret
        aes_key = self._create_aes_key_from_rsa(rsa_public_key)
        round_keys = self._key_expansion(aes_key)

        # Dosyayı oku
        with open(input_file_path, 'rb') as f:
            file_data = f.read()

        # Padding ekle
        padded_data = self._add_padding(file_data)

        # Blok blok şifrele
        encrypted_data = b''
        for i in range(0, len(padded_data), self.BLOCK_SIZE):
            block = padded_data[i:i + self.BLOCK_SIZE].decode('latin-1')
            encrypted_block = self._encrypt_block(block, round_keys)
            encrypted_data += encrypted_block.encode('latin-1')

        # Base64'e çevir
        return base64.b64encode(encrypted_data).decode()

# 1. Büyük dosyayı şifrele (parçalara bölerek)
encryptor = AES256FileEncrypt(DB)
encryptor.encrypt_file(
    user_id=123,
    input_file_path="belge.pdf",
    output_file_path="belge.pdf.enc"
)

# 2. Şifrelenmiş dosyayı çöz (parçaları birleştirerek)
#decryptor = AES256FileDecrypt(DB)
#decryptor.decrypt_file(
#     user_id=123,
#     encrypted_file_path="belge.pdf.enc",
#     output_file_path="belge_cozulen.pdf"
# )

# 3. Küçük dosya için base64 (API ile gönderme)
encrypted_base64 = encryptor.encrypt_file_to_base64(123, "kucuk_dosya.txt")

# 4. Base64'ten çöz
# decryptor.decrypt_base64_to_file(123, encrypted_base64, "kucuk_dosya_cozulen.txt")