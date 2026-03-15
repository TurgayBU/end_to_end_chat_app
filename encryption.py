from config import DB_CONFIG as DB
import os
import base64
import hashlib
import mysql.connector
from mysql.connector import Error
class AES256Encrypt:
    def __init__(self, db_config):
        """
        AES-256 Encrypt sınıfı
        db_config: Veritabanı bağlantı bilgileri
        """
        self.db_config = db_config
        self.Nb = 4
        self.Nk = 8
        self.Nr = 14

        # S-Box
        self.s_box = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]

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

            if result:
                return result[0]  # public_key
            return None

        except Error as e:
            print(f"Veritabanı hatası: {e}")
            return None
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()

    def _create_aes_key_from_rsa(self, rsa_public_key):
        """RSA public key'den AES key üret"""
        # RSA public key'i hash'le
        hash_obj = hashlib.sha256(rsa_public_key.encode() if isinstance(rsa_public_key, str) else rsa_public_key)
        return hash_obj.digest()  # 32 byte

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
        """Tek blok şifreleme"""
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

    def encrypt(self, user_id, plain_text):
        """
        Kullanıcının RSA public key'ini kullanarak metni şifrele
        """
        # Veritabanından RSA public key'i al
        rsa_public_key = self._get_rsa_public_key_from_db(user_id)
        if not rsa_public_key:
            raise ValueError(f"User ID {user_id} için RSA public key bulunamadı")

        # RSA public key'den AES key üret
        aes_key = self._create_aes_key_from_rsa(rsa_public_key)

        # Round key'leri oluştur
        round_keys = self._key_expansion(aes_key)

        # Padding ekle
        text = plain_text
        pad_len = 16 - (len(text) % 16)
        text += chr(pad_len) * pad_len

        # Blok blok şifrele
        encrypted = ""
        for i in range(0, len(text), 16):
            block = text[i:i + 16]
            encrypted += self._encrypt_block(block, round_keys)

        # Base64 encode et
        return base64.b64encode(encrypted.encode()).decode()
