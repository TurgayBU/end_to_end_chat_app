from config import DB_CONFIG as DB
import os
import base64
import hashlib
import mysql.connector
from mysql.connector import Error
class AES256Decrypt:
    def __init__(self, db_config):
        """
        AES-256 Decrypt sınıfı
        db_config: Veritabanı bağlantı bilgileri
        """
        self.db_config = db_config
        self.Nb = 4
        self.Nk = 8
        self.Nr = 14

        # S-Box ve ters S-Box
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

        self.inv_s_box = [0] * 256
        for i in range(256):
            self.inv_s_box[self.s_box[i]] = i

        self.rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a]

    def _get_rsa_private_key_from_db(self, user_id):
        """Veritabanından RSA private key'i çek"""
        try:
            connection = mysql.connector.connect(**self.db_config)
            cursor = connection.cursor()

            query = "SELECT private_key FROM rsa_keys WHERE user_id = %s"
            cursor.execute(query, (user_id,))
            result = cursor.fetchone()

            if result:
                return result[0]  # private_key
            return None

        except Error as e:
            print(f"Veritabanı hatası: {e}")
            return None
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()

    def _create_aes_key_from_rsa(self, rsa_private_key):
        """RSA private key'den AES key üret"""
        hash_obj = hashlib.sha256(rsa_private_key.encode() if isinstance(rsa_private_key, str) else rsa_private_key)
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
        matrix = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                idx = i + 4 * j
                if idx < len(text):
                    matrix[i][j] = ord(text[idx])
        return matrix

    def _matrix_to_text(self, matrix):
        text = ""
        for j in range(4):
            for i in range(4):
                if matrix[i][j] != 0:
                    text += chr(matrix[i][j] & 0xFF)
        return text

    def _inv_sub_bytes(self, matrix):
        result = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                result[i][j] = self.inv_s_box[matrix[i][j]]
        return result

    def _inv_shift_rows(self, matrix):
        result = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                result[i][j] = matrix[i][(j - i) % 4]
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

    def _inv_mix_columns(self, matrix):
        result = [[0 for _ in range(4)] for _ in range(4)]
        for j in range(4):
            result[0][j] = self._gmul(0x0e, matrix[0][j]) ^ self._gmul(0x0b, matrix[1][j]) ^ self._gmul(0x0d, matrix[2][
                j]) ^ self._gmul(0x09, matrix[3][j])
            result[1][j] = self._gmul(0x09, matrix[0][j]) ^ self._gmul(0x0e, matrix[1][j]) ^ self._gmul(0x0b, matrix[2][
                j]) ^ self._gmul(0x0d, matrix[3][j])
            result[2][j] = self._gmul(0x0d, matrix[0][j]) ^ self._gmul(0x09, matrix[1][j]) ^ self._gmul(0x0e, matrix[2][
                j]) ^ self._gmul(0x0b, matrix[3][j])
            result[3][j] = self._gmul(0x0b, matrix[0][j]) ^ self._gmul(0x0d, matrix[1][j]) ^ self._gmul(0x09, matrix[2][
                j]) ^ self._gmul(0x0e, matrix[3][j])
        return result

    def _add_round_key(self, matrix, round_key):
        result = [[0 for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                result[i][j] = matrix[i][j] ^ round_key[i][j]
        return result

    def _decrypt_block(self, block, round_keys):
        """Tek blok şifre çözme"""
        state = self._text_to_matrix(block)

        state = self._add_round_key(state, round_keys[self.Nr])

        for round_num in range(self.Nr - 1, 0, -1):
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            state = self._add_round_key(state, round_keys[round_num])
            state = self._inv_mix_columns(state)

        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        state = self._add_round_key(state, round_keys[0])

        return self._matrix_to_text(state)

    def decrypt(self, user_id, encrypted_base64):
        """
        Kullanıcının RSA private key'ini kullanarak şifreli metni çöz
        """
        # Veritabanından RSA private key'i al
        rsa_private_key = self._get_rsa_private_key_from_db(user_id)
        if not rsa_private_key:
            raise ValueError(f"User ID {user_id} için RSA private key bulunamadı")

        # RSA private key'den AES key üret
        aes_key = self._create_aes_key_from_rsa(rsa_private_key)

        # Round key'leri oluştur
        round_keys = self._key_expansion(aes_key)

        # Base64 decode et
        encrypted_text = base64.b64decode(encrypted_base64).decode()

        # Blok blok çöz
        decrypted = ""
        for i in range(0, len(encrypted_text), 16):
            block = encrypted_text[i:i + 16]
            decrypted += self._decrypt_block(block, round_keys)

        # Padding'i kaldır
        if decrypted:
            pad_len = ord(decrypted[-1])
            if pad_len <= 16:
                decrypted = decrypted[:-pad_len]

        return decrypted