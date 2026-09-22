from config import DB_CONFIG as DB
import os
import base64
import hashlib
import mysql.connector
from mysql.connector import Error
import math

class AES256FileDecrypt:
    def __init__(self, db_config):
        """
        AES-256 Dosya Şifre Çözme Sınıfı
        """
        self.db_config = db_config
        self.Nb = 4
        self.Nk = 8
        self.Nr = 14
        self.BLOCK_SIZE = 16

        # S-Box ve ters S-Box
        self.s_box = [...]  # S-Box buraya gelecek

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
            return result[0] if result else None
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
        """16 bytelık bloğun şifresini çöz"""
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

    def _remove_padding(self, data):
        """PKCS#7 padding kaldır"""
        if not data:
            return data
        pad_len = data[-1]
        if pad_len <= self.BLOCK_SIZE:
            return data[:-pad_len]
        return data

    def decrypt_file(self, user_id, encrypted_file_path, output_file_path=None):
        """
        Şifrelenmiş dosyayı çöz

        Args:
            user_id: Kullanıcı ID
            encrypted_file_path: Şifrelenmiş dosya yolu
            output_file_path: Çözülmüş dosya yolu (None ise .enc uzantısı kaldırılır)

        Returns:
            output_file_path: Çözülmüş dosya yolu
        """
        # Çıktı dosya yolunu belirle
        if not output_file_path:
            if encrypted_file_path.endswith('.enc'):
                output_file_path = encrypted_file_path[:-4]
            else:
                output_file_path = encrypted_file_path + ".dec"

        # Veritabanından RSA private key'i al
        rsa_private_key = self._get_rsa_private_key_from_db(user_id)
        if not rsa_private_key:
            raise ValueError(f"User ID {user_id} için RSA private key bulunamadı")

        # RSA private key'den AES key üret
        aes_key = self._create_aes_key_from_rsa(rsa_private_key)

        # Round key'leri oluştur
        round_keys = self._key_expansion(aes_key)

        with open(encrypted_file_path, 'rb') as infile, open(output_file_path, 'wb') as outfile:
            # Header'ı oku
            header_len = int.from_bytes(infile.read(4), 'big')
            header_str = infile.read(header_len).decode()
            header = eval(header_str)  # Güvenlik için ast.literal_eval kullanın

            chunk_count = 0
            while True:
                # Chunk boyutunu oku
                chunk_size_bytes = infile.read(4)
                if not chunk_size_bytes:
                    break

                chunk_size = int.from_bytes(chunk_size_bytes, 'big')
                encrypted_chunk = infile.read(chunk_size)

                # Şifreyi çöz
                decrypted_chunk = b''
                for i in range(0, len(encrypted_chunk), self.BLOCK_SIZE):
                    block = encrypted_chunk[i:i + self.BLOCK_SIZE].decode('latin-1')
                    decrypted_block = self._decrypt_block(block, round_keys)
                    decrypted_chunk += decrypted_block.encode('latin-1')

                # Padding'i kaldır
                unpadded_chunk = self._remove_padding(decrypted_chunk)

                # Dosyaya yaz
                outfile.write(unpadded_chunk)

                chunk_count += 1

        print(f"Dosya çözüldü: {output_file_path}")
        return output_file_path

    def decrypt_base64_to_file(self, user_id, base64_data, output_file_path):
        """
        Base64 formatındaki şifrelenmiş veriyi çöz ve dosyaya kaydet
        """
        # Veritabanından RSA private key'i al
        rsa_private_key = self._get_rsa_private_key_from_db(user_id)
        if not rsa_private_key:
            raise ValueError(f"User ID {user_id} için RSA private key bulunamadı")

        # AES key üret
        aes_key = self._create_aes_key_from_rsa(rsa_private_key)
        round_keys = self._key_expansion(aes_key)

        # Base64'ü çöz
        encrypted_data = base64.b64decode(base64_data)

        # Şifreyi çöz
        decrypted_data = b''
        for i in range(0, len(encrypted_data), self.BLOCK_SIZE):
            block = encrypted_data[i:i + self.BLOCK_SIZE].decode('latin-1')
            decrypted_block = self._decrypt_block(block, round_keys)
            decrypted_data += decrypted_block.encode('latin-1')

        # Padding'i kaldır
        unpadded_data = self._remove_padding(decrypted_data)

        # Dosyaya yaz
        with open(output_file_path, 'wb') as f:
            f.write(unpadded_data)

        return output_file_path