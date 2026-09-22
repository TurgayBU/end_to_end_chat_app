from config import DB_CONFIG as DB
import random
import math
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
class key:
    def __init__(self, DB):
        self.db = DB
        self.public_key = None
        self.private_key = None
        self.n = None

    def Prime_Number(self):
        lower_bound = 1 << 1023
        upper_bound = (1 << 1024) - 1
        numbers = []
        k = 0
        while k < 2:
            candidate = random.getrandbits(1024)
            candidate = candidate | (1 << 1023)
            candidate = candidate | 1
            if candidate <= upper_bound and candidate >= lower_bound:
                if self.Is_Prime_Number(candidate):
                    if candidate not in numbers:
                        numbers.append(candidate)
                        k = k + 1
        if numbers[0] == numbers[1]:
            return self.Prime_Number()
        return self.Multiplication(numbers)

    def Is_Prime_Number(self, n, iteration=40):
        if n < 2:
            return False
        if n in (2, 3):
            return True
        if n % 2 == 0:
            return False

        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        for _ in range(iteration):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def Multiplication(self, numbers):
        self.n = numbers[0] * numbers[1]
        return self.Phi_Calculation(numbers)

    def Phi_Calculation(self, numbers):
        Phi = (numbers[0] - 1) * (numbers[1] - 1)
        return self.Public_Key(Phi)

    def GCD(self, a, b):
        return math.gcd(a, b) == 1

    def Public_Key(self, Phi):
        while True:
            candidate = random.randint(2, Phi - 1)
            if self.GCD(candidate, Phi):
                self.public_key = candidate
                return self.Private_Key(candidate, Phi)

    def Private_Key(self, public_key, phi):
        self.private_key = pow(public_key, -1, phi)
        return self.Save_Data(public_key, self.private_key)

    def Save_Data(self, public_key, private_key):
        key_data = {
            'public_key': public_key,
            'private_key': private_key,
            'modulus': self.n
        }

        if self.db:
            try:
                cursor = self.db.cursor()
                cursor.execute("""
                    INSERT INTO rsa_keys (public_key, private_key, modulus, created_at) 
                    VALUES (?, ?, ?, datetime('now'))
                """, (str(public_key), str(private_key), str(self.n)))
                self.db.commit()
            except:
                pass
        return key_data