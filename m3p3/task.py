import hashlib, math


class CryptoUtils:
    def jacobi(a, m):
        j = 1
        a %= m
        while a:
            t = 0
            while not a & 1:
                a = a >> 1
                t += 1
            if t & 1 and m % 8 in (3, 5):
                j = -j
            if a % 4 == m % 4 == 3:
                j = -j
            a, m = m % a, a
        return j if m == 1 else 0

    def encode_as_byte_array(n):
        # använd på email innan hashning
        return n.encode("utf-8")

    def hash(data):
        # använd på email innan hashning
        return hashlib.sha1(data).digest()

    def hash_until_jacobi_one(email_string, m):
        # data ska vara email somen string av email
        hash_email = CryptoUtils.hash(CryptoUtils.encode_as_byte_array(email_string))
        jacobi_value = CryptoUtils.jacobi(
            int.from_bytes(hash_email, byteorder="big"), m
        )
        while jacobi_value != 1:
            hash_email = CryptoUtils.hash(hash_email)
            jacobi_value = CryptoUtils.jacobi(
                int.from_bytes(hash_email, byteorder="big"), m
            )
        return hash_email


class PKG:

    def __init__(self, p, q):
        self.p = p
        self.q = q

    def generate_private_key(self, email):
        m = self.p * self.q
        a = int.from_bytes(CryptoUtils.hash_until_jacobi_one(email, m))
        exp = (m + 5 - (self.p + self.q)) // 8
        return pow(a, exp, m)

    def format_private_key(self, private_key):
        hexed_key = hex(int(private_key))[2:]
        while len(hexed_key) < 64:
            hexed_key = "0" + hexed_key
        return hexed_key


class IBEDecryptor:
    def __init__(self, pkg):
        self.pkg = pkg

    def decrypt(self, ciphertext, private_key):
        # ciphertext är en lista av hexade strängar
        m = self.pkg.p * self.pkg.q
        decrypted_message = ""
        for s in ciphertext:
            if CryptoUtils.jacobi(int(s, 16) + 2 * private_key, m) == 1:
                decrypted_message += "1"
            else:
                decrypted_message += "0"
        return decrypted_message

    def format_decrypted_message(self, decrypted_message):
        message = int(decrypted_message, 2)
        """hexed_msg = hex(int(message))[2:]
        while len(hexed_msg) < 64:
            hexed_msg = "0" + hexed_msg
        return hexed_msg"""
        return message


def main():
    p = 0x9240633D434A8B71A013B5B00513323F
    q = 0xF870CFCD47E6D5A0598FC1EB7E999D1B
    pkg = PKG(p, q)
    decryptor = IBEDecryptor(pkg)
    with open("cipher.txt", "r") as f:
        ciphertext = [line.strip() for line in f.readlines()]

    email = "walterwhite@crypto.sec"
    while not email:
        email = input("Enter your email: ").strip()

    private_key = pkg.generate_private_key(email)
    print(f"Your private key: {pkg.format_private_key(private_key)}")
    decrypted_message = decryptor.decrypt(ciphertext, private_key)
    print(f"Decrypted message: {decryptor.format_decrypted_message(decrypted_message)}")


if __name__ == "__main__":
    main()
