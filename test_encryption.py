import unittest
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from vault import encrypt_password, decrypt_password, generate_random_password


class TestEncryption(unittest.TestCase):
    def test_encrypt_decrypt_password(self):
        # Use a sample key and password for testing
        key = get_random_bytes(32)
        password = "test_password"

        # Test the encryption and decryption functions
        encrypted_password = encrypt_password(password, key)
        decrypted_password = decrypt_password(encrypted_password, key).decode("utf-8")

        # Assert that the decrypted password is equal to the original password
        self.assertEqual(password, decrypted_password)

    def test_generate_random_password(self):
        # Test the random password generation function
        length = 12
        random_password = generate_random_password(length)

        # Assert that the generated password has the correct length
        self.assertEqual(len(random_password), length)

        # Assert that the generated password is different on each call
        another_random_password = generate_random_password(length)
        self.assertNotEqual(random_password, another_random_password)


if __name__ == "__main__":
    unittest.main()
