using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace GhostAuthenticatorSetup
{
    public static class Crypto
    {
        private const int KeySize = 256; // AES 256
        private const int BlockSize = 128; // AES Block Size
        private const int PBKDF2Iterations = 600000; // OWASP US-Standard iterations for SHA256

        // Derive key using PBKDF2-HMAC-SHA256
        public static byte[] DeriveKey(string password, byte[] salt)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, PBKDF2Iterations, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(KeySize / 8);
            }
        }

        // Generate cryptographically secure random bytes (for salt and IV)
        public static byte[] GenerateRandomBytes(int size)
        {
            byte[] bytes = new byte[size];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return bytes;
        }

        // Encrypt plain text bytes using AES-256-CBC
        public static byte[] Encrypt(byte[] plainBytes, byte[] key)
        {
            byte[] iv = GenerateRandomBytes(BlockSize / 8);

            using (var aes = Aes.Create())
            {
                aes.KeySize = KeySize;
                aes.BlockSize = BlockSize;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;

                using (var ms = new MemoryStream())
                {
                    // Write IV at the beginning of stream
                    ms.Write(iv, 0, iv.Length);

                    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(plainBytes, 0, plainBytes.Length);
                        cs.FlushFinalBlock();
                    }

                    return ms.ToArray();
                }
            }
        }

        // Decrypt cipher bytes using AES-256-CBC
        public static byte[] Decrypt(byte[] cipherBytes, byte[] key)
        {
            int ivLength = BlockSize / 8;
            byte[] iv = new byte[ivLength];
            Array.Copy(cipherBytes, 0, iv, 0, ivLength);

            using (var aes = Aes.Create())
            {
                aes.KeySize = KeySize;
                aes.BlockSize = BlockSize;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;

                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, ivLength, cipherBytes.Length - ivLength);
                        cs.FlushFinalBlock();
                    }

                    return ms.ToArray();
                }
            }
        }
    }
}
