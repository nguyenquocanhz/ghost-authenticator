using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AuthenticatorDesktop
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
        // Encrypted Backup (.ghostbak) Container Support
        private static readonly byte[] GhostBakHeader = Encoding.UTF8.GetBytes("GHOSTBAK_V1");

        public static byte[] EncryptGhostBak(string plainTextJson, string password)
        {
            byte[] salt = GenerateRandomBytes(16);
            byte[] key = DeriveKey(password, salt);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainTextJson);
            byte[] cipherWithIv = Encrypt(plainBytes, key);

            using (var ms = new MemoryStream())
            {
                ms.Write(GhostBakHeader, 0, GhostBakHeader.Length);
                ms.Write(salt, 0, salt.Length);
                ms.Write(cipherWithIv, 0, cipherWithIv.Length);
                return ms.ToArray();
            }
        }

        public static string DecryptGhostBak(byte[] fileBytes, string password)
        {
            if (fileBytes.Length < GhostBakHeader.Length + 16 + 16)
                throw new InvalidDataException("Tệp tin sao lưu .ghostbak không hợp lệ hoặc bị hư hỏng.");

            for (int i = 0; i < GhostBakHeader.Length; i++)
            {
                if (fileBytes[i] != GhostBakHeader[i])
                    throw new InvalidDataException("Tệp tin không đúng định dạng sao lưu .ghostbak.");
            }

            int saltOffset = GhostBakHeader.Length;
            byte[] salt = new byte[16];
            Array.Copy(fileBytes, saltOffset, salt, 0, 16);

            byte[] key = DeriveKey(password, salt);

            int cipherOffset = saltOffset + 16;
            byte[] cipherWithIv = new byte[fileBytes.Length - cipherOffset];
            Array.Copy(fileBytes, cipherOffset, cipherWithIv, 0, cipherWithIv.Length);

            byte[] decryptedBytes = Decrypt(cipherWithIv, key);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}
