using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AuthenticatorDesktop
{
    public static class Crypto
    {
        public const int SaltSize = 16;
        private const int KeySize = 256; // AES 256
        private const int BlockSize = 128; // AES Block Size (legacy CBC format)
        private const int PBKDF2Iterations = 600000; // OWASP US-Standard iterations for SHA256

        // Current storage format: "GAV2" | 12-byte nonce | 16-byte tag | ciphertext (AES-256-GCM).
        // AES-GCM is authenticated, so a wrong key or any tampering is detected instead of
        // silently producing garbage, as recommended by Microsoft SDL cryptography guidance.
        private static readonly byte[] FormatV2Magic = Encoding.ASCII.GetBytes("GAV2");
        private const int NonceSize = 12;
        private const int TagSize = 16;

        // Derive key using PBKDF2-HMAC-SHA256
        public static byte[] DeriveKey(string password, byte[] salt)
        {
            return Rfc2898DeriveBytes.Pbkdf2(password, salt, PBKDF2Iterations, HashAlgorithmName.SHA256, KeySize / 8);
        }

        // Generate cryptographically secure random bytes (for salt and nonce)
        public static byte[] GenerateRandomBytes(int size)
        {
            return RandomNumberGenerator.GetBytes(size);
        }

        // True when data was written by the current (AES-GCM) format.
        public static bool IsCurrentFormat(byte[] data)
        {
            return data.Length >= FormatV2Magic.Length + NonceSize + TagSize
                && data.AsSpan(0, FormatV2Magic.Length).SequenceEqual(FormatV2Magic);
        }

        // Encrypt using AES-256-GCM
        public static byte[] Encrypt(byte[] plainBytes, byte[] key)
        {
            byte[] nonce = GenerateRandomBytes(NonceSize);
            byte[] tag = new byte[TagSize];
            byte[] cipher = new byte[plainBytes.Length];

            using (var aes = new AesGcm(key, TagSize))
            {
                aes.Encrypt(nonce, plainBytes, cipher, tag);
            }

            byte[] result = new byte[FormatV2Magic.Length + NonceSize + TagSize + cipher.Length];
            int offset = 0;
            Buffer.BlockCopy(FormatV2Magic, 0, result, offset, FormatV2Magic.Length); offset += FormatV2Magic.Length;
            Buffer.BlockCopy(nonce, 0, result, offset, NonceSize); offset += NonceSize;
            Buffer.BlockCopy(tag, 0, result, offset, TagSize); offset += TagSize;
            Buffer.BlockCopy(cipher, 0, result, offset, cipher.Length);
            return result;
        }

        // Decrypt data in either the current AES-GCM format or the legacy AES-CBC format.
        // Throws CryptographicException when the key is wrong or the data was modified.
        public static byte[] Decrypt(byte[] data, byte[] key)
        {
            if (IsCurrentFormat(data))
            {
                int offset = FormatV2Magic.Length;
                var nonce = data.AsSpan(offset, NonceSize); offset += NonceSize;
                var tag = data.AsSpan(offset, TagSize); offset += TagSize;
                var cipher = data.AsSpan(offset);
                byte[] plain = new byte[cipher.Length];

                using (var aes = new AesGcm(key, TagSize))
                {
                    aes.Decrypt(nonce, cipher, tag, plain);
                }
                return plain;
            }

            return DecryptLegacyCbc(data, key);
        }

        // Files written by version 1.0.0: 16-byte IV followed by AES-256-CBC ciphertext.
        private static byte[] DecryptLegacyCbc(byte[] cipherBytes, byte[] key)
        {
            int ivLength = BlockSize / 8;
            if (cipherBytes.Length <= ivLength)
                throw new CryptographicException("Encrypted data is invalid.");

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
        // V1 = AES-CBC payload (read only), V2 = AES-GCM payload.
        private static readonly byte[] GhostBakHeaderV1 = Encoding.UTF8.GetBytes("GHOSTBAK_V1");
        private static readonly byte[] GhostBakHeaderV2 = Encoding.UTF8.GetBytes("GHOSTBAK_V2");

        public static byte[] EncryptGhostBak(string plainTextJson, string password)
        {
            byte[] salt = GenerateRandomBytes(SaltSize);
            byte[] key = DeriveKey(password, salt);
            try
            {
                byte[] payload = Encrypt(Encoding.UTF8.GetBytes(plainTextJson), key);

                using (var ms = new MemoryStream())
                {
                    ms.Write(GhostBakHeaderV2, 0, GhostBakHeaderV2.Length);
                    ms.Write(salt, 0, salt.Length);
                    ms.Write(payload, 0, payload.Length);
                    return ms.ToArray();
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        public static string DecryptGhostBak(byte[] fileBytes, string password)
        {
            int headerLength = GhostBakHeaderV2.Length;
            if (fileBytes.Length < headerLength + SaltSize + 16)
                throw new InvalidDataException("The .ghostbak backup is invalid or damaged.");

            var header = fileBytes.AsSpan(0, headerLength);
            if (!header.SequenceEqual(GhostBakHeaderV2) && !header.SequenceEqual(GhostBakHeaderV1))
                throw new InvalidDataException("The file is not a .ghostbak backup.");

            byte[] salt = fileBytes.AsSpan(headerLength, SaltSize).ToArray();
            byte[] payload = fileBytes.AsSpan(headerLength + SaltSize).ToArray();

            byte[] key = DeriveKey(password, salt);
            try
            {
                return Encoding.UTF8.GetString(Decrypt(payload, key));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
    }
}
