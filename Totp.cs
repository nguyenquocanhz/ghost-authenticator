using System;
using System.Security.Cryptography;

namespace AuthenticatorDesktop
{
    public static class Totp
    {
        public const string DefaultAlgorithm = "SHA1";
        public const int DefaultDigits = 6;
        public const int DefaultPeriod = 30;

        public static bool IsSupportedAlgorithm(string algorithm)
        {
            return NormalizeAlgorithm(algorithm) != null;
        }

        public static string? NormalizeAlgorithm(string? algorithm)
        {
            switch ((algorithm ?? DefaultAlgorithm).Trim().ToUpperInvariant())
            {
                case "SHA1": return "SHA1";
                case "SHA256": return "SHA256";
                case "SHA512": return "SHA512";
                default: return null;
            }
        }

        public static string GeneratePin(string secret)
        {
            return GeneratePin(secret, DefaultAlgorithm, DefaultDigits, DefaultPeriod);
        }

        public static string GeneratePin(string secret, string algorithm, int digits, int period)
        {
            try
            {
                byte[] key = Base32.ToBytes(secret);
                if (key.Length == 0)
                    return "------";

                if (period <= 0) period = DefaultPeriod;
                long timeWindow = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / period;
                return GeneratePin(key, timeWindow, algorithm, digits);
            }
            catch
            {
                return "ERROR";
            }
        }

        public static string GeneratePin(byte[] key, long timeWindow)
        {
            return GeneratePin(key, timeWindow, DefaultAlgorithm, DefaultDigits);
        }

        // RFC 6238 TOTP with the algorithm, digit count and period from the otpauth URI.
        public static string GeneratePin(byte[] key, long timeWindow, string algorithm, int digits)
        {
            if (digits < 6 || digits > 8) digits = DefaultDigits;

            byte[] timeBytes = BitConverter.GetBytes(timeWindow);

            // Reverse bytes for Big Endian
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(timeBytes);
            }

            // Adjust to 8 bytes representation
            byte[] buffer = new byte[8];
            Array.Copy(timeBytes, 0, buffer, 8 - timeBytes.Length, timeBytes.Length);

            using (HMAC hmac = CreateHmac(algorithm, key))
            {
                byte[] hash = hmac.ComputeHash(buffer);
                int offset = hash[hash.Length - 1] & 0x0F;

                int binaryCode = ((hash[offset] & 0x7f) << 24)
                               | ((hash[offset + 1] & 0xff) << 16)
                               | ((hash[offset + 2] & 0xff) << 8)
                               | (hash[offset + 3] & 0xff);

                int modulus = (int)Math.Pow(10, digits);
                int pin = binaryCode % modulus;
                return pin.ToString("D" + digits);
            }
        }

        private static HMAC CreateHmac(string algorithm, byte[] key)
        {
            switch (NormalizeAlgorithm(algorithm))
            {
                case "SHA256": return new HMACSHA256(key);
                case "SHA512": return new HMACSHA512(key);
                default: return new HMACSHA1(key);
            }
        }
    }
}
