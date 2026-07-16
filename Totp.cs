using System;
using System.Security.Cryptography;

namespace AuthenticatorDesktop
{
    public static class Totp
    {
        public static string GeneratePin(string secret)
        {
            try
            {
                byte[] key = Base32.ToBytes(secret);
                if (key.Length == 0)
                    return "------";

                long timeWindow = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
                return GeneratePin(key, timeWindow);
            }
            catch
            {
                return "ERROR";
            }
        }

        public static string GeneratePin(byte[] key, long timeWindow)
        {
            byte[] timeBytes = BitConverter.GetBytes(timeWindow);
            
            // Reverse bytes for Big Endian
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(timeBytes);
            }

            // Adjust to 8 bytes representation
            byte[] buffer = new byte[8];
            Array.Copy(timeBytes, 0, buffer, 8 - timeBytes.Length, timeBytes.Length);

            using (var hmac = new HMACSHA1(key))
            {
                byte[] hash = hmac.ComputeHash(buffer);
                int offset = hash[hash.Length - 1] & 0x0F;
                
                int binaryCode = ((hash[offset] & 0x7f) << 24)
                               | ((hash[offset + 1] & 0xff) << 16)
                               | ((hash[offset + 2] & 0xff) << 8)
                               | (hash[offset + 3] & 0xff);

                int pin = binaryCode % 1000000;
                return pin.ToString("D6");
            }
        }
    }
}
