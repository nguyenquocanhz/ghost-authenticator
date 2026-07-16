using System;
using System.Text;

namespace AuthenticatorDesktop
{
    public static class Base32
    {
        public static byte[] ToBytes(string input)
        {
            if (string.IsNullOrEmpty(input))
                return Array.Empty<byte>();

            input = input.Trim().Replace(" ", "").Replace("-", "").ToUpperInvariant();
            
            // Remove padding
            input = input.TrimEnd('=');
            
            if (input.Length == 0)
                return Array.Empty<byte>();

            int byteCount = input.Length * 5 / 8;
            byte[] returnArray = new byte[byteCount];

            byte curByte = 0, bitsRemaining = 8;
            int arrayIndex = 0;

            foreach (char c in input)
            {
                int value = CharToValue(c);
                if (value == -1)
                    throw new ArgumentException("Invalid Base32 character: " + c);

                if (bitsRemaining > 5)
                {
                    int mask = value << (bitsRemaining - 5);
                    curByte = (byte)(curByte | mask);
                    bitsRemaining -= 5;
                }
                else
                {
                    int mask = value >> (5 - bitsRemaining);
                    curByte = (byte)(curByte | mask);
                    returnArray[arrayIndex++] = curByte;
                    
                    curByte = (byte)(value << (3 + bitsRemaining));
                    bitsRemaining = (byte)(8 - (5 - bitsRemaining));
                }
            }

            // Return the decoded bytes
            return returnArray;
        }

        private static int CharToValue(char c)
        {
            int value = c;

            // 65-90 == A-Z
            if (value < 91 && value > 64)
                return value - 65;
            
            // 50-55 == 2-7
            if (value < 56 && value > 49)
                return value - 24;

            return -1;
        }
    }
}
