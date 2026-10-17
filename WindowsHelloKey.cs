using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;

namespace AuthenticatorDesktop
{
    // Windows Hello unlock backed by a KeyCredential (Microsoft Passport key in the TPM).
    //
    // The vault key is wrapped with a key derived from a Windows Hello signature over a
    // random challenge. Unwrapping needs a fresh Hello verification, so other programs
    // running as the same user cannot read the vault key from disk (unlike plain DPAPI).
    public static class WindowsHelloKey
    {
        private const string CredentialName = "GhostAuthenticator.VaultKey";
        private const int ChallengeSize = 32;
        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("GHW1");

        public static async Task<bool> IsSupportedAsync()
        {
            try
            {
                return await KeyCredentialManager.IsSupportedAsync();
            }
            catch
            {
                return false;
            }
        }

        // Creates (or replaces) the Hello credential and returns the wrapped vault key blob,
        // or null when the user cancelled or Hello failed.
        public static async Task<byte[]?> WrapAsync(byte[] vaultKey)
        {
            var created = await KeyCredentialManager.RequestCreateAsync(CredentialName, KeyCredentialCreationOption.ReplaceExisting);
            if (created.Status != KeyCredentialStatus.Success)
                return null;

            byte[] challenge = Crypto.GenerateRandomBytes(ChallengeSize);
            byte[]? wrappingKey = await DeriveWrappingKeyAsync(created.Credential, challenge);
            if (wrappingKey == null)
                return null;

            try
            {
                byte[] wrapped = Crypto.Encrypt(vaultKey, wrappingKey);
                byte[] blob = new byte[Magic.Length + ChallengeSize + wrapped.Length];
                Buffer.BlockCopy(Magic, 0, blob, 0, Magic.Length);
                Buffer.BlockCopy(challenge, 0, blob, Magic.Length, ChallengeSize);
                Buffer.BlockCopy(wrapped, 0, blob, Magic.Length + ChallengeSize, wrapped.Length);
                return blob;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(wrappingKey);
            }
        }

        // Asks Windows Hello to verify the user and returns the vault key, or null when the
        // user cancelled, Hello is unavailable, or the blob does not match this credential.
        public static async Task<byte[]?> UnwrapAsync(byte[] blob)
        {
            if (blob.Length <= Magic.Length + ChallengeSize || !blob.AsSpan(0, Magic.Length).SequenceEqual(Magic))
                return null;

            var opened = await KeyCredentialManager.OpenAsync(CredentialName);
            if (opened.Status != KeyCredentialStatus.Success)
                return null;

            byte[] challenge = blob.AsSpan(Magic.Length, ChallengeSize).ToArray();
            byte[] wrapped = blob.AsSpan(Magic.Length + ChallengeSize).ToArray();

            byte[]? wrappingKey = await DeriveWrappingKeyAsync(opened.Credential, challenge);
            if (wrappingKey == null)
                return null;

            try
            {
                return Crypto.Decrypt(wrapped, wrappingKey);
            }
            catch (CryptographicException)
            {
                return null;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(wrappingKey);
            }
        }

        public static async Task DeleteAsync()
        {
            try
            {
                await KeyCredentialManager.DeleteAsync(CredentialName);
            }
            catch
            {
                // Nothing to delete, or Hello is unavailable.
            }
        }

        // Windows Hello signs with RSA PKCS#1 v1.5, which is deterministic, so the same
        // challenge always yields the same signature and therefore the same wrapping key.
        private static async Task<byte[]?> DeriveWrappingKeyAsync(KeyCredential credential, byte[] challenge)
        {
            var signed = await credential.RequestSignAsync(CryptographicBuffer.CreateFromByteArray(challenge));
            if (signed.Status != KeyCredentialStatus.Success)
                return null;

            CryptographicBuffer.CopyToByteArray(signed.Result, out byte[] signature);
            try
            {
                return SHA256.HashData(signature);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
    }
}
