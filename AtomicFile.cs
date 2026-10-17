using System.IO;

namespace AuthenticatorDesktop
{
    public static class AtomicFile
    {
        // Writes to a temporary file first and then swaps it in, so a crash or power loss
        // mid-write leaves the previous vault intact instead of a truncated file.
        public static void WriteAllBytes(string path, byte[] bytes)
        {
            string tempPath = path + ".tmp";

            using (var stream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(flushToDisk: true);
            }

            File.Move(tempPath, path, overwrite: true);
        }
    }
}
