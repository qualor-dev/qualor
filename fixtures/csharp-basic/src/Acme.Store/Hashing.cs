using System.Security.Cryptography;

namespace Acme.Store;

public static class Hashing
{
    public static byte[] Fingerprint(byte[] data)
    {
        using var md5 = MD5.Create();
        return md5.ComputeHash(data);
    }
}
