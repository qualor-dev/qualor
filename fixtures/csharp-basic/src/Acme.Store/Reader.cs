using System.IO;

namespace Acme.Store;

public static class Reader
{
    public static string FirstLine(string path)
    {
        var reader = new StreamReader(path);
        return reader.ReadLine() ?? string.Empty;
    }
}
