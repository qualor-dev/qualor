namespace Acme.Store;

public static class Names
{
    public const int Limit = 20;

    public static string Describe(string[] items)
    {
        if (items.Length == 0)
        {
            return "none";
        }
        var parts = new System.Collections.Generic.List<string>();
        foreach (var item in items)
        {
            if (item.Length > 20)
            {
                parts.Add(item.Substring(0, 20) + "...");
            }
            else
            {
                parts.Add(item.ToUpperInvariant());
            }
        }
        parts.Sort(System.StringComparer.Ordinal);
        return string.Join(", ", parts);
    }

    public static int Count => 0;
}
