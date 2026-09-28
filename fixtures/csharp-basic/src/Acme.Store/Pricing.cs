namespace Acme.Store;

// Prices in cents.
public class Pricing
{
    private int calls;

    public int Calls => calls;

    public int Discount(int total, bool member)
    {
        calls++;
        int rate = 5;
        if (total > 10000 && member)
        {
            return total * rate * 2 / 100;
        }
        else if (total > 5000)
        {
            return total * rate / 100;
        }
        return 0;
    }

#pragma warning disable CA1822
    public int Zero() => 0;
#pragma warning restore CA1822
}
