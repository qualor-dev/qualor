namespace Acme.Store.Tests;

public static class PricingChecks
{
    public static bool MemberDiscount() => new Pricing().Discount(20000, true) == 2000;
}
