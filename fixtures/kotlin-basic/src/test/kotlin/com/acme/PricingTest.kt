package com.acme

class PricingTest {
    fun discountForMembers() {
        check(Pricing().discount(20000, true) == 2000)
    }
}
