package com.acme

// Prices an order.
class Pricing {
    fun discount(total: Int, member: Boolean): Int {
        if (total > 10000 && member) {
            return total / 10
        } else if (total > 5000) {
            return total / 20
        }
        return 0
    }

    fun parse(text: String): Int {
        try {
            return text.toInt()
        } catch (e: Exception) {
        }
        return -1
    }

    fun label(code: Int): String = when (code) {
        1 -> "one"
        2 -> "two"
        else -> "many"
    }

    fun total(a: Int, b: Int, c: Int, d: Int, e: Int): Int = a + b + c + d + e
}
