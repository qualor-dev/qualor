package com.acme

// Labels shown on invoices.
object Labels {
    fun describe(first: String, last: String, title: String?, age: Int): String {
        val builder = StringBuilder()
        if (title != null && title.isNotEmpty()) {
            builder.append(title).append(' ')
        }
        builder.append(first.trim()).append(' ').append(last.trim())
        when {
            age < 18 -> builder.append(" (minor)")
            age >= 65 -> builder.append(" (senior)")
            else -> builder.append(" (adult)")
        }
        val result = builder.toString().replace("  ", " ")
        return if (result.length > 80) result.substring(0, 80) else result
    }
}
