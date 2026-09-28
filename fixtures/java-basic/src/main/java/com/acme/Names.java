package com.acme;

public final class Names {
    private Names() {}

    public static String describe(String first, String last, int age, boolean active) {
        StringBuilder sb = new StringBuilder();
        sb.append("Name: ").append(first).append(' ').append(last);
        sb.append(", age: ").append(age);
        sb.append(", status: ").append(active ? "on" : "off");
        if (active) {
            sb.append(" (active)");
        } else {
            sb.append(" (inactive)");
        }
        String result = sb.toString().trim();
        return result.isEmpty() ? "unknown" : result;
    }
}
