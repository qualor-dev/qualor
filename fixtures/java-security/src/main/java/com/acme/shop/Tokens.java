package com.acme.shop;

import java.security.SecureRandom;
import java.util.Random;

/** Tokens for password-reset links. */
public final class Tokens {
    private static final Random WEAK = new Random();
    private static final SecureRandom STRONG = new SecureRandom();

    private Tokens() {
    }

    public static String weakToken() {
        return Long.toHexString(WEAK.nextLong());
    }

    public static String strongToken() {
        return Long.toHexString(STRONG.nextLong());
    }
}
