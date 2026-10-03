package com.acme.shop;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import javax.crypto.Cipher;

/** Digests and ciphers for stored card references. */
public final class Hashing {
    private Hashing() {
    }

    public static byte[] md5(byte[] data) throws GeneralSecurityException {
        return MessageDigest.getInstance("MD5").digest(data);
    }

    public static byte[] sha256(byte[] data) throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    public static Cipher ecbCipher() throws GeneralSecurityException {
        return Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    public static Cipher gcmCipher() throws GeneralSecurityException {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }
}
