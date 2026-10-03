package com.acme.shop;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.URL;
import java.net.URLConnection;

/** Fetches supplier catalogues and restores saved carts. */
public final class Downloads {
    private Downloads() {
    }

    public static URLConnection open(String address) throws IOException {
        return new URL(address).openConnection();
    }

    public static Object restoreCart(InputStream saved) throws IOException, ClassNotFoundException {
        try (ObjectInputStream in = new ObjectInputStream(saved)) {
            return in.readObject();
        }
    }
}
