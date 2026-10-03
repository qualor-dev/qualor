package com.acme.shop;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/** Reads files stored next to orders. */
public final class Attachments {
    private static final File ROOT = new File("/var/shop/attachments");

    private Attachments() {
    }

    public static byte[] read(String name) throws IOException {
        return Files.readAllBytes(new File(ROOT, name).toPath());
    }

    public static byte[] readLogo() throws IOException {
        return Files.readAllBytes(new File(ROOT, "logo.png").toPath());
    }
}
