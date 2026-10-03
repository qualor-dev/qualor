package com.acme.shop;

import java.io.IOException;

/** Runs the external report tool. */
public final class ReportRunner {
    private ReportRunner() {
    }

    public static Process export(String format) throws IOException {
        return Runtime.getRuntime().exec("report-tool --format " + format);
    }

    public static Process exportPdf() throws IOException {
        return new ProcessBuilder("report-tool", "--format", "pdf").start();
    }
}
