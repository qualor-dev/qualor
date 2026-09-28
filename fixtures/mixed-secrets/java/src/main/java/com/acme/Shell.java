package com.acme;

import java.io.IOException;

public class Shell {
    public Process start(String command) throws IOException {
        return Runtime.getRuntime().exec(command);
    }
}
