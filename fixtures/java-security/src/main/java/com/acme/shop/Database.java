package com.acme.shop;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/** Opens the shop database. */
public final class Database {
    private Database() {
    }

    public static Connection open(String url) throws SQLException {
        return DriverManager.getConnection(url, "shop", "changeit");
    }

    public static Connection open(String url, String user, char[] password) throws SQLException {
        return DriverManager.getConnection(url, user, new String(password));
    }
}
