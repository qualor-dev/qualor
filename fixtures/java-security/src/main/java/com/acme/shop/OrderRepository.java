package com.acme.shop;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

/** Order queries: one built by concatenation, one with a bound parameter. */
public final class OrderRepository {
    private OrderRepository() {
    }

    public static int deleteByCustomer(Connection connection, String customer) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            return statement.executeUpdate("DELETE FROM orders WHERE customer = '" + customer + "'");
        }
    }

    public static int deleteById(Connection connection, long id) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("DELETE FROM orders WHERE id = ?")) {
            statement.setLong(1, id);
            return statement.executeUpdate();
        }
    }
}
