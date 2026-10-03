package com.acme.shop;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OrderServlet extends HttpServlet {
    private transient Connection connection;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String customer = request.getParameter("customer");
        try (Statement statement = connection.createStatement();
                PreparedStatement bound = connection.prepareStatement("SELECT * FROM orders WHERE customer = ?")) {
            statement.executeQuery("SELECT * FROM orders WHERE customer = '" + customer + "'");
            bound.setString(1, customer);
            bound.executeQuery();
        } catch (SQLException e) {
            response.sendError(500);
        }
    }
}
