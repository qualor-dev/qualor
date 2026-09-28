package com.acme;

public class CalculatorTest {
    public static void main(String[] args) {
        Calculator c = new Calculator();
        System.out.println(c.divide(4, 2) + c.max(3, 1));
        System.out.println(c.sameName("a", "a"));
    }
}
