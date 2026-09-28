package com.acme;

public class Calculator {
    private int unusedCounter;

    public int divide(int a, int b) {
        try {
            return a / b;
        } catch (ArithmeticException e) {
        }
        return 0;
    }

    public boolean sameName(String a, String b) {
        return a == b;
    }

    public int max(int a, int b) {
        int temp = 42;
        if (a > b) {
            return a;
        }
        return b;
    }
}
