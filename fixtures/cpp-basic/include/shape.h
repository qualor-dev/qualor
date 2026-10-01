#pragma once
#include <string>

class Shape {
public:
    explicit Shape(std::string name) : name_(std::move(name)) {}
    virtual ~Shape() = default;
    virtual double area() const = 0;
    const std::string &name() const { return name_; }

private:
    std::string name_;
};
