#include <memory>
#include <string>
#include <utility>
#include <vector>
#include "shape.h"

class Square : public Shape {
public:
    explicit Square(double side) : Shape("square"), side_(side) {}
    double area() const override { return side_ * side_; }

private:
    double side_;
};

double total(const std::vector<std::unique_ptr<Shape>> &shapes) {
    double sum = 0;
    for (const auto &s : shapes) {
        sum += s->area();
    }
    return sum;
}

int describe(std::string label) {
    std::string kept = std::move(label);
    int *counts = new int[4];
    counts[0] = static_cast<int>(kept.size() + label.size());
    int result = counts[0];
    delete counts;
    return result;
}

int ratio(int a) {
    int zero = 0;
    if (a > 3) {
        return a / zero;
    }
    return a;
}
