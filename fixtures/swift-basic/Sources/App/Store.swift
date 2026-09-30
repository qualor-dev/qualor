import Foundation

/// A small store. The findings of this fixture are listed in expected.json.
final class Store {
    private var items: [String: Int] = [:]

    func add(_ name: String, count: Int) {
        items[name] = (items[name] ?? 0) + count
    }

    func total() -> Int {
        var sum = 0
        for (_, value) in items where value > 0 {
            sum += value
        }
        return sum
    }

    func first(_ raw: Any) -> String {
        let name = raw as! String
        return name
    }

    func lookup(_ key: String) -> Int {
        return items[key]!
    }

    func grade(_ score: Int) -> String {
        if score > 90 {
            return "A"
        } else if score > 50 {
            return "B"
        } else if score > 90 {
            return "C"
        } else {
            return "D"
        }
    }

    func summary() -> String { "Store with \(items.count) items, and a summary line that is longer than the limit" }
}
