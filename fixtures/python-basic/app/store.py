"""Order storage helpers."""
import hashlib
import os
import subprocess


# Queries are built by hand here on purpose (the fixture's S608).
def find_order(cursor, order_id):
    query = "SELECT * FROM orders WHERE id = '%s'" % order_id
    cursor.execute(query)
    return cursor.fetchone()


def checksum(data):
    return hashlib.md5(data).hexdigest()


def archive(path):
    subprocess.call("tar czf backup.tgz " + path, shell=True)


class Store:
    """A tiny in-memory store."""

    def __init__(self, items=[]):
        self.items = items

    def classify(self, total, member):
        if total > 10000 and member:
            return "gold"
        elif total > 5000 or member:
            return "silver"
        else:
            return "bronze"

    def count(self, kind):
        n = 0
        for item in self.items:
            if item == None:
                continue
            n += 1 if item.kind == kind else 0
        return n

    def describe(self, value):
        match value:
            case 1:
                return "one"
            case 2 | 3:
                return "few"
            case _:
                return "many"
