from flask import request


def lookup(cur):
    cur.execute("SELECT * FROM orders WHERE id = " + request.args["id"])
    return cur.fetchone()
