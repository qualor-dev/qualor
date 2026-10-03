import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/orders")
def orders():
    cur = sqlite3.connect("shop.db").cursor()
    customer = request.args.get("customer", "")
    cur.execute("SELECT * FROM orders WHERE customer = '%s'" % customer)
    found = cur.fetchall()
    cur.execute("SELECT * FROM orders WHERE customer = ?", (customer,))
    return {"found": found, "bound": cur.fetchall()}
