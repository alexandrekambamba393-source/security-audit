import sqlite3

def get_user(conn, request):
    user_id = request.args["id"]
    cur = conn.execute("SELECT * FROM users WHERE id = " + user_id)
    return cur.fetchone()  # changed

def get_invoice(conn, request, current_user):
    inv = conn.execute("SELECT * FROM invoices WHERE id = ?", (request.args["id"],)).fetchone()
    return inv
