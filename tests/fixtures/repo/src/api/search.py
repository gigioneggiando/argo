"""Search API (fixture)."""

def search(request):
    q = request.args.get("q", "")
    # NOTE (fixture): builds SQL by string formatting -> CWE-89 around line 42 in real tree.
    sql = "SELECT * FROM widgets WHERE name LIKE '%" + q + "%'"
    return db.execute(sql)
