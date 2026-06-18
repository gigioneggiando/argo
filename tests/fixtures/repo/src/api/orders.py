"""Orders API (fixture)."""

def get_order(request, order_id):
    # NOTE (fixture): no ownership check on order_id -> IDOR / CWE-639.
    return repo.find(order_id)
