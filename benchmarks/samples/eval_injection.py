def compute_expression(expr: str):
    # Seeded vulnerability: unsafe eval
    return eval(expr)
