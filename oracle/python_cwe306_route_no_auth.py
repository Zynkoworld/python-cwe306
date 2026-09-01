"""python-cwe306 -- routed request handler carrying NO recognized authentication decorator.

decide(code, line) -> "FLAG" | "SAFE".  `line` is the `def`/`async def` line of a function.
FLAG iff that function has a recognized ROUTE decorator AND none of its decorators is a recognized
AUTHENTICATION decorator.

A decorator counts as a route when it is an attribute call on some object (`@app.route`,
`@router.get`, `@bp.post`) and either the attribute is `route`/`websocket`, or its first argument is a
string literal that looks like a URL path (starts with `/`). That path check is what keeps
`@cache.get(...)`-style decorators out.

WHAT THIS DECIDES (read this before trusting the label): it decides the PRESENCE of a recognized auth
decorator on a routed handler. It does NOT decide whether that endpoint OUGHT to require
authentication -- a public health endpoint is correctly routed and correctly unauthenticated, and this
decider will still return FLAG for it. Treat FLAG as "CWE-306 candidate, needs a human policy
decision", not as a finding. stdlib `ast` only; no code is executed.
"""
import ast

CWE = "CWE-306"

_ROUTE_ATTRS = {"route", "get", "post", "put", "patch", "delete", "head", "options", "websocket"}
_ALWAYS_ROUTE = {"route", "websocket"}
_AUTH_EXACT = {
    "login_required", "auth_required", "authentication_required", "requires_auth", "requires_authentication",
    "jwt_required", "token_required", "permission_required", "permission_classes", "authenticated",
    "staff_member_required", "user_passes_test", "protected", "require_auth", "verify_token",
}


def _dec_name(dec):
    node = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _is_route(dec):
    node = dec.func if isinstance(dec, ast.Call) else dec
    if not isinstance(node, ast.Attribute) or node.attr not in _ROUTE_ATTRS:
        return False
    if node.attr in _ALWAYS_ROUTE:
        return True
    # @router.get('/items') -- utvonal-literal kell, hogy a @cache.get(...) ne csusszon be
    if isinstance(dec, ast.Call) and dec.args:
        a = dec.args[0]
        return isinstance(a, ast.Constant) and isinstance(a.value, str) and a.value.startswith("/")
    return False


def _is_auth(dec):
    n = _dec_name(dec)
    if n is None:
        return False
    low = n.lower()
    if low in _AUTH_EXACT:
        return True
    return low.endswith("_required") or "auth" in low or "login" in low or "permission" in low


def decide(code, line):
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return "SAFE"
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if getattr(node, "lineno", None) != line:
            continue
        decs = node.decorator_list
        if not any(_is_route(d) for d in decs):
            return "SAFE"
        if any(_is_auth(d) for d in decs):
            return "SAFE"
        return "FLAG"
    return "SAFE"
