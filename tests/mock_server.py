# tests/mock_server.py
# A deliberately vulnerable Flask API server for safe fuzzing practice
# Run with: python3 tests/mock_server.py
# Runs on: http://localhost:5000

from flask import Flask, request, jsonify
import time

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Fake database of users (in memory — resets on restart)
# ---------------------------------------------------------------------------
USERS = {
    "1": {"id": 1, "username": "admin",    "email": "admin@example.com",    "role": "admin"},
    "2": {"id": 2, "username": "alice",    "email": "alice@example.com",    "role": "user"},
    "3": {"id": 3, "username": "bob",      "email": "bob@example.com",      "role": "user"},
}


# ---------------------------------------------------------------------------
# Route 1: GET /users
# Vulnerability: reflects raw input back in error message (info leakage)
# ---------------------------------------------------------------------------
@app.route('/users', methods=['GET'])
def get_users():
    user_id = request.args.get('id')

    if user_id is None:
        return jsonify({"users": list(USERS.values())}), 200

    # Vulnerability: leaks the raw input in the error message
    if user_id not in USERS:
        return jsonify({
            "error": f"User not found: {user_id}",
            "query":  f"SELECT * FROM users WHERE id = {user_id}",
            "db":     "mysql://admin:password123@localhost/app"
        }), 404

    return jsonify(USERS[user_id]), 200


# ---------------------------------------------------------------------------
# Route 2: POST /login
# Vulnerability: returns 500 on SQL-looking input, leaks stack trace
# ---------------------------------------------------------------------------
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}

    username = data.get('username', '')
    password = data.get('password', '')

    # Vulnerability: crashes on SQL injection attempts
    sql_chars = ["'", '"', '--', ';', 'OR', 'AND', 'DROP', 'SELECT']
    for char in sql_chars:
        if char.lower() in str(username).lower():
            # Simulate a server crash with exposed traceback
            return jsonify({
                "error":     "Internal Server Error",
                "exception": "ProgrammingError: syntax error in SQL query",
                "traceback": f"File 'db.py', line 42, in execute\n"
                             f"  cursor.execute('SELECT * FROM users WHERE "
                             f"username = {username}')\n"
                             f"sqlite3.OperationalError: unrecognized token"
            }), 500

    # Normal login check
    if username == "admin" and password == "admin123":
        return jsonify({"token": "eyJhbGciOiJIUzI1NiJ9.fake.token"}), 200

    return jsonify({"error": "Invalid credentials"}), 401


# ---------------------------------------------------------------------------
# Route 3: GET /search
# Vulnerability: slow response on long input (DoS simulation)
# ---------------------------------------------------------------------------
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')

    # Vulnerability: processing time grows with input size
    if len(query) > 100:
        time.sleep(2)    # simulate expensive operation on large input
        return jsonify({
            "error":   "Query too complex",
            "length":  len(query),
            "message": f"Processing failed for input: {query[:50]}..."
        }), 400

    results = [u for u in USERS.values()
               if query.lower() in u['username'].lower()]
    return jsonify({"results": results, "count": len(results)}), 200


# ---------------------------------------------------------------------------
# Route 4: POST /users
# Vulnerability: accepts any field (mass assignment)
# ---------------------------------------------------------------------------
@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json(silent=True) or {}

    # Vulnerability: blindly accepts all fields including 'role'
    new_id  = str(len(USERS) + 1)
    new_user = {
        "id":       int(new_id),
        "username": data.get('username', 'unknown'),
        "email":    data.get('email',    'unknown@example.com'),
        "role":     data.get('role',     'user'),   # should never accept role from client
    }
    USERS[new_id] = new_user
    return jsonify({"created": new_user}), 201


# ---------------------------------------------------------------------------
# Route 5: DELETE /users/<id>
# Vulnerability: no auth check — anyone can delete any user
# ---------------------------------------------------------------------------
@app.route('/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    if user_id in USERS:
        deleted = USERS.pop(user_id)
        return jsonify({"deleted": deleted}), 200
    return jsonify({"error": f"User {user_id} not found"}), 404


# ---------------------------------------------------------------------------
# Route 6: GET /health
# Clean route — should always return 200, useful as baseline
# ---------------------------------------------------------------------------
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status":  "ok",
        "version": "1.0.0",
        "routes":  ["/users", "/login", "/search", "/health"]
    }), 200


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    print()
    print("=" * 50)
    print("  Vulnerable Mock API Server")
    print("  Running on http://localhost:5000")
    print("  Press Ctrl+C to stop")
    print("=" * 50)
    print()
    print("  Routes:")
    print("  GET    /health         — baseline check")
    print("  GET    /users          — list users")
    print("  GET    /users?id=X     — get user by id")
    print("  POST   /login          — login endpoint")
    print("  GET    /search?q=X     — search users")
    print("  POST   /users          — create user")
    print("  DELETE /users/<id>     — delete user")
    print()
    app.run(debug=False, port=5000)

