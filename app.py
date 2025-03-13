from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_cors import CORS
from flask_jwt_extended import create_access_token, JWTManager
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///chat.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

app.config["JWT_SECRET_KEY"] = "your_secret_key"
jwt = JWTManager(app)

users = {
    "admin": {"username": "admin", "password": "admin123", "role": "admin"},
    "user": {"username": "user", "password": "user123", "role": "user"},
    "analyst": {"username": "analyst", "password": "analyst123", "role": "analyst"},
}

analysts = [
    {"username": "analyst1"},
    {"username": "analyst2"},
    {"username": "analyst3"}
]

incidents = [
    {"id": 1, "description": "DDoS Attack Detected", "severity": "High", "status": "Investigating"},
    {"id": 2, "description": "Unauthorized Login Attempt", "severity": "Medium", "status": "Resolved"}
]

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(50), nullable=False)  # 'Admin' or 'User'
    message = db.Column(db.String(500), nullable=False)

with app.app_context():
    db.create_all()

@app.route("/")
def home():
    return render_template("index.html", incidents=incidents)

@app.route("/role-selection")
def role_selection():
    return render_template("role-selection.html")

@app.route("/<role>-login")
def login_page(role):
    if role in ["admin", "user", "analyst"]:
        return render_template(f"{role}-login.html")
    return "Role not found", 404

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role")

    user = users.get(username)
    
    if user and user["password"] == password and user["role"] == role:
        token = create_access_token(identity={"username": username, "role": role})
        
        redirect_url = {
            "admin": url_for("admin_dashboard"),
            "analyst": url_for("analyst_dashboard"),
            "user": url_for("user_dashboard"),
        }.get(role, url_for("home"))

        return jsonify({"token": token, "role": role, "redirect_url": redirect_url}), 200

    return jsonify({"message": "Invalid credentials!"}), 401

@app.route("/analysts", methods=["GET"])
def get_analysts():
    return jsonify(analysts), 200

@app.route("/admin-dashboard")
def admin_dashboard():
    messages = ChatMessage.query.all()  # Fetch chat history
    return render_template("admin-dashboard.html", messages=messages)

@app.route("/user-dashboard")
def user_dashboard():
    messages = ChatMessage.query.all()  # Fetch chat history
    return render_template("user-dashboard.html", messages=messages)

@app.route("/analyst-dashboard")
def analyst_dashboard():
    return render_template("analyst-dashboard.html")

@app.route("/users/add", methods=["POST"])
def add_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    role = data.get("role")

    if username in users:
        return jsonify({"error": "Username already exists"}), 400

    users[username] = {"username": username, "password": password, "role": role}
    return jsonify({"message": "User added successfully"}), 201

@app.route("/users/edit/<username>", methods=["POST"])
def edit_user(username):
    data = request.json
    if username in users:
        users[username]["role"] = data["role"]
        return jsonify({"message": "User role updated successfully"})
    return jsonify({"error": "User not found"}), 404

@app.route("/users/delete/<username>", methods=["DELETE"])
def delete_user(username):
    if username in users:
        del users[username]
        return jsonify({"message": "User deleted successfully"})
    return jsonify({"error": "User not found"}), 404

@app.route("/incidents/submit", methods=["POST"])
def submit_incident():
    data = request.json
    incident = {
        "id": len(incidents) + 1,
        "description": data["description"],
        "severity": data["severity"],
        "status": "Pending"
    }
    incidents.append(incident)
    
    socketio.emit("new_incident", incident)
    
    return jsonify({"message": "Incident submitted", "incident": incident})

@app.route("/incidents/edit/<int:incident_id>", methods=["POST"])
def edit_incident(incident_id):
    data = request.json
    for incident in incidents:
        if incident["id"] == incident_id:
            incident["status"] = data["status"]
            return jsonify({"message": "Incident updated successfully"})
    return jsonify({"error": "Incident not found"}), 404

@app.route("/incidents/delete/<int:incident_id>", methods=["DELETE"])
def delete_incident(incident_id):
    global incidents
    incidents = [inc for inc in incidents if inc["id"] != incident_id]
    return jsonify({"message": "Incident deleted successfully"}), 200

@socketio.on("admin_message")
def handle_admin_message(data):
    new_message = ChatMessage(sender="Admin", message=data["message"])
    db.session.add(new_message)
    db.session.commit()
    emit("receive_message", {"sender": "Admin", "message": data["message"]}, broadcast=True)

@socketio.on("user_message")
def handle_user_message(data):
    new_message = ChatMessage(sender="User", message=data["message"])
    db.session.add(new_message)
    db.session.commit()
    emit("receive_message", {"sender": "User", "message": data["message"]}, broadcast=True)

if __name__ == "__main__":
    socketio.run(app, debug=True)

