from flask import (
    Flask,
    session,
    request,
    jsonify,
    make_response,
    render_template,
    redirect,
)
from flask_session import Session
import hashlib as hl
import json, uuid
from flask_sqlalchemy import SQLAlchemy
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask_migrate import Migrate

with open(".sensitive/dbconfig.json", "r") as file:
    db_data = json.load(file)

app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app=app)

# Database Config
app.config["SECRET_KEY"] = db_data["secret_key"]
app.config["SQLALCHEMY_DATABASE_URI"] = db_data["db_url"]
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
db = SQLAlchemy(app)

migrate = Migrate(app, db)


# ORM Models
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(32), unique=True)
    user_name = db.Column(db.String(64))
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(128))


class Meds(db.Model):
    meds_id = db.Column(db.Integer, primary_key=True)
    users_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    master_id = db.Column(db.String(64))
    slave_id = db.Column(db.String(3))
    pill_select = db.Column(db.Integer)
    time_hours = db.Column(db.Integer)
    time_mins = db.Column(db.Integer)


# JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]

        if not token:
            return jsonify({"message": "Error: Forbidden (No Token Found)"}), 401

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"])
            current_user = User.query.filter_by(user_id=data["user_id"]).first()
        except:
            return (
                jsonify({"message": "Error: Forbidden (Invalid Token or Header)"}),
                401,
            )

        return f(current_user, *args, **kwargs)

    return decorated


@app.route("/")
def home_page():
    return render_template("index.html")


@app.route("/authorise", methods=["POST"])
def user_auth():
    uname = str(request.form["uname"])
    pwd_hash = str(request.form["pwd"])
    return str(len(hl.sha512(pwd_hash.encode()).hexdigest()))


if __name__ == "__main__":
    app.run(debug=True)
