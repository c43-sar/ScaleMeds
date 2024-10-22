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
import json, uuid, re
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
# On Updation/changes, run `flask db migrate -m "Messages"` and `flask db upgrade`
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(32), unique=True)
    user_name = db.Column(db.String(64))
    full_name = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, unique=False, default=False)


class Meds(db.Model):
    meds_id = db.Column(db.Integer, primary_key=True)
    users_id = db.Column(db.Integer, db.ForeignKey("users.user_id"))
    master_id = db.Column(db.String(64))
    slave_id = db.Column(db.String(3))
    pill_select = db.Column(db.Integer)
    time_hours = db.Column(db.Integer)
    time_mins = db.Column(db.Integer)


# # JWT
# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = None

#         if "x-access-token" in request.headers:
#             token = request.headers["x-access-token"]

#         if not token:
#             return jsonify({"message": "Error: Forbidden (No Token Found)"}), 401

#         try:
#             data = jwt.decode(token, app.config["SECRET_KEY"])
#             current_user = User.query.filter_by(user_id=data["user_id"]).first()
#         except:
#             return (
#                 jsonify({"message": "Error: Forbidden (Invalid Token or Header)"}),
#                 401,
#             )

#         return f(current_user, *args, **kwargs)

#     return decorated


@app.route("/")
def home_page():
    if session.get("auth_token"):
        return redirect("/dashboard")
    return render_template("index.html")


@app.route("/register")
def reg_user():
    return render_template("register.html")


@app.route("/signup", methods=["POST"])
def signup():
    data = request.form
    name, uname = data.get("name"), data.get("uname")
    pwd = data.get("pwd")
    regex_obj = re.compile("[a-z0-9]{5,15}")
    regex_res = regex_obj.fullmatch(uname)

    if not regex_res or len(pwd) < 8:
        return make_response(
            "Invalid username or password pattern. Form likely bypassed or compromised.",
            406
        )
    
    admin_reqd = False
    admins = User.query.filter_by(is_admin=True).first()
    if not admins:
        admin_reqd = True
    
    user = User.query.filter_by(user_name=uname).first()
    if not user:
        user = User(
            user_id=str(uuid.uuid4()),
            full_name=name,
            user_name=uname,
            password=hl.sha512(pwd.encode()).hexdigest(),
            is_admin=admin_reqd
        )

        db.session.add(user)
        db.session.commit()
        return make_response("Successfully registered.", 201)
    else:
        return make_response("User already exists. Please Log in.", 202)


@app.route("/authorise", methods=["POST"])
def user_auth():
    uname = str(request.form["uname"])
    pwd_hash = hl.sha512(str(request.form["pwd"]).encode()).hexdigest()
    user = User.query.filter_by(user_name=uname).first()
    if not user:
        return "User does NOT exist. Register here"
    if user.password == pwd_hash:
        auth_token = jwt.encode(
            {
                "user_id": user.user_id,
                "exp": datetime.utcnow() + timedelta(hours=1),
            },
            app.config["SECRET_KEY"],
            algorithm="HS256",
        )
        session["auth_token"] = auth_token
        return redirect("/dashboard")
    return redirect("/")


@app.route("/dashboard")
def user_dash():
    if not session.get("auth_token"):
        return redirect("/")
    user_token = session.get("auth_token")
    try:
        user_token = jwt.decode(
            user_token,
            app.config["SECRET_KEY"],
            options={"require": ["exp"]},
            algorithms=["HS256"],
        )
        user_id = user_token["user_id"]
        user = User.query.filter_by(user_id=user_id).first()
        return render_template("dash.html", user_full_name = user.full_name)
    except:
        return "Error. Try Login again."


if __name__ == "__main__":
    app.run(debug=True)
