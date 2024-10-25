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
    user_id = db.Column(db.String(36), unique=True)
    user_name = db.Column(db.String(64), unique=True)
    full_name = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, unique=False, default=False)


class Meds(db.Model):
    __tablename__ = "meds"
    meds_id = db.Column(db.Integer, primary_key=True)
    # users_id = db.Column(db.String(36), db.ForeignKey("users.user_id"))
    master_id = db.Column(
        db.String(64), db.ForeignKey("devices.master_id"), unique=True
    )
    patient_name = db.Column(db.String(64))
    slave_id = db.Column(db.String(2))
    pill_select = db.Column(db.Integer)
    time_hours = db.Column(db.Integer)
    time_mins = db.Column(db.Integer)


class Device(db.Model):
    __tablename__ = "devices"
    dev_no = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey("users.user_id"), unique=True)
    master_id = db.Column(db.String(64), unique=True)


def get_user(session=None):
    if not session or not session.get("auth_token"):
        return False
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
        if not user:
            return True
        return user
    except:
        return False


def get_user_id(session=None):
    x = get_user(session=session)
    if not x:
        return None
    if x == True:
        return True
    return x.user_id


def get_master_id(session=None):
    user_id = get_user_id(session=session)
    if not user_id:
        return None
    device = Device.query.filter_by(user_id=user_id).first()
    if not device:
        return True
    return device.master_id


@app.route("/")
def home_page():
    if len(User.all()) == 0:
        return redirect("/register")
    if session.get("auth_token"):
        return redirect("/dashboard")
    return render_template("index.html", message="")


@app.route("/login")
def user_signin():
    return render_template(
        "index.html", message="You have been logged out. Please login to use the app."
    )


@app.route("/register")
def reg_user():
    return render_template("register.html")


@app.route("/signout")
def user_session_delete():
    session["auth_token"] = None
    return redirect("/login")


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
            406,
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
            is_admin=admin_reqd,
        )

        db.session.add(user)
        db.session.commit()
        return render_template(
            "index.html", message="Account created successfully. Please Log in."
        )
    else:
        return render_template(
            "index.html", message="User already exists. Please Log in."
        )


@app.route("/authorise", methods=["POST"])
def user_auth():
    uname = str(request.form["uname"])
    pwd_hash = hl.sha512(str(request.form["pwd"]).encode()).hexdigest()
    user = User.query.filter_by(user_name=uname).first()
    if not user:
        return render_template(
            "index.html", message="Wrong username or user does not exist."
        )
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
    return render_template(
        "index.html", message="Wrong username and password combination."
    )


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
        print(Meds.all())

        if not user:
            return redirect("/signout")

        device = Device.query.filter_by(user_id=user_id).first()
        if not device and user.is_admin == False:
            return redirect("/register_device")

        return render_template(
            "dash.html", user_full_name=user.full_name, meds_list=Meds.all()
        )

    except:
        return redirect("/signout")


@app.route("/register_device")
def dev_reg_page():
    return render_template("newdevice.html")


@app.route("/device_reg_update")
def dev_reg():
    user_id = get_user_id(session=session)
    if user_id == True or not user_id:
        return redirect("/signout")

    master_id = ""
    for i in range(0, 8):
        master_id += request.form.get(str("id_pt_" + str(i)))

    existing_device = Device.query.filter_by(user_id=user_id)
    if not existing_device:
        new_device = Device(user_id=user_id, master_id=master_id)
        db.session.add(new_device)
        return redirect("/dash")

    existing_device.master_id = master_id
    return redirect("/dash")


@app.route("/addmeds")
def user_add_meds_page():
    render_template("addmeds.html", master_id="Under Constuction")


@app.route("/submitmeds")
def user_add_meds():
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

        if not user:
            return redirect("/signout")

        slave_id = int(request.form.get("slave_id"))
        slave_id = str(hex(slave_id)[2:])
        patient = request.form.get("patient")
        pill_select = int(request.form.get("pill_select"))
        time_hrs = int(request.form.get("time_hrs"))
        time_mins = int(request.form.get("time_mins"))

        device = Device.query.filter_by(user_id=user_id)
        master_id = device.master_id

        med = Meds(
            master_id=master_id,
            patient_name=patient,
            slave_id=slave_id,
            pill_select=pill_select,
            time_hours=time_hrs,
            time_mins=time_mins,
        )

        db.session.add(med)
        db.session.commit()
        return redirect("/dash")
    except:
        return "Failed to add"


if __name__ == "__main__":
    app.run(debug=True)
