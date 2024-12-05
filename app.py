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
from flask_sqlalchemy import *
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask_migrate import Migrate

with open(".sensitive/dbconfig.json", "r") as file:
    db_data = json.load(file)

app = Flask(__name__)
app._static_folder = './static'
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
    master_id = db.Column(db.String(64))
    patient_name = db.Column(db.String(64))
    slave_id = db.Column(db.String(2))
    pill_select = db.Column(db.Integer)
    time_hours = db.Column(db.Integer)
    time_mins = db.Column(db.Integer)


class Device(db.Model):
    __tablename__ = "devices"
    dev_no = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), unique=True)
    master_id = db.Column(db.String(64), unique=True)


# ACK
class Ack(db.Model):
    __tablename__ = "ack"
    id = db.Column(db.Integer, primary_key=True)
    meds_id = db.Column(db.Integer, db.ForeignKey("meds.meds_id"))
    dose_taken = db.Column(db.Boolean, unique=False)


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
        # print(db.session.execute(db.select(User).filter_by(user_id=user_id)).scalar())
        user = db.session.execute(db.select(User).filter_by(user_id=user_id)).scalar()
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
    device = db.session.execute(db.select(Device).filter_by(user_id=user_id)).scalar()
    if not device:
        return True
    return device.master_id


def get_master_id_pretty(session=None):
    user_id = get_user_id(session=session)
    if not user_id:
        return None
    device = db.session.execute(db.select(Device).filter_by(user_id=user_id)).scalar()
    if not device:
        return True
    master_id = device.master_id
    return str("-".join(re.findall("." * 8, master_id)))


@app.route("/")
def home_page():
    # print(db.session.execute(db.select(User)).scalars().all())
    if len(db.session.execute(db.select(User)).scalars().all()) == 0:
        return redirect("/register")
    if session.get("auth_token"):
        return redirect("/dashboard")
    return render_template("login.html", message="")


@app.route("/login")
def user_signin():
    return render_template(
        "login.html", message="You have been logged out. Please login to use the app."
    )


@app.route("/register")
def reg_user():
    return render_template("register.html")

@app.route("/logout")
def user_logout():
    return redirect("/signout")

@app.route("/signout")
def user_session_delete():
    session["auth_token"] = None
    return redirect("/login")


@app.route("/signup", methods=["POST"])
def signup():
    data = request.form
    name, uname = data.get("name"), data.get("uname")
    pwd = data.get("pwd")
    regex_obj = re.compile("[a-z0-9._]{5,15}")
    regex_res = regex_obj.fullmatch(uname)

    if not regex_res or len(pwd) < 8:
        return make_response(
            "Invalid username or password pattern. Form likely bypassed or compromised.",
            406,
        )

    admin_reqd = False
    admins = db.session.execute(db.select(User).filter_by(is_admin=True)).scalar()
    if not admins:
        admin_reqd = True

    user = db.session.execute(db.select(User).filter_by(user_name=uname)).scalar()
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
            "login.html", message="Account created successfully. Please Log in."
        )
    else:
        return render_template(
            "login.html", message="User already exists. Please Log in."
        )


@app.route("/authorise", methods=["POST"])
def user_auth():
    # Debug statements
    print("Form data:", request.form.to_dict())
    if "username" not in request.form or "password" not in request.form.to_dict():
        return "Bad Request: Missing form data", 400

    uname = str(request.form.to_dict()["username"])
    pwd_hash = hl.sha512(str(request.form.to_dict()["password"]).encode()).hexdigest()

    user = db.session.execute(db.select(User).filter_by(user_name=uname)).scalar()
    if not user:
        return render_template(
            "login.html", message="Wrong username or user does not exist."
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
        "login.html", message="Wrong username and password combination."
    )



@app.route("/dashboard")
def user_dash():
    user = get_user(session=session)
    if user == True or not user:
        return redirect("/signout")

    # print(Device.query.all())
    device = db.session.execute(
        db.select(Device).filter_by(user_id=user.user_id)
    ).scalar()
    db.session.refresh(device)
    # print(device)
    if not device and (user.is_admin == False):
        return redirect("/register_device")
    # print(Meds.query.all())
    return render_template(
        "dash.html",
        user_full_name=user.full_name,
        n=len(db.session.execute(db.select(Meds)).scalars().all()),
        meds_list=db.session.execute(
            db.select(Meds.patient_name, Meds.pill_select)
        ).all(),
    )


@app.route("/register_device")
def dev_reg_page():
    return render_template("newdevice.html")


@app.route("/device_reg_update", methods=["POST"])
def dev_reg():
    user_id = get_user_id(session=session)
    if user_id == True or not user_id:
        return redirect("/signout")

    master_id = ""
    for i in range(0, 8):
        master_id += request.form.get(str("id_pt_" + str(i)))
    # print(master_id)

    existing_device = db.session.execute(
        db.select(Device).filter_by(user_id=user_id)
    ).scalar()
    if not existing_device:
        new_device = Device(
            user_id=user_id,
            master_id=master_id,
        )
        # print("new device:", new_device)
        db.session.add(new_device)
        # db.session.flush()
        db.session.commit()
        # print(Device.query.all())
        return redirect("/dashboard")

    existing_device.master_id = master_id
    db.session.commit()
    # print(Device.query.all())
    return redirect("/dashboard")


@app.route("/addmeds")
def user_add_meds_page():
    master_id = get_master_id(session=session)
    if not master_id or master_id == True:
        return redirect("/signout")
    master_id = "-".join(re.findall("." * 8, master_id))
    return render_template("addmeds.html", master_id=master_id)


@app.route("/submitmeds", methods=["POST"])
def user_add_meds():
    user_id = get_user_id(session=session)
    if user_id == True or not user_id:
        return redirect("/signout")
    slave_id = int(request.form.get("slave_id"))
    slave_id = str(hex(slave_id)[2:])
    patient = request.form.get("patient")
    pill_select = int(request.form.get("pill_select"))
    time_hrs = int(request.form.get("time_hrs"))
    time_mins = int(request.form.get("time_mins"))

    try:
        device = db.session.execute(
            db.select(Device).filter_by(user_id=user_id)
        ).scalar()
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
        return redirect("/dashboard")
    except:
        return "Failed to add medication"


@app.route('/delete_med/<int:meds_id>', methods=['POST'])
def delete_meds(meds_id):
    med = Meds.query.get(meds_id)
    if med:
        db.session.delete(med)
        db.session.commit()
        return redirect('/home')
    else:
        return redirect('/home')


# UNDER CONSTRUCTION


@app.route("/home")
def dashboard():
    user = get_user(session)
    master_id = get_master_id(session)

    missed_doses = (
        Meds.query.join(Ack, Meds.meds_id == Ack.meds_id)
        .filter(Ack.dose_taken == False, Meds.master_id == master_id)
        .all()
    )

    medications = Meds.query.filter_by(master_id=master_id).all()

    return render_template(
        "dashboard.html",
        user_name=user.full_name,
        missed_doses=missed_doses,
        meds=medications,
    )


@app.route("/api/get_medications", methods=["POST"])
def get_medications():
    data = request.get_json()
    master_id = data.get("master_id")

    if not master_id:
        return jsonify({"error": "master_id is required"}), 400

    medications = Meds.query.filter_by(master_id=master_id).all()

    if not medications:
        return jsonify({"error": "No medications found for the given master_id"}), 404

    meds_list = [
        {
            "meds_id": med.meds_id,
            "slave_id": med.slave_id,
            "pill_select": med.pill_select,
            "time_hours": med.time_hours,
            "time_mins": med.time_mins,
        }
        for med in medications
    ]

    return jsonify(meds_list), 200


@app.route("/api/acknowledge", methods=["POST"])
def acknowledge():
    data = request.get_json()
    meds_id = data.get("meds_id")
    dose_taken = data.get("dose_taken")

    if meds_id is None or dose_taken is None:
        return jsonify({"error": "meds_id and dose_taken are required"}), 400

    ack = Ack(meds_id=meds_id, dose_taken=dose_taken)
    db.session.add(ack)
    db.session.commit()

    return jsonify({"message": "Acknowledgement recorded"}), 200


@app.route("/add_meds", methods=["GET", "POST"])
def add_meds():
    if request.method == "POST":
        master_id = get_master_id(session)
        patient_name = request.form["patient_name"]
        slave_id = request.form["slave_id"]
        pill_select = request.form["pill_select"]
        time_hours = request.form["time_hours"]
        time_mins = request.form["time_mins"]

        # Convert slave_id to hex and remove '0x'
        slave_id_hex = hex(int(slave_id))[2:]

        med = Meds(
            master_id=master_id,
            patient_name=patient_name,
            slave_id=slave_id_hex,
            pill_select=pill_select,
            time_hours=time_hours,
            time_mins=time_mins,
        )

        db.session.add(med)
        db.session.commit()

        return redirect("/home")

    return render_template("add_meds.html", get_master_id_pretty=get_master_id_pretty)


@app.route("/edit_meds/<int:meds_id>", methods=["GET", "POST"])
def edit_meds(meds_id):
    med = Meds.query.get(meds_id)

    if request.method == "POST":
        med.patient_name = request.form["patient_name"]
        slave_id = request.form["slave_id"]
        med.pill_select = request.form["pill_select"]
        med.time_hours = request.form["time_hours"]
        med.time_mins = request.form["time_mins"]

        # Convert slave_id to hex and remove '0x'
        med.slave_id = hex(int(slave_id))[2:]

        db.session.commit()

        return redirect("/home")

    return render_template(
        "edit_meds.html", med=med, get_master_id_pretty=get_master_id_pretty
    )


if __name__ == "__main__":
    app.run(debug=True)
