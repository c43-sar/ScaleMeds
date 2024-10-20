from flask import Flask, session, request, jsonify, make_response, render_template, redirect
from flask_session import Session
import hashlib as hl

app = Flask(__name__)
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = "filesystem"
Session(app=app)


@app.route('/')
def home_page():
	return render_template("index.html")

@app.route('/authorise', methods=['POST'])
def user_auth():
	uname = str(request.form['uname'])
	pwd_hash = str(request.form['pwd'])
	return str(len(hl.sha512(pwd_hash.encode()).hexdigest()))

if __name__ == "__main__":
	app.run(debug=True)