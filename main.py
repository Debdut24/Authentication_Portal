import flask
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from typing import Callable

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

class MySQL(SQLAlchemy):
    Column:Callable
    Integer:Callable
    String:Callable

db = MySQL(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id = user_id).first()


@app.route('/')
def home():
    return render_template("index.html",logged_in=current_user.is_authenticated)


@app.route('/register', methods = ['POST','GET'])
def register():
    if request.method == "POST":
        password = request.form.get("password")
        final_password = generate_password_hash(password = password,
                                                method='pbkdf2:sha256',
                                                salt_length=8)
        check_user = User.query.filter_by(email = request.form.get("email")).first()
        if check_user:
            flash("Account with the same Email exits")
        else:
            user = User (name = request.form.get ("name"),
                         email = request.form.get ("email"),
                         password = final_password,)
            return redirect(url_for('secrets',name = request.form.get("name")))
    return render_template("register.html")


@app.route('/login',methods = ['GET','POST'])
def login():
    if request.method == "POST":
        check_user = User.query.filter_by (email = request.form.get ("email")).first ()
        if not check_user:
            flash("The account does not exist.")
        elif check_password_hash(pwhash = check_user.password,
                               password = request.form.get("password")):
            login_user(check_user)
            return redirect(url_for('secrets',name=check_user.name))
        elif check_password_hash(pwhash = check_user.password,
                               password = request.form.get("password")) == False:
            flash("Wrong password ! Recheck your password.")
    return render_template("login.html")


@app.route('/secrets/<name>')
@login_required
def secrets(name):
    return render_template("secrets.html",name = name,logged_in = True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home',logged_in = False))


@app.route('/download')
@login_required
def download():
    filename = "cheat_sheet.pdf"
    return send_from_directory (
        directory = "static/files",
        path = filename,
        as_attachment = False
    )

if __name__ == "__main__":
    app.run(debug=True)
