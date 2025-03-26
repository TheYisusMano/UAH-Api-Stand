import os

from flask import Flask, session, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import insert, select
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("POSTGRE_KEY")

app.config["JWT_SECRET_KEY"] = os.getenv("SECRET_KEY")
jwt = JWTManager(app)


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)

db.init_app(app)


class User(db.Model):
    __tablename__ = 'usuarios'
    id: Mapped[int] = mapped_column(primary_key=True)
    nombre: Mapped[str]
    apellido: Mapped[str]
    biometric_id: Mapped[str] = mapped_column(unique=True)
    admin: Mapped[bool] = mapped_column(default=False)


# Set the secret key to some random bytes. Keep this really secret!
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


@app.route('/')
def index():

    if 'username' in session:
        return f'Logged in as {session["username"]}'
    return 'You are not logged in'


@app.route('/create', methods=['POST'])
def create():
    json = request.get_json()
    print(json)
    with db.session() as session:
        stmt = insert(User).values(nombre=json['nombre'],
                                   apellido=json['apellido'],
                                   biometric_id=json['biometric_id'],
                                   admin=json['admin'])
        session.execute(stmt)
        session.commit()
        print(User.query.all())
    return 'User created'


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route("/login", methods=["POST"])
def login():
    biometric_id = request.json.get("biometric_id", None)
    sentencia = select(User).select_from(User).where(
        User.biometric_id == biometric_id)
    with db.session() as session:
        user = session.execute(sentencia).fetchone()
        if user is None:
            return jsonify({"msg": "Bad username or password"}), 401
    identity_id = str(user[0].id)
    access_token = create_access_token(identity=identity_id)
    return jsonify(access_token=access_token)


@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    setencia = select(User).select_from(User).where(User.id == current_user)
    with db.session() as session:
        user = session.execute(setencia).fetchone()
        if user is None:
            return jsonify({"msg": "Bad username or password "}), 401
    user_name = str(user[0].nombre)
    return jsonify(logged_in_as=current_user, user_name=user_name), 200
