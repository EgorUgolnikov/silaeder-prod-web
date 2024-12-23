from functools import wraps
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
import jwt
import time
import random
db = SQLAlchemy()
app = Flask(__name__)

migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

@app.route('/api/ping', methods=['GET'])
def send():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    isPublic = db.Column(db.Boolean)
    countryCode = db.Column(db.String(2), nullable=False)
    phone = db.Column(db.String(100))
    image= db.Column(db.String(200))
    last_generation = db.Column(db.Integer, nullable=True)


class Country(db.Model):
    __tablename__ = 'countries'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    alpha2 = db.Column(db.String(2), nullable=False, unique=True)
    alpha3 = db.Column(db.String(3), nullable=False, unique=True)
    region = db.Column(db.String(20))


def present_country(country):
    return {
        'name': country.name,
        'alpha2': country.alpha2,
        'alpha3': country.alpha3,
        'region': country.region
    }


def present_user(user):
    return {
        'login': user.login,
        'email': user.email,
        'id': user.id,
        'country': user.country_code,
        'image': user.image,
        'phone': user.phone
    }


@app.route('/api/countries/<int:alpha2>', methods=['GET'])
def get_country(alpha2):
    country = Country.query.filter_by(alpha2=alpha2).first()
    if country:
        return jsonify(present_country(country))
    else:
        return 'country not found', 404


@app.route('/api/countries', methods=['GET'])
def get_all_countries():
    regions = request.args.getlist('region')
    if regions == []:
        return Country.query.all()
    else:
        return Country.query.filter(Country.region.in_(regions)).all()



@app.route('/api/auth/register', methods=['POST'])
def add_user():
    data = request.get_json()

    if data is None:
        return jsonify({'reason': 'Invalid JSON format'}), 400

    login = data.get('login')
    password = data.get('password')
    country = data.get('country')
    email = data.get('email')
    phone = data.get('phone')
    image = data.get('image')

    if not login:
        return jsonify({'reason': 'Missing login'}), 400
    if not password:
        return jsonify({'reason': 'Missing password'}), 400
    if not email:
        return jsonify({'reason': 'Missing email'}), 400
    if not country:
        return jsonify({'reason': 'Missing country'}), 400

    if not User.query.filter_by(countryCode=country).first():
        return jsonify({'reason': 'Country not exist'}), 400
    if User.query.filter_by(login=login).first():
        return jsonify({'reason': 'User already exists'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'reason': 'Email already used'}), 400
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(login=login, password=hashed_password, countryCode=country, email=email, isPublic=True, phone=phone, image=image)  # дописать

    db.session.add(user)

    db.session.commit()

    return jsonify(present_user(user))


@app.route('/api/auth/sign-in', methods=['POST'])
def login():
    data = request.get_json()

    login = data.get('login')
    password = data.get('password')

    if not login or not password:
        return jsonify({'error': 'Missing data'}), 400

    # ищем пользователя в базе и проверяем хэш пароля
    user = User.query.filter_by(login=login).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    # генерируем токен с id пользователя и временем создания
    token = jwt.encode({'user_id': user.id, 'created_at': int(time.time())}, app.config['SECRET_KEY'],
                       algorithm='HS256')

    return jsonify({'token': token}), 200


def requires_user(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # получаем токен из заголовков запроса
        token = request.headers.get('Authorization', '').replace('Bearer ', '')

        # если токена нет - возвращаем ошибку
        if not token:
            return jsonify({'error': 'Missing token'}), 401

        # расшифровываем токен и получаем его содержимое
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except Exception as e:
            return jsonify({'error': 'Invalid token'}), 401

        # получаем id пользователя и время генерации из токена
        user_id = payload.get('user_id')
        created_at = payload.get('created_at')

        # если чего-то нет - возвращаем ошибку
        if not user_id or not created_at:
            return jsonify({'error': 'Invalid token'}), 401

        # находим пользователя, если его нет - возвращаем ошибку
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 401

        # передаем в целевой эндпоинт пользователя и параметры пути
        return func(user, *args, **kwargs)

    return wrapper


@app.route('/api/me/profile', methods=['GET'])
@requires_user
def get_my_profile(user):
    return present_user(user), 200


@app.route('/api/me/profile', methods=['PATCH'])
@requires_user
def change_my_profile(user):
    data = request.get_json()

    if 'phone' in data:
        if User.query.filter_by(phone=data.phone).first():
            return jsonify({'error': 'Phone number already used'}), 409
        else:
            user.phone = data.phone
    if 'image' in data:
        user.image = data.image
    if 'isPublic' in data:
        user.isPublic = data.isPublic
    if 'countryCode' in data:
        user.countryCode = data.countryCode
    return present_user(user), 200


@app.route('/api/profiles/<login>', methods=['GET'])
@requires_user
def get_profile(user, login):
    s_user = User.query.filter_by(login=login).first()
    if not s_user:
        return jsonify({'error': 'User not found'}), 403
    if s_user.isPublic:
        return present_user(s_user), 200
    else:
        return jsonify({'error': 'Profile is not public'}), 403


@app.route('/api/me/updatePassword', methods=['POST'])
@requires_user
def update_password(user):
    data = request.get_json()
    old = data.get("oldPassword")
    new = data.get("newPassword")
    if bcrypt.check_password_hash(user.password, old):
        if new:
            user.password = bcrypt.generate_password_hash(new).decode('utf-8')
        else:
            return jsonify({'error': 'Wrong new password'}), 400
    else:
        return jsonify({'error': 'Wrong old password'}), 403
    return present_user(user), 200


if __name__ == '__main__':
    app.run(debug=True, port=8000)


