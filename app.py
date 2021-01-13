from flask import Flask, render_template, make_response, request, g, jsonify, url_for, redirect
import sqlite3
from dotenv import load_dotenv
import uuid
import json
from bcrypt import checkpw, hashpw, gensalt
import jwt
import os, re
from datetime import datetime, timedelta
from time import sleep

load_dotenv()
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_EXP_TIME = os.getenv("JWT_EXP_TIME")
app = Flask(__name__, static_url_path="/static")
app.config.from_object(__name__)
app.secret_key = os.getenv("SECRET_KEY")
salt = gensalt(12)


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('database.db')
    return db


def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


def register_user_session(login, token, current_host):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('insert into sessions (user, session_token) values (?,?)', [login, token])
            user = cursor.execute('select * from users where login = ? limit 1', [login])
            if current_host not in user['hosts']:
                new_hosts = user['hosts'] + f'{current_host};'
                cursor.execute('insert into sessions (hosts) values (?)', [new_hosts])
            tran.commit()
    except Exception as e:
        raise e


def release_session(login):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('delete from sessions where user = ?', [login])
            tran.commit()
    except Exception as e:
        raise e



def decode_jwt_data(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except Exception as e:
        return {}


def encode_jwt_data(login):
    try:
        return jwt.encode({
            'login': login,
            'last_login': datetime.now().isoformat(),
            'exp': int((datetime.now() + timedelta(seconds=int(JWT_EXP_TIME))).timestamp())
        }, JWT_SECRET, algorithms=['HS256'])
    except Exception as e:
        return None


def send_allowed(method_list):
    if 'OPTIONS' not in method_list:
        method_list.append('OPTIONS')
    response = make_response(jsonify(""), 204)
    response.headers['Allow'] = ','.join(method_list)
    return response


def parse_token(tok):
    try:
        token = tok.replace('Token ', '')
    except Exception as e:
        token = ''
    decoded = decode_jwt_data(token)
    if decoded != {} and decoded['exp'] > int((datetime.now() + timedelta(seconds=int(JWT_EXP_TIME))).timestamp()):
        g.user = decoded
    else:
        g.user = {}
    return g.user, token


def verify_user(login, password):
    try:
        enc = hashpw(password.encode(), salt)
        enc2 = hashpw(enc, salt)
        g.db = sqlite3.connect('database.db')
        cursor = g.db.execute('select * from users where login = ? and password = ?', [login, enc2])
        current_user = cursor.fetchone()
        return checkpw(enc2, current_user[3].encode())
    except Exception as e:
        return False


def check_login_available(login):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.execute('select * from users where login = ?', [login])
            if login in cursor.fetchall():
                return False
            else:
                return True
    except Exception as e:
        return False


def check_password_strength(password):
    pattern1 = re.compile('[A-Z]+')
    pattern2 = re.compile('[0-9]+')
    pattern3 = re.compile('[!@#$%^&*()]+')
    return re.match(pattern1, password) and re.match(pattern2, password) and re.match(pattern3, password)


def register_user(email, login, password, host):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('insert into users (email, login, password, hosts) values (?,?)', [email, login, password, f'{host};'])
            tran.commit()
    except Exception as e:
        raise e


def fetch_user_data(login):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('select * from users where login = ?', [login])
            current_user = cursor.fetchone()
            return {'email': current_user['email'], 'login': current_user['login']}, current_user['hosts'].slice('')
    except Exception as e:
        raise e


def check_session_registered(token, login):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('select * from sessions where session_token = ?', [token])
            current_user = cursor.fetchone()
            return cursor.fetchone() is not None and current_user['user'] == login
    except Exception as e:
        raise e


def delete_site_entry(site, login):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('delete from site_passwords where user_ID = ? and site = ?', [login, site])
            tran.commit()
    except Exception as e:
        raise e


@app.before_request
def check_auth():
    g.user, token = parse_token(request.headers.get('Authorization'))
    try:
        if not check_session_registered(token, g.user['login']):
            g.user = {}
    except Exception as e:
        pass


@app.route('/', methods=['GET', 'OPTIONS'])
def render_main():
    if request.method == 'OPTIONS':
        return send_allowed(['GET'])
    else:
        return redirect("/login")


@app.route('/login', methods=['GET', 'POST', 'OPTIONS'])
def sign_in():
    if request.method == 'OPTIONS':
        return send_allowed(['GET', 'POST'])
    elif request.method == 'GET':
        if g.user != {}:
            return redirect(url_for(manage_user))
        else:
            return render_template("login.html")
    elif request.method == 'POST':
        sleep(1)  # make bruteforcing more tedious
        data = request.get_json()
        login = data.get('login')
        password = data.get('password')
        pattern = re.compile('[a-zA-Z]|[0-9]|-|_')
        if None in [login, password] or \
                pattern.match(login) is False or \
                verify_user(login, password) is False:
            return make_response(jsonify({
                'message': 'Invalid credentials'
            }), 400)
        else:
            try:
                jwt_bytes = encode_jwt_data(login)
                if jwt_bytes is not None:
                    register_user_session(jwt_bytes.decode())
                    res = make_response(jsonify({
                        'message': 'Login successful',
                        'token': jwt_bytes.decode()
                    }), 200)
                    app.config.update(
                        SESSION_COOKIE_SECURE=True,
                        SESSION_COOKIE_HTTPONLY=True,
                        SESSION_COOKIE_SAMESITE='Strict',
                    )
                    res.set_cookie('token', f'Token {jwt_bytes.decode()}', secure=True, httponly=True,
                                   samesite='Strict', path="/")
                    return res
                else:
                    return make_response(jsonify({
                        'message': 'Could not log in. Unknown error happened while attempting to write token'
                    }), 500)
            except Exception as e:
                return make_response(jsonify({
                    'message': 'Something bad happened... Like, really bad :('
                }), 500)


@app.route('/register', methods=['GET', 'POST', 'OPTIONS'])
def sign_up():
    if request.method == 'OPTIONS':
        return send_allowed(['GET', 'POST'])
    elif request.method == 'GET':
        if g.user != {}:
            return redirect(url_for(manage_user))
        else:
            sleep(1)  # render template instead
    elif request.method == 'POST':
        data = request.get_json()
        email = data['email']
        login = data['login']
        password = data['password']
        password_rep = data['password_rep']
        if None in [login, email] or \
                re.match(re.compile('([a-zA-Z]|_|-)+@([a-zA-Z]|[0-9]|\.)+.[a-zA-Z]+'), email) is False or \
                re.match(re.compile('([a-zA-Z]|[0-9]|-|_){1,}'), login):
            return make_response(jsonify({
                'message': 'Wrong data provided'
            }), 400)
        if not check_login_available(login):
            return make_response(jsonify({
                'message': 'Login taken'
            }), 400)
        if password != password_rep:
            return make_response(jsonify({
                'message': 'Passwords don\'t match'
            }), 400)
        if not check_password_strength(password):
            return make_response(jsonify({
                'message': 'Password is too weak. Good password must consist of at least 8 characters and include '
                           'at least one capital letter, one number and one special character from !@#$%^&*()'
            }), 400)
        try:
            register_user(email, login, password)
            res = make_response(jsonify({
                'message': 'Registered successfully, now you can log in. Redirecting...'
            }), 301)
            res.headers['Location'] = url_for(sign_in)
            return res
        except Exception as e:
            return make_response(jsonify({
                'message': 'Unknown error happened while trying to register'
            }), 500)


@app.route('/user', methods=['GET', 'OPTIONS'])
def manage_user():
    if request.method == 'OPTIONS':
        return send_allowed(['GET'])
    elif request.method == 'GET':
        if g.user != {}:
            try:
                data, connections = fetch_user_data(g.user['login'])
                sleep(1)  # render template instead
            except Exception as e:
                return make_response(jsonify({
                    'message': 'Unknown error happened while trying to fetch user data'
                }), 500)


@app.route('/user/my-passwords', methods=['GET', 'DELETE', 'OPTIONS'])
def manage_passwords():
    if request.method == 'OPTIONS':
        return send_allowed(['GET', 'DELETE'])
    elif g.user != {}:
        if request.method == 'DELETE':
            try:
                data = request.get_json()
                delete_site_entry(data['site'], g.user['login'])
                return make_response(jsonify({
                    'message': f'Site entry {data["site"]} deleted successfully'
                }), 200)
            except Exception as e:
                return make_response(jsonify({
                    'message': 'Could not delete site entry'
                }), 304)


@app.route('/user/my-passwords/new', methods=['GET', 'POST', 'OPTIONS'])
def add_password():
    if request.method == 'OPTIONS':
        return send_allowed(['GET', 'POST'])


@app.route('/user/logout', methods=['GET', 'OPTIONS'])
def log_out():
    if request.method == 'OPTIONS':
        return send_allowed(['GET'])
    elif request.method == 'GET':
        if g.user != {}:
            release_session(g.user['login'])
            g.user = {}
            res = make_response(jsonify({
                'message': 'Logged out successfully'
            }), 301)
            res.headers['Location'] = url_for(sign_in)
            return res
        else:
            res = make_response(jsonify({
                'message': 'You are already logged out apparently'
            }), 301)
            res.headers['Location'] = url_for(sign_in)


if __name__ == '__main__':
    init_db()
    app.run()
