from flask import Flask, render_template, make_response, request, g, jsonify, url_for, redirect
import sqlite3
from dotenv import load_dotenv
import jwt
import os, re
from datetime import datetime, timedelta
from time import sleep
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_EXP_TIME = os.getenv("JWT_EXP_TIME")
app = Flask(__name__, static_url_path="/static")
app.config.from_object(__name__)
app.secret_key = os.getenv("SECRET_KEY")


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
            cursor.execute('select * from users where login = ? limit 1', [login])
            user = cursor.fetchone()
            if current_host not in user[4]:
                new_hosts = user[4] + f'{current_host};'
                tran.cursor().execute('update users set hosts=(?) where login = ?', [new_hosts, login])
            tran.commit()
    except Exception as e:
        print(e)
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
        token = jwt.encode({
            'login': login,
            'last_login': datetime.now().isoformat(),
            'exp': int((datetime.now() + timedelta(seconds=int(JWT_EXP_TIME))).timestamp())
        }, JWT_SECRET, algorithm='HS256')
        return token
    except Exception as e:
        print(e)
        return None


def send_allowed(method_list):
    if 'OPTIONS' not in method_list:
        method_list.append('OPTIONS')
    response = make_response(jsonify(""), 204)
    response.headers['Allow'] = ','.join(method_list)
    return response


def parse_token(token):
    decoded = decode_jwt_data(token)
    if decoded != {} and decoded['exp'] > int((datetime.now().timestamp())):
        g.user = decoded
    else:
        g.user = {}
    return g.user, token


def verify_user(login, password):
    try:
        g.db = sqlite3.connect('database.db')
        cursor = g.db.execute('select * from users where login = ?', [login])
        current_user = cursor.fetchone()
        return check_password_hash(current_user[3], password)
    except Exception as e:
        return False


def check_login_available(login):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.execute('select * from users where login = ?', [login])
            if cursor.fetchone() is None:
                return True
            else:
                return False
    except Exception as e:
        return False


def check_password_strength(password):
    pattern1 = re.compile('[A-Z]+')
    pattern2 = re.compile('[0-9]+')
    pattern3 = re.compile('[!@#$%^&*()]+')
    return bool(re.search(pattern1, password)) and \
           bool(re.search(pattern2, password)) and \
           bool(re.search(pattern3, password)) and \
           len(password) >= 8


def register_user(email, login, password, host):
    enc = generate_password_hash(password=password, method='pbkdf2:sha256:100000')
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('insert into users (email, login, password, hosts) values (?,?,?,?)',
                           [email, login, enc, f'{host};'])
            tran.commit()
    except Exception as e:
        print(e)
        raise e


def fetch_user_data(login):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('select * from users where login = ?', [login])
            current_user = cursor.fetchone()
            return {'email': current_user[1], 'login': current_user[2]}, current_user[4][:-1].split(';')
    except Exception as e:
        print(e)
        raise e


def check_session_registered(token, login):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('select * from sessions where session_token = ?', [token])
            current_user = cursor.fetchone()
            return current_user is not None and current_user[1] == login
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


def fetch_site_list(login):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('select * from site_passwords where user_ID = ?', [login])
            user_sites = cursor.fetchall()

    except Exception as e:
        raise e


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.before_request
def check_auth():
    try:
        token = request.headers['Cookie']
        token = token.replace('token=', '')
    except Exception:
        token = ''
    g.user, token = parse_token(token)
    try:
        if not check_session_registered(token, g.user['login']):
            g.user = {}
    except Exception as e:
        pass


@app.after_request
def modify_header_security(res):
    res.headers['Server'] = 'Obviously there is a server, it\'s confidential though'
    return res


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
            return redirect("/user")
        else:
            return render_template("login.html", user=g.user)
    elif request.method == 'POST':
        data = request.get_json()
        login = data.get('login')
        password = data.get('password')
        pattern = re.compile(r'([a-zA-Z]|[0-9]|-|_){1,128}')
        if None in [login, password] or \
                bool(pattern.match(login)) is False or \
                verify_user(login, password) is False:
            sleep(1)  # make bruteforcing more tedious
            res = make_response(jsonify({
                'message': 'Invalid credentials'
            }), 400)
        else:
            try:
                jwt_token = encode_jwt_data(login)
                if jwt_token is not None:
                    register_user_session(login, jwt_token, request.headers['Host'])
                    res = make_response(jsonify({
                        'message': 'Login successful',
                        'token': jwt_token
                    }), 200)
                    print("po make response")
                    app.config.update(
                        SESSION_COOKIE_SECURE=True,
                        SESSION_COOKIE_HTTPONLY=True,
                        SESSION_COOKIE_SAMESITE='Strict',
                    )
                    print("po appconfig")
                    res.set_cookie('token', jwt_token, secure=True, httponly=True,
                                   samesite='Strict', path="/")
                    print("hmm")
                else:
                    res = make_response(jsonify({
                        'message': 'Could not log in. Unknown error happened while attempting to write token'
                    }), 500)
            except Exception as e:
                print(e)
                res = make_response(jsonify({
                    'message': 'Something bad happened... Like, really bad :('
                }), 500)
        res.headers['Content-Type'] = 'application/json'
        return res


@app.route('/register', methods=['GET', 'POST', 'OPTIONS'])
def sign_up():
    if request.method == 'OPTIONS':
        return send_allowed(['GET', 'POST'])
    elif request.method == 'GET':
        if g.user != {}:
            return redirect('/user')
        else:
            return render_template("register.html", user=g.user)
    elif request.method == 'POST':
        data = request.get_json()
        email = data['email']
        login = data['login']
        password = data['password']
        password_rep = data['password_rep']
        email_pattern = re.compile(r'([a-zA-Z]|[0-9]|_|-)+@([a-zA-Z]|[0-9]|[.])+[.][a-zA-Z]{1,128}')
        login_pattern = re.compile(r'([a-zA-Z]|[0-9]|-|_){1,128}')
        if None in [login, email] or \
                bool(email_pattern.search(email)) is False or \
                bool(login_pattern.search(login)) is False:
            res = make_response(jsonify({
                'message': 'Wrong data provided'
            }), 400)
            res.headers['Content-Type'] = "application/json"
            return res
        elif not check_login_available(login):
            res = make_response(jsonify({
                'message': 'Login taken'
            }), 400)
            res.headers['Content-Type'] = "application/json"
            return res
        elif password != password_rep:
            res = make_response(jsonify({
                'message': 'Passwords don\'t match'
            }), 400)
            res.headers['Content-Type'] = "application/json"
            return res
        elif not check_password_strength(password):
            res = make_response(jsonify({
                'message': 'Password is too weak. Good password must consist of at least 8 characters and include '
                           'at least one capital letter, one number and one special character from !@#$%^&*()-_'
            }), 400)
            res.headers['Content-Type'] = "application/json"
            return res
        else:
            try:
                register_user(email, login, password, request.headers['Host'])
                res = make_response(jsonify({
                    'message': 'Registered successfully, now you can log in'
                }), 200)
                res.headers['Location'] = url_for('sign_in')
                return res
            except Exception as e:
                res = make_response(jsonify({
                    'message': 'Unknown error happened while trying to register'
                }), 500)
            res.headers['Content-Type'] = "application/json"
            return res


@app.route('/user', methods=['GET', 'OPTIONS'])
def manage_user():
    if request.method == 'OPTIONS':
        return send_allowed(['GET'])
    elif request.method == 'GET':
        if g.user != {}:
            try:
                data, connections = fetch_user_data(g.user['login'])
                return render_template("user.html", data=data, connections=connections, user=g.user)
            except Exception as e:
                res = make_response(jsonify({
                    'message': 'Unknown error happened while trying to fetch user data'
                }), 500)
                res.headers['Content-Type'] = 'application/json'
                return res
        else:
            res = make_response(jsonify({
                'message': 'You have no access to this site'
            }), 405)
            res.headers['Content-Type'] = 'application/json'
            return res


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
        elif request.method == 'GET':
            try:
                data = fetch_site_list(g.user['login'])
            except Exception as e:
                pass


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
    print("hello")
    init_db()
    app.run(ssl_context='adhoc', host='0.0.0.0', port=5000)
