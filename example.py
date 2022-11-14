import os
from flask import Flask, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_httpauth import HTTPBasicAuth
from flask_httpauth import HTTPTokenAuth
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

auth_basic = HTTPBasicAuth()
auth_token = HTTPTokenAuth('Bearer')

users = {
    "frontend": generate_password_hash(os.getenv('FRONTEND_PWD')),
    "dev": generate_password_hash(os.getenv('DEV_PWD'))
}

token_serializer = Serializer(app.config['SECRET_KEY'], expires_in=86400)

@auth_basic.verify_password
def verify_password(username, password):
    print(username, password)
    if username in users and check_password_hash(users.get(username), password):
        return username

@auth_token.verify_token
def verify_token(token):
    try:
        data = token_serializer.loads(token)
    except:
        return False

    if 'username' in data:
        return data['username']

@app.route('/login')
@auth_basic.login_required
def login():
    return jsonify({"token": token_serializer.dumps({'username': auth_basic.current_user()}).decode('utf-8')})

@app.route('/')
@auth_token.login_required
def index():
    return "Access authorized, %s!" % auth_token.current_user()


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
