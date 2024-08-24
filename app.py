from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import jwt
from config import Config
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)
app.config.from_object(Config)

mongo = PyMongo(app)

def generate_jwt_token(username):
    payload = {
        'username': username,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')

def decode_jwt_token(token):
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password are required')
            return redirect(url_for('register'))

        if mongo.db.User.find_one({'username': username}):
            flash("Username already exists.")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        user = {
            'username': username,
            'password': hashed_password,
            'created_at': datetime.datetime.utcnow(),
            'updated_at': datetime.datetime.utcnow()
        }
        mongo.db.User.insert_one(user)
        flash('User registered successfully')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password are required')
            return redirect(url_for('login'))
        
        user = mongo.db.User.find_one({'username': username})

        if user:
            if check_password_hash(user['password'], password):
                token = generate_jwt_token(username)
                session['token'] = token
                session['username'] = username
                flash('Login successful', 'success')
                return redirect(url_for('index'))
            else:
                flash('Invalid password', 'error')
                return redirect(url_for('login'))
        else:
            flash('Username not found', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')

    
@app.route('/logout', methods=['GET'])
def logout():
    session.pop('token', None)
    session.pop('username', None)
    flash('Logged out successfully')
    return redirect(url_for('index'))


@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 401
    
    try:
        token = token.split(' ')[1]
        payload = decode_jwt_token(token)
        if payload:
            return jsonify({'message': 'Protected content accessed', 'user': payload['username']}), 200
        else:
            return jsonify({'message': 'Invalid or expired token'}), 401
    except Exception as e:
        return jsonify({'message': 'Error decoding token'}), 401


if __name__ == "__main__":
    app.run(debug=True)