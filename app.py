from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
from config import Config
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)
app.config.from_object(Config)

mongo = PyMongo(app)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    if mongo.db.User.find_one({'username': username}):
        return jsonify({'message': "username already exits."}), 409

    hashed_password = generate_password_hash(password)

    user = {
        'username': username,
        'password': hashed_password,
        'created_at': datetime.datetime.utcnow(),
        'updated_at': datetime.datetime.utcnow()
    }

    mongo.db.User.insert_one(user)

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['GET', 'POST'])
def login():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400
    
    user = mongo.db.User.find_one({'username': username})

    if user:
        if check_password_hash(user['password'], password):
            return jsonify({'message': 'Login successful'}), 200
        else:
            return jsonify({'message': 'Invalid password'}), 401
    else:
        return jsonify({'message': 'Username not found'}), 404


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("You  have been logout out.")
    return redirect(url_for('Home'))

if __name__ == "__main__":
    app.run(debug=True)