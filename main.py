from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)


app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root3'
app.config['MYSQL_PASSWORD'] = 'DarrenDBMS2024'
app.config['MYSQL_DB'] = 'pythonlogin2'
app.config['MYSQL_PORT'] = 3306


mysql = MySQL(app)
bcrypt = Bcrypt(app)


@app.route('/')
def index():
    return redirect(url_for('secure_login'))

# Vulnerable SELECT
@app.route('/vulnerable_login', methods=['GET', 'POST'])
def vulnerable_login():
    msg = ''
    data = []
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # This query is vulnerable to SQL injection
        query = f"SELECT * FROM accounts WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        accounts = cursor.fetchall()

        if accounts:
            # Display all returned account details
            msg = 'Vulnerable login successful! Retrieved data:'
            data = accounts  # Capture the retrieved data
        else:
            msg = 'Incorrect username/password!'
    return render_template('vulnerable_login.html', msg=msg, data=data)

# Secure
@app.route('/secure_login', methods=['GET', 'POST'])
def secure_login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        if account and bcrypt.check_password_hash(account['password'], password):
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            return 'Secure login successful!'
        else:
            msg = 'Incorrect username/password!'
    return render_template('secure_login.html', msg=msg)


@app.route('/MyWebApp/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('secure_login'))


@app.route('/MyWebApp/registration', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email'].encode()
        hashpwd = bcrypt.generate_password_hash(password).decode('utf-8')
        key = Fernet.generate_key()
        with open("symmetric.key", "wb") as fo:
            fo.write(key)
        f = Fernet(key)
        encrypted_email = f.encrypt(email)
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO accounts (username, password, email) VALUES (%s, %s, %s)', (username, hashpwd, encrypted_email,))
        mysql.connection.commit()
        msg = 'You have successfully registered!'
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('registration.html', msg=msg)


@app.route('/MyWebApp/home')
def home():
    if 'loggedin' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('secure_login'))


@app.route('/MyWebApp/profile')
def profile():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        encrypted_email = account['email'].encode()
        with open('symmetric.key', 'rb') as file:
            key = file.read()
        f = Fernet(key)
        decrypted_email = f.decrypt(encrypted_email).decode()
        account['email'] = decrypted_email
        return render_template('profile.html', account=account)
    return redirect(url_for('secure_login'))


# vulnerable update
@app.route('/vulnerable_update', methods=['GET', 'POST'])
def vulnerable_update():
    msg = ''
    if request.method == 'POST' and 'id' in request.form and 'username' in request.form:
        user_id = request.form['id']
        username = request.form['username']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        # Vulnerable query allowing SQL injection
        query = f"UPDATE accounts SET username = '{username}' WHERE id = '{user_id}'"
        cursor.execute(query)
        mysql.connection.commit()
        msg = 'Account updated successfully (via SQL injection)!'

    return render_template('vulnerable_update.html', msg=msg)

#delete
@app.route('/vulnerable_delete', methods=['GET', 'POST'])
def vulnerable_delete():
    msg = ''
    if request.method == 'POST' and 'id' in request.form:
        user_id = request.form['id']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        # Vulnerable query allowing SQL injection
        query = f"DELETE FROM accounts WHERE id = '{user_id}'"
        cursor.execute(query)
        mysql.connection.commit()
        msg = 'Account deleted successfully (via SQL injection)!'

    return render_template('vulnerable_delete.html', msg=msg)

@app.route('/vulnerable_insert', methods=['GET', 'POST'])
def vulnerable_insert():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        # Vulnerable query allowing SQL injection
        query = f"INSERT INTO accounts (username, password, email) VALUES ('{username}', '{password}', '{email}')"
        cursor.execute(query)
        mysql.connection.commit()
        msg = 'Account inserted successfully (via SQL injection)!'

    return render_template('vulnerable_insert.html', msg=msg)


if __name__ == '__main__':
    app.run(debug=True)
