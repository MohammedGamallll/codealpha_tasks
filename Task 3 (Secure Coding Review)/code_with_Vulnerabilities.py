import sqlite3
import os

# Hardcoded credentials (not secure)
USERNAME = "admin"
PASSWORD = "password123"

def connect_db():
    """Connect to the SQLite database"""
    return sqlite3.connect("users.db")

def create_table():
    """Create the users table if it does not exist"""
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.commit()
    conn.close()

def add_user(username, password):
    """Insecure: Adding a user using a vulnerable SQL query (SQL Injection risk)"""
    conn = connect_db()
    cursor = conn.cursor()
    
    # Vulnerable SQL query (prone to SQL Injection)
    query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
    cursor.execute(query)

    conn.commit()
    conn.close()

def get_user(username):
    """Insecure: Fetching a user using an unsafe SQL query"""
    conn = connect_db()
    cursor = conn.cursor()

    # Vulnerable SQL query (SQL Injection risk)
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()
    return user

def execute_command(cmd):
    """Insecure: Executing system commands without validation (Command Injection risk)"""
    os.system(cmd)

# Execute functions
create_table()
add_user("test_user", "1234")
user = get_user("test_user")

if user:
    print(f"User found: {user}")

# Executing an external command (Command Injection vulnerability)
user_input = input("Enter a command to run: ")
execute_command(user_input)
