import sqlite3
import os
import subprocess

# Load credentials from environment variables
USERNAME = os.getenv("DB_USERNAME", "default_username")
PASSWORD = os.getenv("DB_PASSWORD", "default_password")

def connect_db():
    """Connect to the SQLite database"""
    return sqlite3.connect("users.db")

def create_table():
    """Create the users table if it does not exist"""
    with connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        conn.commit()

def add_user(username, password):
    """Secure: Adding a user using parameterized queries"""
    with connect_db() as conn:
        cursor = conn.cursor()
        query = "INSERT INTO users (username, password) VALUES (?, ?)"
        cursor.execute(query, (username, password))
        conn.commit()

def get_user(username):
    """Secure: Fetching a user using parameterized queries"""
    with connect_db() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
    return user

def execute_command(cmd):
    """Secure: Executing system commands with validation"""
    allowed_commands = ["ls", "pwd"]  # Example of allowed commands

    if cmd.split()[0] in allowed_commands:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(result.stdout)
    else:
        print("Command not allowed")

# Execute functions
create_table()
add_user("test_user", "1234")
user = get_user("test_user")

if user:
    print(f"User found: {user}")

# Executing an external command (secured)
user_input = input("Enter a command to run: ")
execute_command(user_input)
