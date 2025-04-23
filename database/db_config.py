import mysql.connector
from mysql.connector import Error
from config import Config

def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=Config.DB_HOST,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            database=Config.DB_NAME
        )
        return connection
    except Error as e:
        print(f"Error connecting to MySQL database: {e}")
        return None

def execute_query(query, params=None):
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute(query, params)
            connection.commit()
            return cursor
        except Error as e:
            print(f"Error executing query: {e}")
            return None
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()
    return None

def fetch_all(query, params=None):
    cursor = execute_query(query, params)
    if cursor:
        result = cursor.fetchall()
        return result
    return []

def fetch_one(query, params=None):
    cursor = execute_query(query, params)
    if cursor:
        result = cursor.fetchone()
        return result
    return None

def insert_data(query, params=None):
    cursor = execute_query(query, params)
    if cursor:
        return cursor.lastrowid
    return None

def update_data(query, params=None):
    cursor = execute_query(query, params)
    if cursor:
        return cursor.rowcount
    return 0

def delete_data(query, params=None):
    cursor = execute_query(query, params)
    if cursor:
        return cursor.rowcount
    return 0