from configparser import ConfigParser
import psycopg2
from psycopg2 import pool  # Explicitly import the pool module
import os

"""
This file contains the utility to connect to the postgres database
and perform certain sql queries.
"""


class DB_connect:
    def __init__(self):
        self.pool = None
        self._connect()  # Call the internal connection method during initialization

    def load_config(self, filename: str = 'database.ini', section: str = 'postgresql') -> dict:
        """
        Load database configuration from the file
        :param filename: name of the configuration file
        :param section: section of database configuration
        :return: a dictionary of database parameters
        """

        parser = ConfigParser()
        if not parser.read(filename):
            raise Exception(f"Configuration file '{filename}' not found or is empty.")

        config = {}
        if parser.has_section(section):
            params = parser.items(section)
            for param in params:
                config[param[0]] = param[1]
        else:
            raise Exception(f'Section {section} not found in the {filename} file')

        return config

    def _connect(self):
        """
        Connect to the PostgreSQL database server and create a connection pool.
        Prioritizes Environment Variables (for Azure), falls back to database.ini (local).
        """
        try:
            # Check if we are running in an environment with DB config (like Azure)
            if os.environ.get("DB_HOST"):
                print("Connecting using Environment Variables...")
                self.pool = pool.ThreadedConnectionPool(
                    minconn=1,
                    maxconn=10,
                    host=os.environ.get("DB_HOST"),
                    database=os.environ.get("DB_NAME"),
                    user=os.environ.get("DB_USER"),
                    password=os.environ.get("DB_PASSWORD"),
                    port=os.environ.get("DB_PORT", "5432"),
                    sslmode="require"  # Azure PostgreSQL requires SSL
                )
            else:
                # Fallback for local development
                print("Connecting using database.ini...")
                config_params = self.load_config()
                self.pool = pool.ThreadedConnectionPool(minconn=1, maxconn=10, **config_params)

        except (psycopg2.DatabaseError, Exception) as e:
            print(f"Error occurred while connecting to PostgreSQL DB: {e}")
            self.pool = None

    def closeall(self):
        """
        Closes all connections in the pool.
        :return: None
        """

        if self.pool:
            self.pool.closeall()
            print("Connection pool to PostgreSQL DB closed.")
            self.pool = None



"""
Test code for the class, this will be executed when the file is run directly.
This is not recommended for production use.
"""
if __name__ == '__main__':
    # Create an instance of DB_connect
    db_instance = DB_connect()

    # Check if the connection pool was successfully created before using it
    if db_instance.pool:
        conn = None
        try:
            # Get a connection from the pool to test
            print("Attempting to get a connection from the pool...")
            conn = db_instance.pool.getconn()
            print("Successfully retrieved a connection from the pool.")

            # It's good practice to perform a simple query to verify the connection is live
            with conn.cursor() as cur:
                cur.execute('SELECT version();')
                db_version = cur.fetchone()
                print(f"Database connection verified. Version: {db_version[0]}")

        except (psycopg2.Error, Exception) as e:
            print(f"An error occurred while using the connection: {e}")

        finally:
            # Return the connection to the pool if it was acquired
            if conn:
                db_instance.pool.putconn(conn)
                print("Connection returned to the pool.")
            # Close all connections in the pool when the script is done
            db_instance.closeall()
    else:
        print("Failed to create a database connection pool. Please check configuration and database status.")