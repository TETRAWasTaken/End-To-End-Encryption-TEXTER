from configparser import ConfigParser
import psycopg2
from psycopg2 import pool
import os

class DB_connect:
    """
    Manages a thread-safe connection pool to a PostgreSQL database.

    This class handles the configuration, connection, and pooling of database
    connections. It can be configured either through a `database.ini` file for
    local development or through environment variables for deployment
    environments like Azure.
    """
    def __init__(self):
        """
        Initializes the DB_connect instance and establishes the connection pool.
        """
        self.pool = None
        self._connect()

    def load_config(self, filename: str = 'database.ini', section: str = 'postgresql') -> dict:
        """
        Loads database configuration from an INI file.

        Args:
            filename: The name of the configuration file.
            section: The section within the INI file to read.

        Returns:
            A dictionary of database connection parameters.

        Raises:
            Exception: If the file or section is not found.
        """
        parser = ConfigParser()
        if not parser.read(filename):
            raise Exception(f"Configuration file '{filename}' not found or is empty.")

        if parser.has_section(section):
            return dict(parser.items(section))
        else:
            raise Exception(f'Section {section} not found in the {filename} file')

    def _connect(self):
        """
        Connects to the PostgreSQL database and creates a connection pool.

        This method prioritizes environment variables for configuration, which is
        suitable for cloud deployments like Azure. It falls back to using a
        `database.ini` file for local development.
        """
        try:
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
                    sslmode="require"
                )
            else:
                print("Connecting using database.ini...")
                config_params = self.load_config()
                self.pool = pool.ThreadedConnectionPool(minconn=1, maxconn=10, **config_params)
        except (psycopg2.DatabaseError, Exception) as e:
            print(f"Error occurred while connecting to PostgreSQL DB: {e}")
            self.pool = None

    def closeall(self):
        """
        Closes all connections in the pool and shuts down the pool.
        """
        if self.pool:
            self.pool.closeall()
            print("Connection pool to PostgreSQL DB closed.")
            self.pool = None

if __name__ == '__main__':
    db_instance = DB_connect()
    if db_instance.pool:
        conn = None
        try:
            print("Attempting to get a connection from the pool...")
            conn = db_instance.pool.getconn()
            print("Successfully retrieved a connection from the pool.")
            with conn.cursor() as cur:
                cur.execute('SELECT version();')
                db_version = cur.fetchone()
                print(f"Database connection verified. Version: {db_version[0]}")
        except (psycopg2.Error, Exception) as e:
            print(f"An error occurred while using the connection: {e}")
        finally:
            if conn:
                db_instance.pool.putconn(conn)
                print("Connection returned to the pool.")
            db_instance.closeall()
    else:
        print("Failed to create a database connection pool. Please check configuration and database status.")