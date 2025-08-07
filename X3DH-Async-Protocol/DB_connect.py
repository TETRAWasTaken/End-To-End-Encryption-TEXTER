from configparser import ConfigParser
import psycopg2

"""
This file contains the utility to connect to the postgres database
and perform certain sql queries.
"""
class DB_connect:
    def __init__(self):
        self.pool = None
        self._connect() # Call the internal connection method during initialization

    def load_config(self, filename: object = 'database.ini', section: object = 'postgresql') -> dict:
        """ Load database configuration from file """

        parser = ConfigParser()
        parser.read(filename)

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
        Connect to the PostgreSQL database server and store the connection.
        This connection will remain open until explicitly closed by the class instance.
        """

        try:
            self.pool = psycopg2.pool.ThreadedConnectionPool(dsn = self.load_config(),
                                                             minconn = 1,
                                                             maxconn = 10
                                                             )
            print("Connection Pooling to PostgreSQL DB successful")

        except (psycopg2.DatabaseError, Exception) as e:
            print(f"Error {e} occurred while connecting to PostgreSQL DB")
            self.pool = None

    def closeall(self):
        """ Closes the database connection if it is open. """
        if self.pool:
            self.pool.closeall()
            print("Connection to PostgreSQL DB closed.")
            self.pool = None

if __name__ == '__main__':
    # Create an instance of DB_connect
    db_instance = DB_connect()
    conn = db_instance.pool.getconn()
