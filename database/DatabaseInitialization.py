# db_init.py
import os
import sys
import psycopg2

def initialize_database():
    """
    Connects to the Azure PostgreSQL database using environment variables
    and runs the x3dh_init.sql script ONLY if the database is empty.
    """
    
    # 1. Load Configuration from Environment Variables (Azure App Settings)
    db_host = os.environ.get("DB_HOST")
    db_name = os.environ.get("DB_NAME")
    db_user = os.environ.get("DB_USER")
    db_password = os.environ.get("DB_PASSWORD")
    db_port = os.environ.get("DB_PORT", "5432")

    # If credentials aren't set, assume local config or manual setup and skip.
    if not all([db_host, db_name, db_user, db_password]):
        print("[DB Init] Missing DB_HOST/NAME/USER/PASSWORD environment variables. Skipping auto-init.")
        # Exit 0 so the server can still attempt to start (e.g. using database.ini locally)
        sys.exit(0)

    conn = None
    try:
        # 2. Connect to the Database
        # Azure Database for PostgreSQL requires sslmode='require'
        print(f"[DB Init] Connecting to {db_name} at {db_host}...")
        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password,
            port=db_port,
            sslmode='require'
        )
        conn.autocommit = False
        cur = conn.cursor()

        # 3. Check if the database is already initialized
        # We check for the existence of the 'user_info' table (standard Postgres is lowercase)
        cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'user_info'
            );
        """)
        is_initialized = cur.fetchone()[0]

        if is_initialized:
            print("[DB Init] Tables already exist. Skipping initialization to PREVENT DATA LOSS.")
        else:
            # 4. Execute the SQL Script
            script_dir = os.path.dirname(os.path.abspath(__file__))
            sql_file_path = os.path.join(script_dir, 'x3dh_init.sql')
            
            print(f"[DB Init] Tables not found. Executing schema from: {sql_file_path}")
            
            if not os.path.exists(sql_file_path):
                print(f"[DB Init] Critical Error: SQL file not found at {sql_file_path}")
                sys.exit(1)

            with open(sql_file_path, 'r') as f:
                sql_content = f.read()

            cur.execute(sql_content)
            conn.commit()
            print("[DB Init] Database initialized successfully.")

    except psycopg2.Error as e:
        print(f"[DB Init] Database Error: {e}")
        # Exit with status 1 to stop the Procfile chain (don't start server if DB is broken)
        sys.exit(1)
    except Exception as e:
        print(f"[DB Init] Unexpected Error: {e}")
        sys.exit(1)
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    initialize_database()
