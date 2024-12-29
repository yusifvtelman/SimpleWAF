import sqlite3

def init_db(db_name='waf.db'):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_ip TEXT,
        message TEXT NOT NULL,
        IsMalicious BOOLEAN,           
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    conn.commit()
    conn.close()

    print(f"Database '{db_name}' and table 'logs' created successfully.")

if __name__ == "__main__":
    init_db()  