import sqlite3

tables = '''CREATE TABLE IF NOT EXISTS log (
    pps INTEGER,
    pid INTEGER,
    proto TEXT,
    targets INTEGER,
    rate TEXT,
    filename TEXT,
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);'''

class TraceLog:
    def __init__(self, filename, pps=None, pid=None, proto=None, targets=None, rate=None, output=None):
        self.filename = filename
        self.pps = pps
        self.pid = pid
        self.proto = proto
        self.targets = targets
        self.rate = rate
        self.output = output
        con = sqlite3.connect(filename)
        cur = con.cursor()
        cur.executescript(tables)
        con.commit()
        cur.close()
        con.close()

    def write(self):
        con = sqlite3.connect(self.filename)
        cur = con.cursor()
        cur.execute(
            'INSERT INTO log (pps, pid, proto, targets, rate, filename) VALUES (:pps, :pid, :proto, :targets, :rate, :filename)',
            {'pps': self.pps, 'pid': self.pid, 'proto': self.proto, 'targets': self.targets, 'rate': self.rate, 'filename': self.output}
        )
        con.commit()
        cur.close()
        con.close()
