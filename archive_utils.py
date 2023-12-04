import requests
import sqlitedict
from datetime import datetime, timezone

def request_via_internet(url):
    response = requests.get(url)
    response.headers.pop("Content-Encoding", None)
    # Flask adds another Date header, so get rid of it
    response.headers["Date"] = ",".join(response.headers["Date"].split(",")[0:2])

    timestamp = datetime.strptime(response.headers["Date"], "%a, %d %b %Y %H:%M:%S %Z")

    return response, timestamp

def archive(url, timestamp, webpage, db_file):
        db = sqlitedict.SqliteDict(db_file)
        
        if url not in db:
            db[url] = { timestamp: webpage }
        else:
            url_archives = db[url]
            url_archives[timestamp] = webpage
            db[url] = url_archives

        db.commit()
        db.close()

def now_timestamp_ms():
     return int(datetime.now(timezone.utc).timestamp() * 1000)

def datetime_to_posix_timestamp(date):
    return int(date.timestamp()).to_bytes(length=4)
