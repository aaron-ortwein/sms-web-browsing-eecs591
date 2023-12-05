import os
import subprocess
import base64

import sqlitedict
from flask import Flask, request
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from archive_utils import archive, request_via_internet, now_timestamp_ms

SERVER_DEVICE_ID = ""
CHALLENGE_RESPONSE_TIMEOUT_MS = 30000

app = Flask(__name__)

@app.route('/')
def serve():
    url = request.args.get("url")
    response, timestamp = request_via_internet(url)
    archive(url, timestamp, response.content, "server_archives.db")

    return response.content, response.status_code, response.headers.items()

@app.route('/kex')
def key_exchange():
    client_number = int(request.args.get("phone"))
    encrypted_symmetric_key = base64.b64decode(request.args.get("key"), altchars=b"_-")

    with open("server_private_key.pem", "rb") as file:
        private_key = load_pem_private_key(file.read(), password=None)
    symmetric_key = private_key.decrypt(encrypted_symmetric_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

    # server should send the client a challenge text to ensure it owns the number it claims to
    challenge = int.from_bytes(os.urandom(8))
    challenge_start = now_timestamp_ms()
    os.system(f'adb -s {SERVER_DEVICE_ID} shell service call isms 5 i32 1 s16 "com.android.mms.service" s16 "null" s16 "{client_number}" s16 "null" s16 "\'{challenge}\'" s16 "null" s16 "null" i32 1 i64 0')
    
    while True:
        if challenge_start + CHALLENGE_RESPONSE_TIMEOUT_MS < now_timestamp_ms():
            return "Timeout waiting for challenge response"
        print(client_number)
        
        response = subprocess.run(
                ["adb", "-s", SERVER_DEVICE_ID, "shell", "content", "query", "--uri", "content://sms/inbox", "--projection", "body", "--where", f"\"address=\'+{client_number}\' and date >= {challenge_start}\"", "|", 
                 "cut", "-d", "=", "-f", "2"], capture_output=True)
        smses = str(response.stdout, encoding="utf-8").split("\n")[:-1]
        
        try:
            smses.remove("No result found.")
        except ValueError:
            pass

        if smses:
            break

    if int(smses[0]) != challenge:
        return "Error: challenge response is incorrect"
    
    db = sqlitedict.SqliteDict("client_keys.db")
    db[client_number] = symmetric_key
    db.commit()
    db.close()

    return "Key received OK"

if __name__ == "__main__":
    app.run()
