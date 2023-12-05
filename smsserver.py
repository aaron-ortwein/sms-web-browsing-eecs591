import os
import threading
import subprocess
import re
from datetime import datetime

import sqlitedict
import xdelta3
import brotli
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cachetools import TTLCache

from node import Endpoint
from archive_utils import archive, request_via_internet, datetime_to_posix_timestamp
from protocol import *

SERVER_DEVICE_ID = ""

class Server(Endpoint):
    def __init__(self):
        if not os.path.exists("server_private_key.pem"):
            with open("server_private_key.pem", "wb") as file:
                private_key = generate_private_key(public_exponent=65537, key_size=2048)
                file.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
            with open("server_public_key.pub", "wb") as file:
                public_key = private_key.public_key()
                file.write(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

        self.device_id = SERVER_DEVICE_ID
        self.active_requests_from = set()
        self.lock = threading.Lock()
        self.ttl_cache = TTLCache(maxsize=10000, ttl=REQUEST_TIMEOUT)
    
    def get_device_id(self):
        return self.device_id

    def get_symmetric_key(self, address):
        db = sqlitedict.SqliteDict("client_keys.db")
        key = db[address]
        db.close()
        return key

    def poll(self):
        # poll for messages from new addresses and start request handler
        previous_result = None
        while True:
            # if we were using two phones, uri should be content://sms/inbox
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "content", "query", "--uri", "content://sms", "--projection", "address:date:body"],
                capture_output=True)
            lines = str(result.stdout, encoding="utf-8").split("\n")[:-1]
            num_lines = len(lines)

            if previous_result and num_lines > previous_result:
                new_lines = lines[:(num_lines - previous_result)]
                requests = []
                for line in new_lines:
                    body = re.search("body=(.+)", line).group(1)
                    _, _, src_phone, message_type, _ = self.decrypt_sms(body)
                    if message_type == MessageType.REQ:
                        requests.append(line)
                        
                        address = re.search("address=(\+?\d+)", line).group(1)
                        request_timestamp = re.search("date=(\d+)", line).group(1)
                    
                        with self.lock:
                            # use TTLCache to prevent server from spawning new threads to service retransmissions
                            if address not in self.active_requests_from and (src_phone, body) not in self.ttl_cache.keys():
                                self.active_requests_from.add(address)
                                self.ttl_cache[(src_phone, body)] = None # dummy value, we just want TTLCache to function as a set
                                print(f"Spawning request handler thread for {address}")
                                thread = threading.Thread(target=self.service_message, args=(address, request_timestamp))
                                thread.start()
            
            previous_result = num_lines

    def service_message(self, address, date):
        try:
            message, request_originator = self.recv_handler(address, date, MessageType.REQ, MessageType.RSP_ACK)
            print(message)
            
            client_timestamp, url = datetime.fromtimestamp(int.from_bytes(message[:4])), str(message[4:], "utf-8")
            webserver_response, timestamp = request_via_internet(url)
            if webserver_response.status_code == 200:
                archive(url, timestamp, webserver_response.content, "server_archives.db")
                db = sqlitedict.SqliteDict("server_archives.db")
                client_page_version = db[url][client_timestamp]
                db.close()
                try:
                    sms_response = datetime_to_posix_timestamp(timestamp) + brotli.compress(xdelta3.encode(client_page_version, webserver_response.content))
                except xdelta3.NoDeltaFound:
                    sms_response = b"error"
            else:
                sms_response = b"error"

            self.send_handler(address, date, sms_response, request_originator, MessageType.RSP, MessageType.REQ_ACK)
        finally:
            with self.lock:
                self.active_requests_from.remove(address)

if __name__ == "__main__":
    server = Server()
    server.poll()
