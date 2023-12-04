import os
import requests
import base64
import argparse
from datetime import datetime

import sqlitedict
import xdelta3
import brotli
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from node import Endpoint
from archive_utils import archive, request_via_internet, now_timestamp_ms, datetime_to_posix_timestamp
from protocol import *

CLIENT_PHONE_NUMBER = "0123456789"
SERVER_PHONE_NUMBER = "0123456789"
SERVER_URL = "http://localhost:5000"
LOCK_FILE = "client.lock"
SYMMETRIC_KEY_FILE = "sms_client_key.key"
ARCHIVE_FILE = "client_archives.db"

class SMSClient(Endpoint):
    def get_symmetric_key(self, address):
        with open(SYMMETRIC_KEY_FILE, "rb") as file:
            return file.read()

    def request(self, url):
        if os.path.exists(LOCK_FILE):
            print("Client can only make one request at a time")
            return
        
        db = sqlitedict.SqliteDict("client_archives.db")
        # Don't allow client to request non-cached pages, it's too much data
        assert url in db
        latest_timestamp = max(db[url].keys())
        latest_webpage_archive = db[url][latest_timestamp]
        db.close()

        open(LOCK_FILE, "w").close()

        try:
            request_start = now_timestamp_ms()
            self.send_handler(SERVER_PHONE_NUMBER, 
                            request_start, 
                            datetime_to_posix_timestamp(latest_timestamp) + bytes(url, "utf-8"), 
                            int(CLIENT_PHONE_NUMBER),
                            MessageType.REQ,
                            MessageType.RSP_ACK,
                            MessageType.RSP,
                            retransmit_timeout_override=5)
            print("Server received request, listening for response...")
            response_start = now_timestamp_ms()
            message, _ = self.recv_handler(SERVER_PHONE_NUMBER, request_start, MessageType.RSP, MessageType.REQ_ACK)

            if b"error" not in message:
                # apply delta and archive
                server_timestamp, data = datetime.fromtimestamp(int.from_bytes(message[:4])), message[4:]
                delta = brotli.decompress(data)
                current_webpage = xdelta3.decode(latest_webpage_archive, delta)
                archive(url, server_timestamp, current_webpage, "client_archives_2.db")
                end = now_timestamp_ms()
                print(f"Bytes Received: {len(data)} | Delta Size (Bytes): {len(delta)} | Current Webpage Size (Bytes): {len(current_webpage)}")
                print(f"End-to-end time: {end - request_start} ms")
                print(f"Response time: {end - response_start} ms")
                print(f"Transmission Rate: {len(data) / ((end - response_start) / 1000)} bytes/s")
        finally:
            os.remove(LOCK_FILE)

class WebClient():
    def key_exchange(self):
        if not os.path.exists(SYMMETRIC_KEY_FILE):
            with open(SYMMETRIC_KEY_FILE, "wb") as file:
                file.write(os.urandom(16))
        with open(SYMMETRIC_KEY_FILE, "rb") as file:
            symmetric_key = file.read()
        with open("server_public_key.pub", "rb") as file:
            server_public_key = load_pem_public_key(file.read())
        
        encrypted_symmetric_key = server_public_key.encrypt(symmetric_key, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
        encoded_encrypted_symmetric_key = str(base64.b64encode(encrypted_symmetric_key, altchars=b"_-"), "utf-8")
        
        response = requests.get(f"{SERVER_URL}/kex?phone={CLIENT_PHONE_NUMBER}&key={encoded_encrypted_symmetric_key}")
        print(response.content)

    def request(self, url):
        response, timestamp = request_via_internet(f"{SERVER_URL}/?url={url}")
        archive(url, timestamp, response.content, "client_archives_eval.db")

def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="server")

    subparsers.add_parser("kex", help="Generates and sends a symmetric key to use for all SMS communications to the server.")

    sms_parser = subparsers.add_parser("sms", help="Requests the URL of an already-archived page over SMS and retrieves only the delta between the most recent archive and the current version.")
    sms_parser.add_argument("url", help="the URL to be requested from the SMS server")
    
    web_parser = subparsers.add_parser("web", help="Requests the URL of a webpage and archives the response.")
    web_parser.add_argument("url", help="the URL to be requested from the web server")

    args = parser.parse_args()
    
    if args.server == "kex":
        client = WebClient()
        client.key_exchange()
    else:
        if args.server == "web":
            client = WebClient()
        elif args.server == "sms":
            client = SMSClient()
    
        client.request(args.url)

if __name__ == "__main__":
    main()
