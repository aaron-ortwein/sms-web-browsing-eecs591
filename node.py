import os
import subprocess
import base64
from datetime import datetime, timezone, timedelta
from abc import ABC, abstractmethod

import numpy
from BitVector import BitVector
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from protocol import *

def bitvector_as_bytes(bitvector):
    return b''.join([int(bitvector[i:(i + 8)]).to_bytes() for i in range(0, len(bitvector), 8)])

class Node(ABC):
    def send_sms(self, address, message):
        # assumes SIM card is in second slot of dual-SIM phone
        # also this is undocumented and may break for other versions of android since function signature can change ; this works for Android 12 and 13
        os.system(f'adb shell service call isms 5 i32 1 s16 "com.android.mms.service" s16 "null" s16 "{address}" s16 "null" s16 "\'{message}\'" s16 "null" s16 "null" i32 1 i64 0')

class Endpoint(Node, ABC):
    @abstractmethod
    def get_symmetric_key(self, address):
        raise NotImplementedError()
    
    def send_data(self, address, data, message_type, request_originator):
        send_buffer = []

        payloads = [data[i:(i + MAX_PAYLOAD_LEN)] for i in range(0, len(data), MAX_PAYLOAD_LEN)]
        for i, payload in enumerate(payloads):
            header = BitVector(size = HEADER_BITS)
            header[0:SEQ_NUMBER_BITS] = BitVector(intVal = i + 1, size = SEQ_NUMBER_BITS)
            header[SEQ_NUMBER_BITS:(SEQ_NUMBER_BITS + LAST_SEQ_NUMBER_BITS)] = BitVector(intVal = len(payloads), size = LAST_SEQ_NUMBER_BITS)
            header[(SEQ_NUMBER_BITS + LAST_SEQ_NUMBER_BITS):(SEQ_NUMBER_BITS + LAST_SEQ_NUMBER_BITS + SRC_PHONE_BITS)] = BitVector(intVal = request_originator, size = SRC_PHONE_BITS)
            header[(SEQ_NUMBER_BITS + LAST_SEQ_NUMBER_BITS + SRC_PHONE_BITS):(SEQ_NUMBER_BITS + LAST_SEQ_NUMBER_BITS + SRC_PHONE_BITS + TYPE_BITS)] = BitVector(intVal = int(message_type), size = TYPE_BITS)
            nonce = os.urandom(NONCE_BYTES)
            header_as_bytes = b''.join([int(header[i:(i + 8)]).to_bytes() for i in range(0, len(header), 8)])
            key = self.get_symmetric_key(request_originator)
            ciphertext = AESGCM(key).encrypt(nonce, payload, associated_data=(header_as_bytes + nonce))
            message = str(base64.b64encode(header_as_bytes + nonce + ciphertext).replace(b'/', b' ').replace(b'+', b'.').replace(b'=', b'?'), "utf-8")

            send_buffer.append(message)
            self.send_sms(address, message)
        
        return send_buffer
    
    def decrypt_sms(self, sms):
        message = base64.b64decode(sms.replace(' ', '/').replace('.', '+').replace('?', '='))
        header = message[0:(HEADER_BITS // 8)]
        nonce = message[(HEADER_BITS // 8):((HEADER_BITS // 8) + NONCE_BYTES)]
        ciphertext = message[((HEADER_BITS // 8) + NONCE_BYTES):]

        header_as_bitvector = BitVector(rawbytes = header)
        sequence_number = int(header_as_bitvector[0:SEQ_NUMBER_BITS])
        total_messages = int(header_as_bitvector[SEQ_NUMBER_BITS:(SEQ_NUMBER_BITS + LAST_SEQ_NUMBER_BITS)])
        src_phone_number = int(header_as_bitvector[(SEQ_NUMBER_BITS + LAST_SEQ_NUMBER_BITS):(SEQ_NUMBER_BITS + LAST_SEQ_NUMBER_BITS + SRC_PHONE_BITS)])
        message_type = int(header_as_bitvector[(SEQ_NUMBER_BITS + LAST_SEQ_NUMBER_BITS + SRC_PHONE_BITS):(SEQ_NUMBER_BITS + LAST_SEQ_NUMBER_BITS + SRC_PHONE_BITS + TYPE_BITS)])

        key = self.get_symmetric_key(src_phone_number)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, associated_data=(header + nonce))        
        
        return (sequence_number, total_messages, src_phone_number, message_type, plaintext)
        
    def send_handler(self, address, date, data, request_originator, send_type, ack_type, recv_type=None, retransmit_timeout_override=None):
        start_timestamp = datetime.now(timezone.utc)
        send_buffer = self.send_data(address, data, send_type, request_originator)
        previous_ack = None
        previous_ack_timestamp = None
        previous_retransmission_timestamp = None
        other_recv_all_data = False

        def retransmit():
            for i, sms in enumerate(send_buffer):
                if not previous_ack or not previous_ack[i]:
                    print(f"Retransmitting message fragment {i}")
                    self.send_sms(address, sms)

        previous_result = 0
        while not other_recv_all_data:
            result = subprocess.run(
                ["adb", "shell", "content", "query", "--uri", "content://sms", "--projection", "body", "--where", f"\"address=\'{address}\' and date >= {date}\"", "--sort", "\"date DESC\"", "|", 
                 "cut", "-d", "=", "-f", "2"],
                capture_output=True)
            smses = str(result.stdout, encoding="utf-8").split("\n")[:-1]
            try:
                smses.remove("No result found.")
            except ValueError:
                pass
            num_smses = len(smses)

            if num_smses > previous_result:
                new_smses = smses[:(num_smses - previous_result)]
                for sms in new_smses:
                    try:
                        _, _, _, message_type, plaintext = self.decrypt_sms(sms)
                        if message_type == ack_type:
                            ack = BitVector(rawbytes=plaintext)
                            if not previous_ack or previous_ack.count_bits() < ack.count_bits():
                                print("Received ack")
                                previous_ack = ack
                                previous_ack_timestamp = datetime.now(timezone.utc)
                                other_recv_all_data = previous_ack.count_bits() == len(send_buffer)
                        elif message_type == recv_type:
                            other_recv_all_data = True
                            break
                        else:
                            continue
                    except InvalidTag:
                        continue

            now = datetime.now(timezone.utc)
            
            if start_timestamp + timedelta(seconds=REQUEST_TIMEOUT) < now:
                raise TimeoutError
            elif start_timestamp + timedelta(seconds=(len(send_buffer) * PER_MESSAGE_DELIVERY_TIME if not retransmit_timeout_override else retransmit_timeout_override)) < now:
                expected_completion_time = int(((len(send_buffer) - previous_ack.count_bits()) if previous_ack else len(send_buffer)) * PER_MESSAGE_DELIVERY_TIME)
                if (previous_retransmission_timestamp is None or
                    previous_ack_timestamp is None and previous_retransmission_timestamp + timedelta(seconds=expected_completion_time) < now or 
                    previous_ack_timestamp and previous_ack_timestamp + timedelta(seconds=expected_completion_time) < now):
                    retransmit()
                    previous_retransmission_timestamp = now

            previous_result = num_smses

    def recv_handler(self, address, date, recv_type, ack_type):
        start_timestamp = datetime.now(timezone.utc)
        recv_buffer = None
        request_originator = None
        expected_completion_duration = None
        previous_ack_timestamp = None

        def send_ack():
            ack_as_bitstring = ''.join(list(map(lambda fragment: '1' if fragment else '0', recv_buffer)))
            ack_as_bitvector = BitVector(bitstring=ack_as_bitstring)

            n = len(ack_as_bitvector)
            num_padding_bits = 8 - (n % 8)
            ack_as_bitvector += BitVector(size=num_padding_bits)

            ack_as_bytes = bitvector_as_bytes(ack_as_bitvector)
            
            assert len(ack_as_bytes) <= MAX_PAYLOAD_LEN
            print(f"Acknowledging message fragments: {[i for i, bit in enumerate(ack_as_bitvector) if bit]}")
            self.send_data(address, ack_as_bytes, ack_type, request_originator)
            return datetime.now(timezone.utc)

        previous_result = 0
        while recv_buffer is None or not all(recv_buffer):
            # if we were using two phones, uri should be content://sms/inbox
            result = subprocess.run(
                ["adb", "shell", "content", "query", "--uri", "content://sms", "--projection", "body", "--where", f"\"address=\'{address}\' and date >= {date}\"", "--sort", "\"date DESC\"", "|", 
                 "cut", "-d", "=", "-f", "2"],
                capture_output=True)
            smses = str(result.stdout, encoding="utf-8").split("\n")[:-1]
            
            try:
                smses.remove("No result found.")
            except ValueError:
                pass
            num_smses = len(smses)

            now = datetime.now(timezone.utc)
           
            if num_smses > previous_result:
                new_smses = smses[:(num_smses - previous_result)]
                for sms in new_smses:
                    try:
                        sequence_number, total_messages, src_phone_number, message_type, plaintext = self.decrypt_sms(sms)
                        #print(sequence_number, total_messages, src_phone_number, message_type, plaintext)
                        if message_type == recv_type:
                            if recv_buffer is None:
                                recv_buffer = numpy.empty(total_messages, dtype=object)
                                request_originator = src_phone_number
                                expected_completion_duration = total_messages * PER_MESSAGE_DELIVERY_TIME
                    
                            if not recv_buffer[sequence_number - 1]:
                                #print(f"Received message: {plaintext}")
                                recv_buffer[sequence_number - 1] = plaintext
                                print(f"{len(recv_buffer) - list(recv_buffer).count(None)} / {len(recv_buffer)} messages received")

                            if all(recv_buffer):
                                print("Sending ACK")
                                previous_ack_timestamp = send_ack()
                                break
                        else:
                            continue
                    except InvalidTag:
                        continue

            # if we have not received all of the data before the request timeout, give up
            if start_timestamp + timedelta(seconds=REQUEST_TIMEOUT) < now:
                raise TimeoutError
            elif expected_completion_duration and start_timestamp + timedelta(seconds=expected_completion_duration) < now:
                if previous_ack_timestamp is None or previous_ack_timestamp + timedelta(seconds=list(recv_buffer).count(None) * PER_MESSAGE_DELIVERY_TIME) < now:
                    previous_ack_timestamp = send_ack()

            previous_result = num_smses
        
        print("Finished receiving data")
        return b''.join(recv_buffer), request_originator
