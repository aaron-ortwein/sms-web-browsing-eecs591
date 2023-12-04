from enum import IntEnum

class MessageType(IntEnum):
    KEX = 0
    DATA = 1
    ACK = 2

    # debugging types to distinguish client and server messages when testing 
    # using one phone (although works with two)
    REQ = 3
    RSP = 4
    REQ_ACK = 5
    RSP_ACK = 6

MAX_PAYLOAD_LEN = 84
HMAC_LEN = 16
SEQ_NUMBER_BITS = 8
LAST_SEQ_NUMBER_BITS = 8
SRC_PHONE_BITS = 44
TYPE_BITS = 4
HEADER_BITS = SEQ_NUMBER_BITS + LAST_SEQ_NUMBER_BITS + SRC_PHONE_BITS + TYPE_BITS
NONCE_BYTES = 12

REQUEST_TIMEOUT = 600
PER_MESSAGE_DELIVERY_TIME = 0.5
