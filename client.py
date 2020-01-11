#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Sat Jan 11 14:08:51 2020
# Author: January

import socket
import sys
import pickle
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("client")

class MsgType():
    REPLY = "reply"
    REPLICATE = "replicate"
    COMMIT = "commit"
    VIEW_CHANGE = "view-change"
    VC_FINAL = "vc-final"
    NEW_VIEW = "new-view"
    SUSPECT = "suspect"

## state
REPLY_WAITING = 1
REPLY_ERROR = 2
REPLY_OK = 3
##

ports = [10000, 10001, 10002, 10003]
addresses = (("127.0.0.1", 10000),("127.0.0.1", 10001), ("127.0.0.1", 10002), ("127.0.0.1", 10003))
signatures = ["client", "replica1", "replica2", "replica3"]

# self config
self_port = 10000
self_address = ("127.0.0.1", 10000)
signature = "client"
self_id = 0
# protocal data
primary = 1
follower = 2
timestamp = 0
# protocal config
tmot = 2
#

def bind_port():
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.bind(self_address)
    return sk

def digest(data):
        return pickle.dumps(data)

def sign(data):
    return signature

def verify(msg, sig, id):
    if sig == signatures[id]:
        return True
    else:
        return False

def pack_op(op):
    return int(op)

def verify_reply(reply):
    print(reply)
    msg_type, p_reply, msg_f = reply
    p_reply_body = p_reply[:-1]
    sn_p, view_p, ts_p, rep_p, sig_p = p_reply[1:]

    msg_f_body = msg_f[:-1]
    d_req_f, sn_f, view_f, ts_f, d_rep_f, sig_f = msg_f[1:]
    msg_f_sig = msg_f[-1]
    if not (verify(p_reply_body, sig_p, primary) and verify(msg_f_body, sig_f, follower)):
        logger.debug("signature invalid")
        return REPLY_ERROR

    if not (sn_p == sn_f and view_p == view_f and ts_p == ts_f and ts_p == timestamp and digest(rep_p) == d_rep_f):
        logger.debug("reply invalid")
        return REPLY_ERROR
    print("reply is {reply}".format(reply = rep_p))
    return REPLY_OK

def request(sk:socket.socket, op):
    # req = [REPLICATE, op, ts, c]
    req = [MsgType.REPLICATE, pack_op(op), 0, self_id]
    req.append(sign(req))
    sk.sendto(pickle.dumps(req), addresses[1])
    sk.settimeout(tmot)
    try:
        data, address = sk.recvfrom(4096)
        msg = pickle.loads(data)
        while True:
            result = verify_reply(msg)
            if result == REPLY_OK:
                print("ok")
                return True
            elif result == REPLY_ERROR:
                raise RuntimeError("ERROR REPLY")
            # 等待更多回复消息
    except Exception as e:
        print(e)
        print("timeout, start retransmission")
        return False

# main
self_sk = bind_port()
while True:
    try:
        op = input("Please input op:")
    except:
        exit(0)
    request(self_sk, op)
    
    
