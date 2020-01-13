#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Sat Jan 11 14:08:51 2020
# Author: January

import socket
import sys
import pickle
import logging
import hashlib
import _thread
import time

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
replica_amount = 3
ports = [10000, 10001, 10002, 10003]
addresses = (("127.0.0.1", 10000),("127.0.0.1", 10001), ("127.0.0.1", 10002), ("127.0.0.1", 10003))
signatures = ["client", "replica1", "replica2", "replica3"]


class Client():
    ## state
    REPLY_WAITING = 1
    REPLY_ERROR = 2
    REPLY_OK = 3
    ##
    def __init__(self):
        # self config
        self.address = ("127.0.0.1", 10000)
        self.signature = "client"
        self.id = 0
        # protocal data
        self.view = 0
        self.primary = 1
        self.follower = 2
        self.ts = 0
        self.request_complete = True
        #视图变更使用
        self.poss_view = 0
        self.new_view_msg_received = set()
        
        # protocal config
        self.tmot = 2
        #
        self.lock = _thread.allocate_lock()
        self.sk = sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sk.bind(self.address)

    def get_sync_group_address(self, view):
        choose = view % 3
        if choose == 0:
            sg = [addresses[1], addresses[2]]
        elif choose == 1:
            sg = [addresses[2], addresses[3]]
        else:
            sg = [addresses[3], addresses[1]]
        return sg
    
    def get_sync_group(self, view):
        choose = view % 3
        if choose == 0:
            sg = [1, 2]
        elif choose == 1:
            sg = [2, 3]
        else:
            sg = [3, 1]
        return sg

    def digest(self, data):
            md5 = hashlib.md5()
            bytes_data = pickle.dumps(data)
            md5.update(bytes_data)
            return md5.hexdigest()

    def sign(self,data):
        return (self.id, self.signature)

    def verify_msg(self, msg, id = -1):
        msg_body = msg[:-1]
        if id == -1:
            id, sig = msg[-1]
        else:
            sig = msg[-1][1]
        if sig == signatures[id]:
            return True
        else:
            return False

    def pack_op(self, op):
        return int(op)

    def verify_reply(self, reply):
        msg_type, p_reply, msg_f = reply
        p_reply_body = p_reply[:-1]
        sn_p, view_p, ts_p, rep_p, sig_p = p_reply[1:]

        msg_f_body = msg_f[:-1]
        d_req_f, sn_f, view_f, ts_f, d_rep_f, sig_f = msg_f[1:]
        msg_f_sig = msg_f[-1]
        if not (self.verify_msg(p_reply, self.primary) and self.verify_msg(msg_f, self.follower)):
            logger.debug("signature invalid")
            self.request_complete = True
            self.ts += 1
            return Client.REPLY_ERROR

        if not (sn_p == sn_f and view_p == view_f and ts_p == ts_f and ts_p == self.ts and self.digest(rep_p) == d_rep_f):
            logger.debug("reply invalid")
            self.request_complete = True
            self.ts += 1
            return Client.REPLY_ERROR
        print("reply is {reply}".format(reply = rep_p))
        self.request_complete = True
        self.ts += 1
        return Client.REPLY_OK

    def reply_timer(self, req):
        i = 0
        while i < 1:
            if self.request_complete == True:
                return
            i += 0.01
            time.sleep(0.01)
        print("req %s timeout"%(str(req)))

    def request(self, op):
        # req = [REPLICATE, op, ts, c]
        if self.request_complete == True:
            req = [MsgType.REPLICATE, self.pack_op(op), self.ts, self.id]
            req.append(self.sign(req))
            self.request_complete = False
            self.sk.sendto(pickle.dumps(req), addresses[self.primary])
            # start timer
            _thread.start_new_thread(self.reply_timer, (req,))
        else:
            print("last request not finish")
    
    def msg_handler(self, msg, sender):
        msg_type = msg[0]
        print(msg)
        if msg_type == MsgType.REPLY:
            self.verify_reply(msg)
        elif msg_type == MsgType.NEW_VIEW:
            self.lock.acquire()
            if self.verify_msg(msg) == False:
                print("Invalid new view message from %d"%(sender))
                self.lock.release()
                return
            if sender in self.new_view_msg_received:
                print("repeated new view msg from %d"%(sender))
                self.lock.release()
                return
            new_view = msg[2]
            if len(self.new_view_msg_received) != 0:
                if self.poss_view != new_view:
                    print("Unmatch new view from replica %d"%(sender))
                    self.new_view_msg_received = set()
                    self.lock.release()
                    # possible fault
                    return
            self.new_view_msg_received.add(sender)
            self.poss_view = new_view
            if len(self.new_view_msg_received) == int((replica_amount + 1) / 2):
                self.view = self.poss_view
                self.new_view_msg_received = set()
                self.primary, self.follower = self.get_sync_group(self.view)
                print("System view changed, view:%d, primary:%d, follower:%d"%(self.view, self.primary, self.follower))
            self.lock.release()
        
    def run(self):
        while True:
            data, address = self.sk.recvfrom(4096)
            msg = pickle.loads(data)
            sender = address[1] - 10000
            _thread.start_new_thread(self.msg_handler, (msg, sender))
# main
client = Client()
_thread.start_new_thread(client.run, ())
while True:
    try:
        op = input("Please input op:")
    except:
        exit(0)
    if op == "":
        continue
    client.request(op)
    
    
