#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Sat Jan 11 14:09:06 2020
# Author: January
# 数字签名采用模拟的方式来实现
# 模拟t=1时的情况

import os
import sys
import socket
import pickle
import select
import _thread
import logging
import hashlib

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("replica")

class MsgType():
    REPLY = "reply"
    REPLICATE = "replicate"
    COMMIT = "commit"
    VIEW_CHANGE = "view-change"
    VC_FINAL = "vc-final"
    NEW_VIEW = "new-view"
    SUSPECT = "suspect"
    COMMIT_REQUEST = "commit-request"


# 本地回环网络组网，3个副本节点使用3个不同的端口表示
replica_amount = 3
# 系统的公开信息，第0个为client对应的信息
client_ids = [0]
ports = [10000, 10001, 10002, 10003]
addresses = (("127.0.0.1", 10000), ("127.0.0.1", 10001), ("127.0.0.1", 10002), ("127.0.0.1", 10003))
signatures = ["client", "replica1", "replica2", "replica3"]

class Replica():
    # protocal config
    tmot = 2
    def __init__(self, replica_num):
        # current replica
        self.id = replica_num
        self.address = addresses[replica_num]
        self.signature = signatures[replica_num]
        self.sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sk.bind(self.address)
        # protocal data
        self.primary = 1
        self.followers = [2]
        self.prepare_log = []
        self.commit_log = []
        self.view = 0
        self.sn = -1
        self.ex = -1
        # replica state
        self.data = 0
        
    def sign(self, data):
        return self.signature

    def verify(self, msg, sig, id):
        if sig == signatures[id]:
            return True
        else:
            return False
    
    def digest(self, data):
        return pickle.dumps(data)
    
    def execute(self, req):
        op = req[1]
        self.data += op
        return self.data

    def msg_handler(self, msg, sender):
        msg_type = msg[0]
        if msg_type == MsgType.REPLICATE:
            req = msg
            print("Receive client request")
            # [replicate, op, ts, c, sig]
            req_body = req[:-1]
            id = req[-2]
            sig = req[-1]
            if id not in client_ids or self.verify(req_body, sig, id) != True:
                print("invalid client request")
                return
            self.sn += 1
            # msg_p [COMMIT, D(req), sn, view, sig]
            msg_p = [MsgType.COMMIT, self.digest(msg), self.sn, self.view]
            msg_p.append(self.sign(msg_p))
            # [req, msg_p]
            msg_to_follower = [MsgType.COMMIT_REQUEST, req, msg_p]
            # add to prepare_log
            self.prepare_log.append([req, msg_p])
            for follower in self.followers:
                self.sk.sendto(pickle.dumps(msg_to_follower), addresses[follower])
    
        elif msg_type == MsgType.COMMIT_REQUEST:
            msg_p = msg[2]
            req = msg[1]
            d_req, sn, view = msg_p[1:4]
            ts = req[2]
            msg_p_body, msg_p_sig = msg_p[:-1], msg_p[-1]
            if self.verify(msg_p_body, msg_p_sig, sender) != True:
                print("Invalid message from %d"%(sender))
                print("start view change")
                return
            if sn == self.sn + 1 and self.digest(req) == d_req:
                self.sn += 1
                reply = self.execute(req)
                self.ex += 1
                msg_f = [MsgType.COMMIT, self.digest(req), self.sn, self.view, ts, self.digest(reply)]
                msg_f.append(self.sign(msg_f))
                self.commit_log.append([req, msg_p, msg_f])
                try:
                    self.sk.sendto(pickle.dumps(msg_f), addresses[self.primary])
                except:
                    print("error send commit to primary")
        elif msg_type == MsgType.COMMIT:
            msg_f = msg
            d_req, sn, view, ts, d_rep, sig = msg[1:]
            msg_body = msg[:-1]
            if self.verify(msg_body, sig, sender) == False:
                print("Invalid message from %d"%(sender))
                print("start view change")
                return
            if self.digest(self.prepare_log[sn][0]) == d_req:
                # add [req, msg_p, msg_f] to commit log
                self.commit_log.append([self.prepare_log[sn][0], self.prepare_log[sn][1], msg_f])
                if len(self.commit_log) >= self.ex + 1:
                    self.ex += 1
                    reply = self.execute(self.commit_log[self.ex][0])
                    if self.digest(reply) == d_rep:
                        p_reply = [MsgType.REPLY, self.sn, self.view, ts, reply]
                        p_reply.append(self.sign(p_reply))
                        msg_to_client = [MsgType.REPLY, p_reply, msg_f]
                        client = self.commit_log[self.ex][0][-2]
                        try:
                            self.sk.sendto(pickle.dumps(msg_to_client), addresses[client])
                        except Exception as e:
                            print("error reply to client")
                            print("ERROR %s"%(str(e)))

    def run(self):
        print("replica%d started, pid is %d"%(self.id, os.getpid()))
        while True:
            try:
                data, addr = self.sk.recvfrom(4096)
                sender = addr[1] - 10000
                logger.debug("data from {0}".format(addr))
                msg = pickle.loads(data)
                logger.debug("parsed data %s"%(str(msg)))
                _thread.start_new_thread(self.msg_handler, (msg, sender))
            except KeyboardInterrupt: 
                self.sk.close()
                exit(0)
            except Exception as e:
                print(e)


# main
if len(sys.argv) < 2:
    print("please specify current replica's num")
    exit(1)
replica_num = int(sys.argv[1])
replica = Replica(replica_num)
replica.run()


            

