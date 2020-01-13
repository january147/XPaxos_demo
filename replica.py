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
import time
import queue
import numpy as np

#logging.basicConfig(level=logging.DEBUG)
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
max_sn = 50
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
        self.follower = 2
        self.prepare_log = []
        self.commit_log = []
        self.vcset = []
        self.vc_received = set()
        self.vf_received = set()
        self.new_view_received = set()
        self.view = 0
        self.sn = -1
        self.ex = -1
        self.view_changing = False
        self.replicate_ok = True
        # 视图变更中间状态，保证执行顺序，避免消息达到顺序的影响
        self.view_change_ctrl = _thread.allocate_lock()
        self.view_change_ok = False
        self.vc_final_ctrl = _thread.allocate_lock()
        self.vc_final_ok = False
        self.new_view_ok = False
        self.new_view_ctrl = _thread.allocate_lock()
        self.follower_reply = False
        # replica state
        self.data = 0
        # lock
        self.lock = _thread.allocate_lock()
        # protocol config
        self.tmout = 2
        
    def sign(self, data):
        return (self.id, self.signature)

    def verify(self, msg, sig, id):
        if sig == signatures[id]:
            return True
        else:
            return False
    
    def digest(self, data):
        md5 = hashlib.md5()
        bytes_data = pickle.dumps(data)
        md5.update(bytes_data)
        return md5.hexdigest()
    
    # 验证最后一个元素是签名的一般消息
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

    def verify_commit_log(self, commit_log):
        req, msg_p, msg_f = commit_log
        d_req_p, sn_p, view_p = msg_p[1:4]
        d_req_f, sn_f, view_f = msg_f[1:4]
        op, ts, c = req[1:4]
        # 验证是否包含对于视图的同步组所有成员的信息，这些信息是否相符(req，sn，view等等是否一致)
        # 避免攻击者更改日志项后利用自己的秘钥重签名
        if msg_p[-1][0] == msg_f[-1][0]:
            logger.debug("msg source error")
            return False
        if not (self.verify_msg(msg_p) and self.verify_msg(msg_f) and self.verify_msg(req)):
            logger.debug("invalid signature")
            return False
        if not (d_req_p == d_req_f and sn_p == sn_f and view_p == view_f and d_req_p == self.digest(req)):
            logger.debug("log content doesn't match")
            return False    
        return True

    # 执行客户端的操作
    def execute(self, req):
        op = req[1]
        self.data += op
        return self.data

    def view_change_timer(self):
        i = 0
        while i < 2:
            if self.view_changing == False:
                return
            i += 0.1
            time.sleep(0.1)
        print("view change to view %d timeout, start new view change"%(self.view))
        self.suspect()

    def follower_reply_timer(self, sn, ts):
        i = 0
        while i < 2:
            if self.follower_reply == True:
                return
            i += 0.1
            time.sleep(0.1)
        print("follower timeout, view:%d, sn:%d, timestamp:%d, start new view change"%(self.view, sn, ts))
        self.suspect()

    def view_change_init(self):
        self.vcset = []
        self.vc_received = set()
        self.vf_received = set()
        self.new_view_received = set()
        self.view_changing = True
        self.replicate_ok = False
        self.view_change_ok = False
        self.vc_final_ok = False
        self.new_view_ok = False
        try:
            self.view_change_ctrl.release()
        except:
            pass
        try:
            self.vc_final_ctrl.release()
        except:
            pass
        try:
            self.new_view_ctrl.release()
        except:
            pass
        self.view_change_ctrl.acquire()
        self.vc_final_ctrl.acquire()
        self.new_view_ctrl.acquire()
    
    def broadcast(self, data, des = None):
        if des == None:
            des = addresses[1:]
        for address in des:
            if address != self.address:
                self.sk.sendto(data, address)
    
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

    def suspect(self):
        self.view_change_init()
        suspect_msg = [MsgType.SUSPECT, self.view, self.id]
        suspect_msg.append(self.sign(suspect_msg))
        packed_suspect_msg = pickle.dumps(suspect_msg)
        self.broadcast(packed_suspect_msg)
        # 延时确保消息按顺序到达
        time.sleep(0.1)
        self.view_change()
        if self.id not in self.get_sync_group(self.view):
            self.replicate_ok = True
            self.view_changing = False
            self.vc_final_ctrl.release()
            self.new_view_ctrl.release()
        else:
            _thread.start_new_thread(self.view_change_timer, ())
        
    def view_change(self):
        self.view += 1
        self.primary, self.follower = self.get_sync_group(self.view)
        # send view change
        vc_msg = [MsgType.VIEW_CHANGE, self.view, self.commit_log[:self.sn + 1]]
        vc_msg.append(self.sign(vc_msg))
        packed_vc_msg = pickle.dumps(vc_msg)
        self.broadcast(packed_vc_msg, self.get_sync_group_address(self.view))
        # 自身的view-change消息加入vcset中
        self.vcset.append(vc_msg)
        self.vc_received.add(self.id)
        # todo start a timer
        self.view_change_ok = True
        self.view_change_ctrl.release()

    def format_commit_log(self):
        result = ""
        for item in self.commit_log:
            req, msg_p, msg_f = item
            sn = msg_p[2]
            op = req[1]
            format_item = "sn:{:d}, op:{:+d}\n".format(sn, op)
            result += format_item
        return result

        
    def msg_handler(self, msg, sender):
        msg_type = msg[0]
        # client normal request
        if msg_type == MsgType.REPLICATE:
            if self.view_changing == True:
                print("receive client request when view changing")
                return
            req = msg
            logger.debug("Receive client request")
            if self.id != self.primary:
                return
            # [replicate, op, ts, c, sig]
            if not (sender in client_ids and self.verify_msg(req) == True):
                print("invalid client request, drop")
                return
            self.sn += 1
            # msg_p [COMMIT, D(req), sn, view, sig]
            msg_p = [MsgType.COMMIT, self.digest(msg), self.sn, self.view]
            msg_p.append(self.sign(msg_p))
            # [req, msg_p]
            msg_to_follower = [MsgType.COMMIT_REQUEST, req, msg_p]
            # add to prepare_log
            if len(self.prepare_log) <= self.sn:
                self.prepare_log.extend([None for i in range(self.sn + 1 - len(self.prepare_log))])
            self.prepare_log[self.sn] = [req, msg_p]
            self.follower_reply = False
            self.sk.sendto(pickle.dumps(msg_to_follower), addresses[self.follower])
            # start timer
            _thread.start_new_thread(self.follower_reply_timer, (self.sn, req[2]))

        # primary asks to commit
        elif msg_type == MsgType.COMMIT_REQUEST:
            msg_p = msg[2]
            req = msg[1]
            d_req, sn, view = msg_p[1:4]
            ts = req[2]
            msg_p_body, msg_p_sig = msg_p[:-1], msg_p[-1]
            if self.verify_msg(msg_p, self.primary) != True:
                print("Invalid commit request message from %d"%(sender))
                print("start view change")
                return
            if view != self.view:
                print("wrong view in commit request message from %d"%(sender))
                return
            if sn == self.sn + 1 and self.digest(req) == d_req:
                self.sn += 1
                reply = self.execute(req)
                self.ex += 1
                msg_f = [MsgType.COMMIT, self.digest(req), self.sn, self.view, ts, self.digest(reply)]
                msg_f.append(self.sign(msg_f))
                if len(self.commit_log) <= self.sn:
                    self.commit_log.append([req, msg_p, msg_f])
                else:
                    self.commit_log[self.sn] = [req, msg_p, msg_f]
                try:
                    self.sk.sendto(pickle.dumps(msg_f), addresses[self.primary])
                except:
                    print("error send commit to primary")
        # followers reponse
        elif msg_type == MsgType.COMMIT:
            msg_f = msg
            d_req, sn, view, ts, d_rep, sig = msg[1:]
            msg_body = msg[:-1]
            if self.verify_msg(msg_f) == False:
                print("Invalid message from %d"%(sender))
                print("start view change")
                return
            if view != self.view:
                print("wrong view in commit message from %d"%(sender))
                return
            if self.digest(self.prepare_log[sn][0]) == d_req:
                # add [req, msg_p, msg_f] to commit log
                if len(self.commit_log) <= self.sn:
                    self.commit_log.append([self.prepare_log[sn][0], self.prepare_log[sn][1], msg_f])
                else:
                    self.commit_log[self.sn] = [self.prepare_log[sn][0], self.prepare_log[sn][1], msg_f]
                if self.sn >= self.ex + 1:
                    self.ex += 1
                    reply = self.execute(self.commit_log[self.ex][0])
                    if self.digest(reply) == d_rep:
                        self.follower_reply = True
                        p_reply = [MsgType.REPLY, self.sn, self.view, ts, reply]
                        p_reply.append(self.sign(p_reply))
                        msg_to_client = [MsgType.REPLY, p_reply, msg_f]
                        client = self.commit_log[self.ex][0][-2]
                        try:
                            self.sk.sendto(pickle.dumps(msg_to_client), addresses[client])
                        except Exception as e:
                            print("error reply to client")
                            print("ERROR %s"%(str(e)))
                        
        elif msg_type == MsgType.SUSPECT:
            self.lock.acquire()
            if self.verify_msg(msg) != True:
                print("Invalid suspect message from %d"%(sender))
                print("start view change")
                self.lock.release()
                return
            if msg[-1][0] not in self.get_sync_group(self.view):
                print("Passive replica try to suspect, maybe fault")
                self.lock.release()
                return
            view = msg[1]
            if view < self.view - 1:
                # 会收到多个来自上个view的suspect消息，忽略这些消息，如果收到更前的view的suspect消息或者之后view的suspec消息则予以警告
                print("obselolete suspect message from %d"%(sender))
                self.lock.release()
                return
            if self.view_changing == True or view == self.view - 1:
                self.lock.release()
                return
            self.view = view
            self.view_change_init()
            self.broadcast(pickle.dumps(msg))
            # 延时确保消息按顺序到达
            time.sleep(0.1)
            self.view_change()
            # 非新视图中同步组的节点已经完成视图变更任务
            if self.id not in self.get_sync_group(self.view):
                self.view_changing = False
                self.replicate_ok = True
                self.new_view_ctrl.release()
                self.vc_final_ctrl.release()
            else:
                # 启动计时器
                _thread.start_new_thread(self.view_change_timer, ())
            self.lock.release()
        elif msg_type == MsgType.VIEW_CHANGE:
            if self.view_changing == False:
                print("Get view-change from %d when not doing view changing, maybe fault"%(sender))
                return
            if self.view_change_ok == False:
                self.view_change_ctrl.acquire()
                self.view_change_ctrl.release()
            self.lock.acquire()
            if self.verify_msg(msg) != True:
                print("Invalid view change message from %d"%(sender))
                print("start view change")
                self.lock.release()
                return
            view = msg[1]
            if view < self.view:
                print("wrong view(%d/%d) in view change message from %d"%(view, self.view, sender))
                self.lock.release()
                return
            if view > self.view:
                self.lock.release()
                i = 0
                while True:
                    if view == self.view:
                        self.lock.acquire()
                        break
                    if i >= 1:
                        print("wrong view(%d/%d) in view change message from %d"%(view, self.view, sender))
                        return
                    i += 0.001
                    time.sleep(0.001)
            if sender in self.vc_received:
                print("Receive repeated vc from %d, maybe fault"%(sender))
                self.lock.release()
                return
            self.vc_received.add(sender)
            self.vcset.append(msg)
            if len(self.vcset) == int((replica_amount + 1) / 2):
                vc_final_msg = [MsgType.VC_FINAL, self.view, self.id, self.vcset]
                vc_final_msg.append(self.sign(vc_final_msg))
                packed_vc_final_msg = pickle.dumps(vc_final_msg)
                # 延时确保消息按顺序到达
                time.sleep(0.1)
                self.broadcast(packed_vc_final_msg, self.get_sync_group_address(self.view))
                # 将自身加入已收到的vc_final消息的集合中
                self.vf_received.add(self.id)
                self.vc_final_ok = True
                self.vc_final_ctrl.release()
            logger.debug("len(vcset):%d"%len(self.vcset))
            self.lock.release()
        elif msg_type == MsgType.VC_FINAL:
            if self.view_changing == False:
                print("Get vc-final from %d when not doing view changing, maybe fault"%(sender))
                return
            if self.vc_final_ok == False:
                self.vc_final_ctrl.acquire()
                self.vc_final_ctrl.release()
            self.lock.acquire()
            if self.verify_msg(msg) != True:
                print("Invalid view final message from %d"%(sender))
                print("start view change")
                self.lock.release()
                return
            view = msg[1]
            if view != self.view:
                print("wrong view(%d/%d) in vc final message from %d"%(view, self.view, sender))
                self.lock.release()
                return
            if sender in self.vf_received:
                print("Receive repeated vf from %d, maybe fault"%(sender))
                self.lock.release()
                return
            self.vf_received.add(sender)
            self.vcset.extend(msg[-2])
            if len(self.vf_received) >= (replica_amount + 1) / 2:
                # 需要对日志中的所有选中的日志项进行签名验证，避免有节点伪造日志内容，
                new_commit_log = []
                for vc_msg in self.vcset:
                    commit_log = vc_msg[-2]
                    for log_entry in commit_log:
                        if self.verify_commit_log(log_entry) == False:
                            continue
                        sn = log_entry[1][2]
                        view = log_entry[1][3]
                        if len(new_commit_log) <= sn:
                            new_commit_log.extend([None for i in range(sn + 1 - len(new_commit_log))])
                        new_entry = new_commit_log[sn]
                        # 选择sn对应的view最大的日志项
                        if new_entry == None or new_entry[1][3] < view:
                            new_commit_log[sn] = log_entry
                self.commit_log = new_commit_log
                # 执行未执行过的log中的操作
                if len(new_commit_log) != 0:
                    self.sn = new_commit_log[-1][1][2]
                for i in range(self.ex + 1, len(new_commit_log)):
                    self.ex += 1
                    if new_commit_log[i] == None:
                        print("log loss")
                        continue
                    self.execute(new_commit_log[i][0])
                # 视图变更操作完成
                self.replicate_ok = True
                print("replica %d view change to view %d complete"%(self.id,self.view))
                # 向主节点报告视图变更完成
                new_view_msg = [MsgType.NEW_VIEW, self.sn, self.view]
                new_view_msg.append(self.sign(new_view_msg))
                if self.id != self.primary:
                    packed_new_view_msg = pickle.dumps(new_view_msg)
                    # 延时确保消息按顺序到达
                    time.sleep(0.1)
                    self.sk.sendto(packed_new_view_msg, addresses[self.primary])
                    # 将新view消息通知客户端
                    self.sk.sendto(packed_new_view_msg, addresses[0])
                    self.view_changing = False
                self.new_view_ok = True
                self.new_view_ctrl.release()
            self.lock.release()
        elif msg_type == MsgType.NEW_VIEW:
            if self.view_changing == False:
                print("Get view-change from %d when not doing view changing, maybe fault"%(sender))
                return
            if self.new_view_ok == False:
                self.new_view_ctrl.acquire()
                self.new_view_ctrl.release()
            self.lock.acquire()
            if self.verify_msg(msg) != True:
                print("invalid new view msg")
                self.lock.release()
                return
            if self.id != self.primary:
                self.lock.release()
                return
            if sender in self.new_view_received:
                print("repeated new view message from %d"%(sender))
                self.lock.release()
                return
            self.new_view_received.add(sender)
            if len(self.new_view_received) >= int((replica_amount - 1) / 2):
                self.view_changing = False
                print("system view change to view %d complete"%(self.view))
                new_view_msg = [MsgType.NEW_VIEW, self.sn, self.view]
                new_view_msg.append(self.sign(new_view_msg))
                self.sk.sendto(pickle.dumps(new_view_msg), addresses[0])
            self.lock.release()

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
_thread.start_new_thread(replica.run, ())
while True:
    try:
        cmd = input(">>> ")
    except:
        exit(0)
    if cmd == "ls":
        print("View:", replica.view)
        print("ID:", replica.id)
        print("Data:", replica.data)
        print("Primary:", replica.primary)
        print("Followr:", replica.follower)
        print("Vc_received:", replica.vc_received)
        print("Vf_received:", replica.vf_received)
        print("View-changing:", replica.view_changing)
        print("Replicate_ok:", replica.replicate_ok)
        print("############Log##############")
        print(replica.format_commit_log())
    elif cmd == "vc":
        replica.suspect()
    elif cmd == "ls nornaml":
        print("View:", replica.view)
        print("ID:", replica.id)
        print("Data:", replica.data)
        print("Primary:", replica.primary)
        print("Followr:", replica.follower)
    elif cmd == "ls vc":
        print("View:", replica.view)
        print("Vc_received:", replica.vc_received)
        print("Vf_received:", replica.vf_received)
        print("View-changing:", replica.view_changing)
        print("Replicate_ok:", replica.replicate_ok)
    elif cmd.startswith("set data"):
        try:
            replica.data = int(cmd.split(" ")[-1])
        except:
            print("invalid input")
    elif cmd == "":
        pass
    else:
        print("unknown cmd", cmd)




            

