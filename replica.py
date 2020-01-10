# 数字签名采用模拟的方式来实现
# 模拟t=1时的情况

import sys
import socket
import pickle
import select
import _thread

# 本地回环网络组网，3个副本节点使用3个不同的端口表示
replica_amount = 3
# 第0个为client的端口
ports = [10000, 10001, 10002, 10003]
addresses = (("127.0.0.1", 1000), ("127.0.0.1", 10001), ("127.0.0.1", 10002), ("127.0.0.1", 10003))
# 
connections_recv = [None for i in range(replica_amount + 1)]
connections_send = [None for i in range(replica_amount + 1)]
self_sk = None

def start_server(replica_num):
    lsk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsk.bind(("127.0.0.1", replicas_port[replica_num]))
    lsk.listen(3)
    while True:
        ssk, address = lsk.accept()
        print("connection from", address)
        # 读取目标节点编号
        data = ssk.recv(1)
        try:
            num = data[0]
        except:
            print("error connection")
            ssk.close()
            continue
        connections_recv[num] = ssk

def bind_port(replica_num):
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.bind(addresses[replica_num])
    return sk


prepare_log = []
commit_log = []
sn = 0
ex = 0

def main():
    if len(sys.argv) < 2:
        print("please specify current replica's num")
        exit(1)
    replica_num = int(sys.argv[1])
    self_sk = bind_port(replica_num)
    for address in addresses:
        if address != addresses[replica_num]:
            self_sk.sendto(b"hello", address)
    while True:
        try:
            data, address = self_sk.recvfrom(4096)
            print("recv %s from %s"%(str(data), str(address)))
        except:
            pass


if __name__ == "__main__":
    main()