from multiprocessing import Process, Value, Array, Lock
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import os
import math
import time
import zmq
import numpy as np
from abc import ABC, abstractmethod
import re
import sys, getopt
import random
import requests
import collections
import hashlib


class PeerClass():

    peer_processes = []

    def __init__(self):
        super().__init__()

    def write_file(self, peer_id, num_list, p, signer, h, public_key):
        filename = "election_" + str(peer_id) + ".log"
        file = open(filename, "w")

        for i in num_list:
            file.write(str(i) + "\n")

        file.write(str(p) + "\n")
        file.write(str(int.from_bytes(signer.sign(h), "big")) + "\n")
        file.write(public_key)


    def __peer(self, peer_id, t):

        port = 5050 + peer_id
        URL="http://127.0.0.1:5000"
        sign_key = ECC.generate(curve='NIST P-256')
        verify_key = sign_key.public_key()
        public_key = verify_key.export_key(format='OpenSSH').strip()
        signer = DSS.new(sign_key, 'fips-186-3')

        try:
            response = requests.post((URL + "/index"), json = {"id" : peer_id, "port": port, "public_key": public_key})
            if response.status_code != 201:
                raise Exception("Check post", response.status_code)
            else:
                try:
                    time.sleep(2)
                    response = requests.get((URL+"/index"))
                    if response.status_code != 200:
                        raise Exception("Check get")

                    peer_list = response.json()
                    #print(peer_list)

                    zmq_socket = zmq.Context()
                    message = {}
                    rand_num = random.randint(0,(2**256)-1)
                    message["number"] = rand_num
                    for peer_item in peer_list:
                        if peer_item["id"] != peer_id:
                            zmq_push = zmq_socket.socket(zmq.PUSH)
                            zmq_push.connect("tcp://127.0.0.1:" + str(peer_item["port"]))
                            zmq_push.send_json(message)

                    num_list = [rand_num]
                    zmq_pull = zmq_socket.socket(zmq.PULL)
                    zmq_pull.bind("tcp://127.0.0.1:" + str(port))

                    for i in range(len(peer_list) - 1):
                        received_message = zmq_pull.recv_json()
                        num_list.append(received_message["number"])


                    xor_nums = 0
                    for num in num_list:
                        xor_nums = xor_nums ^ num

                    byte_xor_nums = xor_nums.to_bytes(32, 'big')
                    digest = SHA3_256.new(byte_xor_nums)
                    for i in range(t - 1):
                        digest = SHA3_256.new(digest.digest())

                    p = int.from_bytes(digest.digest(), "big") % len(peer_list)

                    #write_file(peer_id, num_list, p, signer, digest, public_key)
                    filename = "election_" + str(peer_id) + ".log"
                    file = open(filename, "w")


                    str_list = []
                    for i in num_list:
                        str_list.append(str(i) + "\n")

                    str_list.append(str(p) + "\n")

                    for i in num_list:
                        file.write(str(i) + "\n")

                    file.write(str(p) + "\n")
                    file.write(str(int.from_bytes(signer.sign(SHA3_256.new("".join(str_list).encode('utf-8'))), "big")) + "\n")
                    file.write(public_key)

                except Exception as e:
                	print(str(e))
        except Exception as e:
        	print(str(e))


    def start(self, n, t):

        for i in range(n):
            peer_process = Process(target = self.__peer, args=(i,t,))
            peer_process.start()
            self.peer_processes.append(peer_process)

        #time.sleep(10)
        for peer_process in self.peer_processes:
            #peer_process.terminate()
            peer_process.join()

def checkHelp(argv):
    try:
        opts, args = getopt.getopt(argv,"-h")
    except getopt.GetoptError:
        print("peer.py <NUM_PEERS (n) (integer)>  <NUM_ITER (t) (integer)>")

    for opt, arg in opts:
        if opt == '-h':
            print("peer.py <NUM_PEERS (n) (integer)>  <NUM_ITER (t) (integer)>")
            return 0
    return 1

def checkArgs(argv):
    check = 1
    try:
        if (len(argv) != 2) or (type(int(argv[0])) != int) or (type(int(argv[1])) != int):
            print("peer.py <NUM_PEERS (n) (integer)>  <NUM_ITER (t) (integer)>")
            check = 0
            return 0
        n = int(argv[0])
        t = int(argv[1])
        return [1, n, t]
    except:
        if check:
            print("peer.py <NUM_PEERS (n) (integer)>  <NUM_ITER (t) (integer)>")
            return 0
        return 1

def main(argv):
    check1 = checkHelp(argv)
    if check1:
        check2 = checkArgs(argv)
        if type(check2) != int:
            if check1 and check2[0]:
                cls = PeerClass()
                cls.start(check2[1], check2[2]) #STARTS HERE


if __name__ == "__main__":
    main(sys.argv[1:])
