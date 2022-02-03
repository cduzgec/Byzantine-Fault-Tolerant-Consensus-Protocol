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
import random
import math
import string
import json

def succ(p, peer_list):
    id_list = []
    for peer in peer_list:
        id_list.append(peer["id"])
    id_list.sort()

    p_new = -1
    if p > id_list[-1] or  p <= id_list[0]:
        p_new = id_list[0]
    else:
        for i in range(len(id_list) - 1):
            if p > id_list[i] and p <=id_list[i+1]:
                p_new = id_list[i+1]
                break

    return p_new

def write_file(port_id, num_list, signer, p, public_key):
    filename = "election_" + str(port_id) + ".log"
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

def calculate_hash(num_list, t):
    xor_nums = 0
    for num in num_list:
        xor_nums = xor_nums ^ num

    byte_xor_nums = xor_nums.to_bytes(32, 'big')
    digest = SHA3_256.new(byte_xor_nums)
    for i in range(t - 1):
        digest = SHA3_256.new(digest.digest())

    return digest

def receive(zmq_socket, rand_num, port, len_peer_list):
    num_list = [rand_num]
    zmq_pull = zmq_socket.socket(zmq.PULL)
    zmq_pull.bind("tcp://127.0.0.1:" + str(port))

    for i in range(len_peer_list - 1):
        received_message = zmq_pull.recv_json()
        num_list.append(received_message["number"])

    return num_list

def send(zmq_socket, peer_list, peer_id, message):
    for peer_item in peer_list:
        if peer_item["id"] != peer_id:
            zmq_push = zmq_socket.socket(zmq.PUSH)
            zmq_push.connect("tcp://127.0.0.1:" + str(peer_item["port"]))
            zmq_push.send_json(message)

# def send_other_vals(prop_id, zmq_socket, peer_list, val_id, message):
#     for peer_item in peer_list:
#         if peer_item["id"] != peer_id and peer_item["id"] != prop_id:
#             zmq_push = zmq_socket.socket(zmq.PUSH)
#             zmq_push.connect("tcp://127.0.0.1:" + str(peer_item["port"]))
#             zmq_push.send_json(message)

def proposer(prop_id, signer, zmq_socket, port, peer_list, r, ell):

    h_prev = SHA3_256.new("".encode('utf-8'))   # first block
    for round in range(r):
        time.sleep(2)
        verified_list = []
        block = ""
        for i in range(ell):
            tau = "".join([random.choice(string.ascii_letters + string.digits) for n in range(64)])  # random string (nothing special again; assuming a real transaction is a string)
            block += (tau + "\n")      # be careful with the new line character at the end of each line
        h = SHA3_256.new(block.encode('utf-8')+ h_prev.digest())# hash value must be of "bytes"
        signature = signer.sign(h)     # sign the hash of the block
        h_prev = h                     # the current hash now becomes the previous hash for the next block

        verified = {"pid" : prop_id , "signature" : str(int.from_bytes(signature, "big"))}
        verified_list.append(verified)

        message = {}
        message["block"] = block
        message["signature"] = str(int.from_bytes(signature, "big"))
        message["pid"] = prop_id
        send (zmq_socket, peer_list, prop_id, message)

        #exit(0)
        #time.sleep(3)
        zmq_pull = zmq_socket.socket(zmq.PULL)
        zmq_pull.bind("tcp://127.0.0.1:" + str(port))
        #time.sleep(3)
        #burada cevap bekliyo validatorlardan yani len_peer_list - 1 kere
        for i in range(len(peer_list) - 1):
        #onları alıyo, kontrol ediyo, kontrol ettikçe de verified_list'e ekliyo
            received_message = zmq_pull.recv_json()
            received_block = received_message["block"]
            received_id = received_message["pid"]
            received_signature = int(received_message['signature']).to_bytes(64, byteorder='big')   # put the signature into the correct format to verify it                              # join the transactions into a block

            public_key = -1
            for peer in peer_list:
                if peer["id"] == received_id:
                    public_key = peer["public_key"]
            verifier = DSS.new(ECC.import_key(public_key), 'fips-186-3')

            try:
                verifier.verify(h, received_signature)
                print ("porp", prop_id, "The block is authentic.")
                #burda verify etmiş oluyo
                #yani burda da bi verified_list olması lazım aslında yukarda
                verified = {"pid" : received_id, "signature" : str(int.from_bytes(received_signature, "big"))}
                verified_list.append(verified)
            except ValueError:
                #bu zaten bu phasede hiç gerçekleşmicek
                print ("The block is NOT authentic.")

        #sonra burda da file'a yazıyo
        f = open('block_'+str(prop_id)+"_"+str(round)+'.log','wt')
        f.write(block)
        f.write(json.dumps(verified_list))
        f.close()
        zmq_pull.close()
    #del h, h_prev, signature, block

def validator(val_id, peer_list, signer, zmq_socket, port, r):
    zmq_pull = zmq_socket.socket(zmq.PULL)
    zmq_pull.bind("tcp://127.0.0.1:" + str(port))

    #creating the block hash to verify
    h_prev = SHA3_256.new("".encode('utf-8'))

    for round in range(r):
        verified_list = []
        received_message = zmq_pull.recv_json()
        block = received_message["block"]
        id = received_message["pid"]
        signature = int(received_message['signature']).to_bytes(64, byteorder='big')   # put the signature into the correct format to verify it                              # join the transactions into a block

        public_key = -1
        for peer in peer_list:
            if peer["id"] == id:
                public_key = peer["public_key"]
        verifier = DSS.new(ECC.import_key(public_key), 'fips-186-3')

        h = SHA3_256.new(block.encode('utf-8')+ h_prev.digest())    # hash the block
        #h_previ h'a eşitliyo ki düzgün çalışsın
        h_prev = h
        try:
            verifier.verify(h, signature)
            print (val_id, "The block is authentic.")
            verified_list.append({"pid" : id, "signature" : str(int.from_bytes(signature, "big"))})
            #burda verify etmiş oluyo kendisi de signlıcak
            val_signature = signer.sign(h)
            verified_list.append({"pid" : val_id, "signature" : str(int.from_bytes(val_signature, "big"))})
            #sonra da öbür peerlara gönderiyo proposer dahil ######belki burda bi sleep koymak gerekebilir
            val_message = {}
            val_message["block"] = block
            val_message["pid"] = val_id
            val_message["signature"] = str(int.from_bytes(val_signature, "big"))
            send(zmq_socket, peer_list, val_id, val_message)

            #burda öbürlerinden cevap bekliyo, öbür validatorlardan yani len_peer_list - 2 kere
            #onları alıyo, kontrol ediyo, kontrol ettikçe de verified_list'e eklicek
            for i in range(len(peer_list) - 2):
                received_message = zmq_pull.recv_json()
                v_block = received_message["block"]
                v_id = received_message["pid"]
                v_signature = int(received_message["signature"]).to_bytes(64, byteorder='big')

                v_public_key = -1
                for peer in peer_list:
                    if peer["id"] == v_id:
                        v_public_key = peer["public_key"]
                v_verifier = DSS.new(ECC.import_key(v_public_key), 'fips-186-3')
                try:
                    v_verifier.verify(h, v_signature)
                    print (val_id, "The block is authentic.")
                    #burda verify etmiş oluyo verified_list'e ekliyo
                    verified_list.append({"pid" : v_id, "signature" : str(int.from_bytes(v_signature, "big")) })

                except ValueError:
                    #bu zaten bu phasede hiç gerçekleşmicek
                    print ("The block is NOT authentic.")

            #sonra burda da file'a yazıyo
            f = open('block_'+str(val_id)+"_"+str(round)+'.log','wt')
            f.write(block)
            f.write(json.dumps(verified_list))
            f.close()

        except ValueError:
            #bu zaten bu phasede hiç gerçekleşmicek
            print ("The block is NOT authentic.")



def peer(peer_id, t, port_id, l, r):

    port = 5050 + port_id
    URL="http://127.0.0.1:5000"
    sign_key = ECC.generate(curve='NIST P-256')
    verify_key = sign_key.public_key()
    public_key = verify_key.export_key(format='OpenSSH').strip()

    signer = DSS.new(sign_key, 'fips-186-3')
    verifier = DSS.new(verify_key, 'fips-186-3')  # verifier instance

    try:
        response = requests.post((URL + "/index"), json = {"id" : peer_id, "port": port, "public_key": public_key})
        if response.status_code != 201:
            raise Exception("Check post", response.status_code)
        else:
            try:
                time.sleep(2)
                response = requests.get(URL+"/index")
                if response.status_code != 200:
                    raise Exception("Check get")

                peer_list = response.json()

                zmq_socket = zmq.Context()

                message = {}
                rand_num = random.randint(0,(2**256)-1)
                message["number"] = rand_num
                send(zmq_socket, peer_list, peer_id, message)

                len_peer_list= len(peer_list)
                num_list = receive(zmq_socket, rand_num, port, len_peer_list)

                digest = calculate_hash(num_list, t)

                p = succ(int.from_bytes(digest.digest(), "big") % (2**24), peer_list)

                write_file(port_id, num_list, signer, p, public_key)


                if peer_id == p:
                    print("prop")
                    proposer (p, signer, zmq_socket, port, peer_list,r,l)
                else:
                    print("valid")
                    validator(peer_id, peer_list, signer, zmq_socket, port, r)



            except Exception as e:
            	print(str(e))
    except Exception as e:
    	print(str(e))


def start(l,r,n,t):
    peer_processes = []

    for i in range(n):
        r_num = random.randint(0,(2**24)-1)
        while r_num in peer_processes:
            r_num = random.randint(0,(2**24)-1)
        peer_process = Process(target = peer, args=(r_num,t,i,l,r))
        peer_process.start()
        peer_processes.append(peer_process)

    #time.sleep(10)
    for peer_process in peer_processes:
        #peer_process.terminate()
        peer_process.join()

def checkHelp(argv):
    try:
        opts, args = getopt.getopt(argv,"-h")
    except getopt.GetoptError:
        print("peer.py <NUM_TRANS (l) (integer)>  <NUM_ROUND (r) (integer)>  <NUM_PEERS (n) (integer)>  <NUM_ITER (t) (integer)>")

    for opt, arg in opts:
        if opt == '-h':
            print("peer.py <NUM_TRANS (l) (integer)>  <NUM_ROUND (r) (integer)>  <NUM_PEERS (n) (integer)>  <NUM_ITER (t) (integer)>")
            return 0
    return 1

def checkArgs(argv):
    check = 1
    try:
        if (len(argv) != 4) or (type(int(argv[0])) != int) or (type(int(argv[1])) != int) or  (type(int(argv[2])) != int) or  (type(int(argv[3])) != int):
            print("peer.py <NUM_TRANS (l) (integer)>  <NUM_ROUND (r) (integer)>  <NUM_PEERS (n) (integer)>  <NUM_ITER (t) (integer)>")
            check = 0
            return 0
        l = int(argv[0])
        r = int(argv[1])
        n = int(argv[2])
        t = int(argv[3])
        return [1, l, r, n, t]
    except:
        if check:
            print( (type(int(argv[0])) != int))
            return 0
        return 1

def main(argv):
    check1 = checkHelp(argv)
    if check1:
        check2 = checkArgs(argv)
        if type(check2) != int:
            if check1 and check2[0]:
                start(check2[1], check2[2],check2[3],check2[4] ) #STARTS HERE


if __name__ == "__main__":
    main(sys.argv[1:])
