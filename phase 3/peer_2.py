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

def verify_sig(verifier, h, signature):
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False

def creating_mal_messages(peer_list,peer_id, zmq_socket,h_prev):
    block1 = ""
    block2 = ""
    h_prev1 = SHA3_256.new("".encode('utf-8'))
    h_prev2 = SHA3_256.new("".encode('utf-8'))
    for i in range(ell):
        tau = "".join([random.choice(string.ascii_letters + string.digits) for n in range(64)])  # random string (nothing special again; assuming a real transaction is a string)
        block1 += (tau + "\n")
        tau = "".join([random.choice(string.ascii_letters + string.digits) for n in range(64)])  # random string (nothing special again; assuming a real transaction is a string)
        block2 += (tau + "\n")
    h1 = SHA3_256.new(block1.encode('utf-8')+ h_prev1.digest())# hash value must be of "bytes"
    signature2 = signer.sign(h2)     # sign the hash of the block
    h_prev1 = h1                     # the current hash now becomes the previous hash for the next block
    
    h2 = SHA3_256.new(block2.encode('utf-8')+ h_prev2.digest())# hash value must be of "bytes"
    signature2 = signer.sign(h)     # sign the hash of the block
    h_prev2 = h2                     # the current hash now becomes the previous hash for the next block
    #burda post atmalı hangi honest peera hangi block gidicek
    #ki mal_validatorlar onu getleyip kendilerinde kullanabilsinler


    try:
        time.sleep(2)
        response = requests.get(URL+"/malicious_peers")
        if response.status_code != 200:
            raise Exception("Check malicious_peers get")
                
            malicious_list = response.json()

            honest_peer_num = len(peer_list) - len(malicious_list)
            counter= 0

            for peer in peer_list:
                if (peer_id["id"] != peer_id) and (peer_id["id"] not in malicious_list["peer_id"]) and counter <= honest_peer_num:
                                if counter < honest_peer_num//2:
                                    try:
                                        response = requests.post((URL + "/malicious_messages"), json = {"id" : peer_id["id"], "block": block1})
                                        if response.status_code != 201:
                                            raise Exception("Check malicious_messages post", response.status_code)
                                        counter += 1
                                else:
                                    try:
                                        response = requests.post((URL + "/malicious_messages"), json = {"id" : peer_id["id"], "block": block2})
                                        if response.status_code != 201:
                                            raise Exception("Check malicioumalicious_messagess_peers post", response.status_code)
                                        counter += 1
    return signature1, signature2, block1, block2, h1, h2


def mal_proposer(prop_id, signer, zmq_socket, port, peer_list, r, ell, public_key,s):

    #burda post kendini malicious_peersa eklemek için post atmalı sonra bekleyip get almalı
    try:
        response = requests.post((URL + "/malicious_peers"), json = {"id" : prop_id, "port": port, "public_key": public_key})
        if response.status_code != 201:
            raise Exception("Check malicious_peers post", response.status_code)
        else:
            try:
                time.sleep(2)
                #malicious peerlara ve normal peerlara ulaşmış oluyo artık

                signature1, signature2, block1, block2, h1, h2= creating_mal_messages(malicious_list,zmq_socket)

                h_prev = SHA3_256.new("".encode('utf-8'))   # first block
                for round in range(r):
                    if round != r-1: #bunu yeni ekledim son roundda atack yapsın diye malicious proposer
                        time.sleep(2)
                        block = ""
                        for i in range(ell):
                            tau = "".join([random.choice(string.ascii_letters + string.digits) for n in range(64)])  # random string (nothing special again; assuming a real transaction is a string)
                            block += (tau + "\n")      # be careful with the new line character at the end of each line
                        h = SHA3_256.new(block.encode('utf-8')+ h_prev.digest())# hash value must be of "bytes"
                        signature = signer.sign(h)     # sign the hash of the block
                        h_prev = h                     # the current hash now becomes the previous hash for the next block

                        verified = {"pid" : prop_id , "signature" : str(int.from_bytes(signature, "big"))}
                        verified_list.append(verified)

                        message = {"block": block, "pid": prop_id, "signature": str(int.from_bytes(signature, "big"))}
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

                            if verify_sig(verifier, h, signature):
                                print ("porp", prop_id, "The block is authentic.")
                                #burda verify etmiş oluyo
                                #yani burda da bi verified_list olması lazım aslında yukarda
                                verified = {"pid" : received_id, "signature" : str(int.from_bytes(received_signature, "big"))}
                                verified_list.append(verified)
                            else:
                                #bu zaten bu phasede hiç gerçekleşmicek
                                print ("The block is NOT authentic.")
                    else:
                        try:
                            response = requests.get((URL + "/malicious_messages"))
                            if response.status_code != 201:
                                raise Exception("Check malicious_messages get", response.status_code)
            
                                malicious_messages = response.json()

                                for malicious in malicious_messages:
                                    peer_lst =malicious["peer_ids"].split(",")
                                    for m_id in peer_lst:
                                        for peer in peer_list:
                                            if m_id == peer["id"] and m_id != peer_id:
                                                zmq_push = zmq_socket.socket(zmq.PUSH)
                                                zmq_push.connect("tcp://127.0.0.1:" + str(peer["port"]))
                                                if  malicious["block"] == block1:
                                                    message = {"block": malicious["block"], "pid": peer_id, "signature": str(int.from_bytes(signature1, "big"))}
                                                    zmq_push.send_json(message)
                                                else:
                                                    message = {"block": malicious["block"], "pid": peer_id, "signature": str(int.from_bytes(signature2, "big"))}
                                                    zmq_push.send_json(message)
                                    
                                zmq_pull = zmq_socket.socket(zmq.PULL)
                                zmq_pull.bind("tcp://127.0.0.1:" + str(port))
                                    
                                if s == 1 or s == 3:
                                    for i in range(len(peer_lst)):
                                        received_message = zmq_pull.recv_json()
                                        received_block = received_message["block"]
                                        received_id = received_message["pid"]
                                        received_signature = int(received_message['signature']).to_bytes(64, byteorder='big')   # put the signature into the correct format to verify it                              # join the transactions into a block

                                        public_key = -1
                                        for peer in peer_list:
                                            if peer["id"] == received_id:
                                                public_key = peer["public_key"]
                                        verifier = DSS.new(ECC.import_key(public_key), 'fips-186-3')

                                        if verify_sig(verifier, h1 , signature1) or verify_sig(verifier, h2 , signature2):
                                            print ("porp", prop_id, "The block is authentic.")
                                            #burda verify etmiş oluyo
                                            #yani burda da bi verified_list olması lazım aslında yukarda
                                            verified = {"pid" : received_id, "signature" : str(int.from_bytes(received_signature, "big"))}
                                            verified_list.append(verified)
                                        else:
                                            #bu zaten bu phasede hiç gerçekleşmicek
                                            print ("The block is NOT authentic.")
                                                
                                if s == 2 or s == 4:
                                    for i in range(len(peer_lst)-1):
                                        received_message = zmq_pull.recv_json()
                                        received_block = received_message["block"]
                                        received_id = received_message["pid"]
                                        received_signature = int(received_message['signature']).to_bytes(64, byteorder='big')   # put the signature into the correct format to verify it                              # join the transactions into a block

                                        public_key = -1
                                        for peer in peer_list:
                                            if peer["id"] == received_id:
                                                public_key = peer["public_key"]
                                        verifier = DSS.new(ECC.import_key(public_key), 'fips-186-3')

                                        if verify_sig(verifier, h1 , signature1) or verify_sig(verifier, h2 , signature2):
                                            print ("porp", prop_id, "The block is authentic.")
                                            #burda verify etmiş oluyo
                                            #yani burda da bi verified_list olması lazım aslında yukarda
                                            verified = {"pid" : received_id, "signature" : str(int.from_bytes(received_signature, "big"))}
                                            verified_list.append(verified)
                                        else:
                                            #bu zaten bu phasede hiç gerçekleşmicek
                                            print ("The block is NOT authentic.")
                #sonra burda da file'a yazıyo
                f = open('block_'+str(prop_id)+"_"+str(round)+'.log','wt')
                f.write(block)
                f.write(json.dumps(verified_list))
                f.close()
                zmq_pull.close()




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

        message = {"block": block, "pid": prop_id, "signature": str(int.from_bytes(signature, "big"))}
        # message["block"] = block
        # message["signature"] = str(int.from_bytes(signature, "big"))
        # message["pid"] = prop_id
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

            if verify_sig(verifier, h, signature):
                print ("porp", prop_id, "The block is authentic.")
                #burda verify etmiş oluyo
                #yani burda da bi verified_list olması lazım aslında yukarda
                verified = {"pid" : received_id, "signature" : str(int.from_bytes(received_signature, "big"))}
                verified_list.append(verified)
            else:
                #bu zaten bu phasede hiç gerçekleşmicek
                print ("The block is NOT authentic.")

        #sonra burda da file'a yazıyo
        f = open('block_'+str(prop_id)+"_"+str(round)+'.log','wt')
        f.write(block)
        f.write(json.dumps(verified_list))
        f.close()
        zmq_pull.close()
    #del h, h_prev, signature, block


def mal_validator(): #probably need to get proposers id as parameter
    zmq_pull = zmq_socket.socket(zmq.PULL)
    zmq_pull.bind("tcp://127.0.0.1:" + str(port))

    #connect index server as malicious peers
    try:
        response = requests.post((URL + "/malicious_peers"), json = {"id" : peer_id})
        if response.status_code != 201:
            raise Exception("Check post mal_valid", response.status_code)

        try:
            time.sleep(3)
            response = requests.get(URL+"/malicious_peers")
            if response.status_code != 200:
                raise Exception("Check get mal_valid_peers")

            #get other malicious peers
            mal_peers = response.json()
            mal_peer_ids = list(mal_peers.values())
            block = ""
            if (s == 1 or s == 3) and peer_id == min(mal_peer_ids):
                for i in range(ell):
                    tau = "".join([random.choice(string.ascii_letters + string.digits) for n in range(64)])  # random string (nothing special again; assuming a real transaction is a string)
                    block += (tau + "\n")      # be careful with the new line character at the end of each line

                message_ids = ""
                for peer in peer_list:
                    if peer["id"] not in mal_peer_ids:
                        message_ids += peer["id"] +","

                message_ids = message_ids[:len(message_ids) - 1]

                try:
                    response = requests.post((URL + "/malicious_messages"), json = {"peer_id" : message_ids, "block" : block})
                    if response.status_code != 201:
                        raise Exception("Check post mal_valid", response.status_code)

                except Exception as e:
                    print(str(e))


            # to wait min peer or proposer to create and post
            #the mal_block to index server
            time.sleep(3)
            try:
                response = requests.get(URL+"/malicious_messages")
                if response.status_code != 200:
                    raise Exception("Check get mal_valid_message")

                id_message_pair = response.json()

                #creating the block hash to verify
                h_prev = SHA3_256.new("".encode('utf-8'))

                for round in range(r):
                    if round != r-1:
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
                        if verify_sig(verifier, h, signature):
                            print (val_id, "The block is authentic.")
                            verified_list.append({"pid" : id, "signature" : str(int.from_bytes(signature, "big"))})
                            #burda verify etmiş oluyo kendisi de signlıcak
                            val_signature = signer.sign(h)
                            verified_list.append({"pid" : val_id, "signature" : str(int.from_bytes(val_signature, "big"))})
                            #sonra da öbür peerlara gönderiyo proposer dahil ######belki burda bi sleep koymak gerekebilir
                            val_message = {"block": block, "pid": val_id, "signature": str(int.from_bytes(val_signature, "big"))}
                            # val_message["block"] = block
                            # val_message["pid"] = val_id
                            # val_message["signature"] = str(int.from_bytes(val_signature, "big"))
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
                                if verify_sig(v_verifier, h, v_signature):
                                    print (val_id, "The block is authentic.")
                                    #burda verify etmiş oluyo verified_list'e ekliyo
                                    verified_list.append({"pid" : v_id, "signature" : str(int.from_bytes(v_signature, "big")) })

                                else:
                                    #bu zaten bu phasede hiç gerçekleşmicek
                                    print ("The block is NOT authentic.")
                        else:
                            #bu zaten bu phasede hiç gerçekleşmicek
                            print ("The block is NOT authentic.")

                    else:
                        #round = last round
                        


                        #sonra burda da file'a yazıyo
                        f = open('block_'+str(val_id)+"_"+str(round)+'.log','wt')
                        f.write(block)
                        f.write(json.dumps(verified_list))
                        f.close()

                except Exception as e:
                    print(str(e))

        except Exception as e:
            print(str(e))

    except Exception as e:
        print(str(e))

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
        if verify_sig(verifier, h, signature):
            print (val_id, "The block is authentic.")
            verified_list.append({"pid" : id, "signature" : str(int.from_bytes(signature, "big"))})
            #burda verify etmiş oluyo kendisi de signlıcak
            val_signature = signer.sign(h)
            verified_list.append({"pid" : val_id, "signature" : str(int.from_bytes(val_signature, "big"))})
            #sonra da öbür peerlara gönderiyo proposer dahil ######belki burda bi sleep koymak gerekebilir
            val_message = {"block": block, "pid": val_id, "signature": str(int.from_bytes(val_signature, "big"))}
            # val_message["block"] = block
            # val_message["pid"] = val_id
            # val_message["signature"] = str(int.from_bytes(val_signature, "big"))
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
                if verify_sig(v_verifier, h, v_signature):
                    print (val_id, "The block is authentic.")
                    #burda verify etmiş oluyo verified_list'e ekliyo
                    verified_list.append({"pid" : v_id, "signature" : str(int.from_bytes(v_signature, "big")) })

                else:
                    #bu zaten bu phasede hiç gerçekleşmicek
                    print ("The block is NOT authentic.")

            #sonra burda da file'a yazıyo
            f = open('block_'+str(val_id)+"_"+str(round)+'.log','wt')
            f.write(block)
            f.write(json.dumps(verified_list))
            f.close()

        else:
            #bu zaten bu phasede hiç gerçekleşmicek
            print ("The block is NOT authentic.")

# def decide_malicious(senario, peer_list, p, signer, zmq_socket, port, r, l, peer_id):
#     k = len(peer_list) // 3
#     count = 0
#     if senario == 1:
#         for peer in peer_list:
#             if p == peer["id"]:
#                 print("prop")
#                 proposer (p, signer, zmq_socket, port, peer_list, r, l)
#             elif count < k:
#                 print("mal_valid")
#
#                 #mal_validatorda önce indexten öbür malları öğrenmeli
#                 #sonra en küçük mal block yaratıcısı olarak seçilebilir ve block'u yaratır
#                 #tabi eğer ki proposer da malsa o zaman o yaratmalı
#                 #sonra bu yarattıklarını index servera postlar hangi peera hangi block gibisinden
#                 #sonra öbür mallar bunu index serverdan getler, ve onlara gerekli şeyleri atarlar
#                 #mal peerlar son rounda kadar başka bi şey yapmaları gerekmiyo bence
#                 #ama çok da emin değilim
#
#                 #validator should be changed as mal_validator
#                 validator(peer_id, peer_list, signer, zmq_socket, port, r)
#                 count += 1
#             else:
#                 print("valid")
#                 validator(peer_id, peer_list, signer, zmq_socket, port, r)
#     elif senario == 2:
#         for peer in peer_list:
#             if p == peer["id"]:
#                 print("mal_prop")
#
#                 #mal_proposerda önce indexten öbür malları öğrenmeli
#                 #sonra kendisi blockları yaratmalı 2 tane ve index servera postlamalı
#                 #bu sadece son roundda kullanılıcak unutulmasın
#                 #ilk r-1 round normal bi şekilde çalışmalı
#                 #son roundda 2 farklı block atılıcak honestlara
#                 #mal_validatorlar da mal_propun attığı ile aynı blockları aynı honest_validatorlara atıcak
#
#                 #proposer should be changed as mal_proposer
#                 proposer (p, signer, zmq_socket, port, peer_list, r, l)
#             elif count < k-1:
#                 print("mal_valid")
#                 #validator should be changed as mal_validator
#                 validator(peer_id, peer_list, signer, zmq_socket, port, r)
#                 count += 1
#             else:
#                 print("valid")
#                 validator(peer_id, peer_list, signer, zmq_socket, port, r)
#     elif senario == 3:
#         for peer in peer_list:
#             if p == peer["id"]:
#                 print("prop")
#                 proposer (p, signer, zmq_socket, port, peer_list, r, l)
#             elif count < k+1:
#                 print("mal_valid")
#                 #validator should be changed as mal_validator
#                 validator(peer_id, peer_list, signer, zmq_socket, port, r)
#                 count += 1
#             else:
#                 print("valid")
#                 validator(peer_id, peer_list, signer, zmq_socket, port, r)
#     elif senario == 4:
#         for peer in peer_list:
#             if p == peer["id"]:
#                 print("mal_prop")
#                 #proposer should be changed as mal_proposer
#                 proposer (p, signer, zmq_socket, port, peer_list, r, l)
#             elif count < k:
#                 print("mal_valid")
#                 #validator should be changed as mal_validator
#                 validator(peer_id, peer_list, signer, zmq_socket, port, r)
#                 count += 1
#             else:
#                 print("valid")
#                 validator(peer_id, peer_list, signer, zmq_socket, port, r)


def peer(peer_id, t, port_id, l, r, s, peer_id_type):

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

                #decide_malicious(senario, peer_list, p, signer, zmq_socket, port, r, l, peer_id) #bunun yanlış olduğuna karar verdim

                if peer_id == p:
                    if s == 1 or s == 3:
                        print("prop")
                        proposer(p, signer, zmq_socket, port, peer_list,r,l)
                    elif s == 2 or s == 4:
                        print("mal_prop")

                        #mal_proposerda önce indexten öbür malları öğrenmeli
                        #sonra kendisi blockları yaratmalı 2 tane ve index servera postlamalı
                        #bu sadece son roundda kullanılıcak unutulmasın
                        #ilk r-1 round normal bi şekilde çalışmalı
                        #son roundda 2 farklı block atılıcak honestlara
                        #mal_validatorlar da mal_propun attığı ile aynı blockları aynı honest_validatorlara atıcak

                        mal_proposer()
                else:
                    if peer_id_type[peer_id] == "m":
                        print("mal_valid")

                        #mal_validatorda önce indexten öbür malları öğrenmeli
                        #sonra en küçük mal block yaratıcısı olarak seçilebilir ve block'u yaratır
                        #tabi eğer ki proposer da malsa o zaman o yaratmalı
                        #sonra bu yarattıklarını index servera postlar hangi peera hangi block gibisinden
                        #sonra öbür mallar bunu index serverdan getler, ve onlara gerekli şeyleri atarlar
                        #mal peerlar son rounda kadar başka bi şey yapmaları gerekmiyo bence
                        #ama çok da emin değilim

                        mal_validator()
                    elif peer_id_type[peer_id] == "b":
                        if peer_id_type[p] == "m":
                            print("mal_valid")
                            mal_validator()
                        else:
                            print("valid")
                            validator(peer_id, peer_list, signer, zmq_socket, port, r)
                    else:
                        print("valid")
                        validator(peer_id, peer_list, signer, zmq_socket, port, r)

            except Exception as e:
            	print(str(e))
    except Exception as e:
    	print(str(e))

def decide_peer_id_type(n, s):
    peer_id_type = {}
    count = 0
    k = n // 3 #k = 1 ve 0 ise özel case oluyo galiba onu kontrol et
    if s == 1: #yukarda implement ederken proposer her türlü honest olucak, eğer m ile işaretlenmişse onun boşluğunu backup malicious olarak kapatıcak
        for i in range(n):
            r_num = random.randint(0,(2**24)-1)
            while r_num in peer_processes:
                r_num = random.randint(0,(2**24)-1)
            if count < k:
                peer_id_type[rnum] = "m" #stands for malicious
                count += 1
            elif count == k:
                peer_id_type[rnum] = "b" #stands for backup
                count += 1
            else:
                peer_id_type[rnum] = "h" #stands for honest
    elif s == 2: #yukarıda implement ederken, proposer her türlü malicious olucak, eğer m ile işaretlenmişlerdense, backup mal_validatora girip boşluğu kapatıcak
        for i in range(n):
            r_num = random.randint(0,(2**24)-1)
            while r_num in peer_processes:
                r_num = random.randint(0,(2**24)-1)
            if count < k-1:
                peer_id_type[rnum] = "m" #stands for malicious
                count += 1
            elif count == k-1:
                peer_id_type[rnum] = "b" #stands for backup
                count += 1
            else:
                peer_id_type[rnum] = "h" #stands for honest
    elif s == 3: #yukarda implement ederken proposer her türlü honest olucak, eğer m ile işaretlenmişse onun boşluğunu backup malicious olarak kapatıcak
        for i in range(n):
            r_num = random.randint(0,(2**24)-1)
            while r_num in peer_processes:
                r_num = random.randint(0,(2**24)-1)
            if count < k+1:
                peer_id_type[rnum] = "m" #stands for malicious
                count += 1
            elif count == k+1:
                peer_id_type[rnum] = "b" #stands for backup
                count += 1
            else:
                peer_id_type[rnum] = "h" #stands for honest
    elif s == 4: #yukarıda implement ederken, proposer her türlü malicious olucak, eğer m ile işaretlenmişlerdense, backup mal_validatora girip boşluğu kapatıcak
        for i in range(n):
            r_num = random.randint(0,(2**24)-1)
            while r_num in peer_processes:
                r_num = random.randint(0,(2**24)-1)
            if count < k:
                peer_id_type[rnum] = "m" #stands for malicious
                count += 1
            elif count == k:
                peer_id_type[rnum] = "b" #stands for backup
                count += 1
            else:
                peer_id_type[rnum] = "h" #stands for honest

    return peer_id_type

def start(l, r, n, t, s): #s means senario
    peer_processes = []
    peer_id_type = decide_peer_id_type(n, s)
    i = 0
    for i, id in enumerate(peer_id_type.keys()):
        peer_process = Process(target = peer, args=(id,t,i,l,r,s,peer_id_type))
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
        print("peer.py <NUM_TRANS (l) (integer)>  <NUM_ROUND (r) (integer)>  <NUM_PEERS (n) (integer)>  <NUM_ITER (t) (integer)>  <NUM_ITER (s) (integer 1, 2, 3 or 4)>")

    for opt, arg in opts:
        if opt == '-h':
            print("peer.py <NUM_TRANS (l) (integer)>  <NUM_ROUND (r) (integer)>  <NUM_PEERS (n) (integer)>  <NUM_ITER (t) (integer)>  <NUM_ITER (s) (integer 1, 2, 3 or 4)>")
            return 0
    return 1

def checkArgs(argv):
    check = 1
    try:
        if (len(argv) != 5) or (type(int(argv[0])) != int) or (type(int(argv[1])) != int) or  (type(int(argv[2])) != int) or  (type(int(argv[3])) != int) or  (type(int(argv[4])) != int):
            print("peer.py <NUM_TRANS (l) (integer)>  <NUM_ROUND (r) (integer)>  <NUM_PEERS (n) (integer)>  <NUM_ITER (t) (integer)>  <NUM_ITER (s) (integer 1, 2, 3 or 4)>")
            check = 0
            return 0
        l = int(argv[0])
        r = int(argv[1])
        n = int(argv[2])
        t = int(argv[3])
        s = int(argv[4])
        return [1, l, r, n, t, s]
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
                start(check2[1], check2[2],check2[3],check2[4], check2[5]) #STARTS HERE


if __name__ == "__main__":
    main(sys.argv[1:])
