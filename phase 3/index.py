from flask import Flask, request
from flask_restful import Resource, Api, reqparse
import json
import random
app = Flask(__name__)
api = Api(app)

index_list = []
verify_keys = {}
malicious_list = []
malicious_messages = []

class MaliciousBlocksToHonestPeers(Resource):
    def get(self):
        return malicious_messages, 200

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('peer_id')
        parser.add_argument('block')
        args = parser.parse_args()

        list_item = {
            "peer_ids" : args["peer_ids"], #a string that peer ids are seperated with comma
            "block" : args["block"],
        }
        malicious_messages.append(list_item)
        return malicious_messages, 201

class MaliciousPeers(Resource):
    def get(self):
        return malicious_list, 200

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('id')
        args = parser.parse_args()

        list_item = {
            "id" : int(args["id"]),
        }
        malicious_list.append(list_item)
        return malicious_list, 201

class IndexVerifyKeys(Resource):
    def get(self):
        return verify_keys, 200

class Index(Resource):
    def get(self):
        return index_list, 200

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('id')
        parser.add_argument('port')
        parser.add_argument('public_key')
        args = parser.parse_args()

        list_item = {
            "id" : int(args["id"]),
            "port" : int(args["port"]),
            "public_key" : args["public_key"],
        }
        verify_keys[args["id"]] = args["public_key"]
        index_list.append(list_item)
        return index_list, 201

api.add_resource(Index, '/index')
api.add_resource(IndexVerifyKeys, '/verify_keys')
api.add_resource(MaliciousPeers, '/malicious_peers')
api.add_resource(MaliciousBlocksToHonestPeers, '/malicious_messages')

if __name__ == '__main__':
    app.run(debug=True)
