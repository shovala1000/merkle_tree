# shoval argov, 206626681, Ariel mantel, 313450249
# !/usr/bin/python3
import base64
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


# class to represent a node in merkle tree
class MerkleTreeNode:
    def __init__(self, value):
        self.left = None
        self.right = None
        self.value = value
        self.hashValue = get_hash_value(value)


# getting the hash value of a string
def get_hash_value(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


# get a list of values (strings) and make a merkle tree
def add_node(leaves):
    nodes = []
    # make every leaf's value to a merkle tree node
    for i in leaves:
        nodes.append(MerkleTreeNode(i))
    # make a merkle tree from all the nodes
    while len(nodes) != 1:
        temp = []
        for i in range(0, len(nodes), 2):
            # node 1 of binary tree
            node1 = nodes[i]
            # node 2 of binary tree
            if i + 1 < len(nodes):
                node2 = nodes[i + 1]
            else:
                # there is just one child in the binary tree
                temp.append(nodes[i])
                break
            # define a parent of 2 nodes
            node1_node2_hash = node1.hashValue + node2.hashValue
            parent = MerkleTreeNode(node1_node2_hash)
            parent.left = node1
            parent.right = node2
            temp.append(parent)
        nodes = temp
    # return the root
    return nodes[0]


# print the proof of inclusion from root(not include) to start_value
def proof_of_inclusion(root, start_value):
    if root.left is None:
        return 0
    if root.left.value == start_value:
        print(root.right.hashValue, end=" ")
        return 1
    if root.right.value == start_value:
        print(root.left.hashValue, end=" ")
        return 1
    # start_value is on the left side, so we need to print the right side
    if 1 == proof_of_inclusion(root.left, start_value):
        print(root.right.hashValue)
    # start_value is on the right side, so we need to print the left side
    if 1 == proof_of_inclusion(root.right, start_value):
        print(root.left.hashValue)


# check if the list of proof is valid for a given val
def is_proof_valid(val, proof):
    # hash value of val
    val_hash = get_hash_value(val)
    # the root's hash value in the list of proof
    root_hash = proof[0]
    proof.remove(proof[0])
    current_hash = val_hash
    # building hash value from proof
    for hash in proof:
        byte = hash[0]
        add_hash = hash.split(byte, 1)[1]
        if "1" == byte:
            current_hash = get_hash_value(current_hash + add_hash)
        elif "0" == byte:
            current_hash = get_hash_value(add_hash + current_hash)
        # error - hash is not starting with 1 or 0
        else:
            print()
            return
    # checking if the proof was valid
    if current_hash == root_hash:
        print(True)
    else:
        print(False)


# initialize key by RSA protocol
def init_keys_RSA():
    try:
        # initialize private key
        priv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        # initialize private pem
        priv_pem = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # initialize public key
        pub_key = priv_key.public_key()
        # initialize public pem
        pub_pem = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # printing the keys
        print(priv_pem.decode('utf-8'))
        print(pub_pem.decode('utf-8'))
    # error
    except:
        print()


# make a signature given private pem and message
def make_signature(private_pem, message):
    try:
        # return private key from private pem
        private_key = serialization.load_pem_private_key(
            private_pem,
            password=None,
        )
        # initialize signature
        signature = private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # print the signature
        print(base64.b64encode(signature).decode("utf-8"))
    # error
    except:
        print()


# verify the signature
def verify(public_pem, signature, value):
    try:
        # return signature object from signature string
        sig = base64.b64decode(signature)
        # return public key from public pem
        public_key = serialization.load_pem_public_key(public_pem)
        # check if valid
        public_key.verify(
            sig,
            value.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(True)
    # error - verify is failed
    except:
        print(False)


if __name__ == "__main__":
    leaves_values = []
    root = None

    while True:
        # get an input from user and check if valid
        input_lst = []
        # make a list of the input spilt by space and number to be the first element
        while 0 == len(input_lst):
            input_str = input()
            input_lst = input_str.split(" ")
            if 0 == len(input_lst):
                print()
            else:
                number = input_lst[0]
        # case number is 1
        if "1" == number:
            # check if input valid
            if 2 != len(input_lst):
                print()
                continue
            # input is valid - make a merkle tree
            node = input_lst[1]
            leaves_values.append(node)
            root = add_node(leaves_values)
        # case number is 2
        if "2" == number:
            # input valid - print root hash
            if root is not None and 1 == len(input_lst):
                print(root.hashValue)
            # check if input valid
            else:
                print()
        # case number is 3
        if "3" == number:
            # check if input valid
            if 2 != len(input_lst):
                print()
                continue
            try:
                start = int(input_lst[1])
            # error - input invalid
            except:
                print()
                continue
            # check if input valid
            if start >= len(leaves_values):
                print()
                continue
            # input valid - case the start_value is one of the root's children
            start_value = leaves_values[start]
            print(root.hashValue, end=" ")
            if root.left.value == start_value:
                print(root.right.hashValue)
            elif root.right.value == start_value:
                print(root.left.hashValue)
            # input valid - case the start_value is not one of the root's children
            else:
                proof_of_inclusion(root, start_value)
        # case number is 4
        if "4" == number:
            # check if input valid
            if 2 > len(input_lst):
                print()
                continue
            # input valid - check if the proof is valid
            val = input_lst[1]
            proof = input_lst
            proof.remove(proof[0])
            proof.remove(proof[0])
            is_proof_valid(val, proof)
        # case number is 5
        if "5" == number:
            # initialize public and private keys
            init_keys_RSA()
        # case number is 6
        if "6" == number:
            # check if input valid
            if 5 != len(input_lst):
                print()
                continue
            else:
                # get the private key
                line = input_lst[1] + " " + input_lst[2] + " " + input_lst[3] + " " + input_lst[4]
                pem = line + "\n"
                while line != "-----END RSA PRIVATE KEY-----":
                    line = input()
                    pem += line + "\n"
                pem = pem.encode()
                # make a signature on the root's hash value
                make_signature(pem, root.hashValue)

        # case number is 7
        if "7" == number:
            # check if input valid
            if 4 != len(input_lst):
                print()
                continue
            # get the public key
            line = input_lst[1] + " " + input_lst[2] + " " + input_lst[3]
            pem = line + "\n"
            while line != "-----END PUBLIC KEY-----":
                line = input()
                pem += line + "\n"
            # after "-----END PUBLIC KEY-----" input need to be a new line
            input()
            pem = pem.encode()
            signature_value = input().split(" ")
            # check if input valid
            if 2 != len(signature_value):
                print()
                continue
            signature = signature_value[0]
            value = signature_value[1]
            # verify the signature
            verify(pem, signature, value)
