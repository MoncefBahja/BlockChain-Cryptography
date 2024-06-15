from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import hashlib
import json
import time

# Functions to generate keys, sign and verify as previously defined
def generate_keys():
    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public = private.public_key()
    return private, public

def sign(message, private):
    message = bytes(str(message), 'utf-8')
    signature = private.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify(message, sig, public):
    message = bytes(str(message), 'utf-8')
    try:
        public.verify(
            sig,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print("Error executing public key:", e)
        return False

# Blockchain components
class Transaction:
    def __init__(self, sender, recipient, amount, signature):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = signature

    def to_dict(self):
        return {
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'signature': self.signature.hex()
        }

class Block:
    def __init__(self, previous_hash, transactions, nonce=0):
        self.timestamp = time.time()
        self.previous_hash = previous_hash
        self.transactions = transactions  # list of Transaction objects
        self.nonce = nonce
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_dict = {
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'nonce': self.nonce
        }
        block_string = json.dumps(block_dict, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block("0", [])
        self.chain.append(genesis_block)

    def add_block(self, block):
        if len(self.chain) > 0:
            block.previous_hash = self.chain[-1].hash
        block.hash = block.compute_hash()
        self.chain.append(block)

    def add_transaction(self, sender, recipient, amount, signature, public_key):
        transaction = Transaction(sender, recipient, amount, signature)
        if verify(f'{sender}{recipient}{amount}', signature, public_key):
            self.pending_transactions.append(transaction)
            return True
        else:
            print("Invalid transaction")
            return False

    def mine_pending_transactions(self):
        block = Block(self.chain[-1].hash, self.pending_transactions)
        self.add_block(block)
        self.pending_transactions = []

# Usage example
if __name__ == '__main__':
    pr, pu = generate_keys()
    blockchain = Blockchain()

    message = "Hi I am code eater"
    signature = sign(message, pr)

    sender = "Alice"
    recipient = "Bob"
    amount = 10

    # Sign the transaction
    transaction_signature = sign(f'{sender}{recipient}{amount}', pr)

    # Add the transaction to the blockchain
    if blockchain.add_transaction(sender, recipient, amount, transaction_signature, pu):
        print("Transaction added")
    else:
        print("Transaction failed")

    # Mine a new block
    blockchain.mine_pending_transactions()

    # Print the blockchain
    for block in blockchain.chain:
        print(block.__dict__)
