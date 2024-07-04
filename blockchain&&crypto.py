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
    def __init__(self, previous_hash, transactions):
        self.timestamp = time.time()
        self.previous_hash = previous_hash
        self.transactions = transactions  # list of Transaction objects
        self.nonce = 0  # Initial nonce set to 0
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

    def mine_block(self, difficulty):
        while not self.hash.startswith('0' * difficulty):
            self.nonce += 1
            self.hash = self.compute_hash()
        print(f"Block mined: {self.hash}")

class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []
        self.difficulty = 2  # Set difficulty for mining (number of leading zeros required in hash)
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block("0", [])
        self.chain.append(genesis_block)

    def add_block(self, block):
        if len(self.chain) > 0:
            block.previous_hash = self.chain[-1].hash
        block.mine_block(self.difficulty)
        self.chain.append(block)

    def add_transaction(self, sender, recipient, amount, signature, public_key):
        transaction = Transaction(sender, recipient, amount, signature)
        if verify(f'{sender}{recipient}{amount}', signature, public_key):
            self.pending_transactions.append(transaction)
            print("Transaction added")
            return True
        else:
            print("Invalid transaction")
            return False

    def mine_pending_transactions(self):
        block = Block(self.chain[-1].hash, self.pending_transactions)
        block.mine_block(self.difficulty)
        self.chain.append(block)
        self.pending_transactions = []

    def display_blockchain(self):
        for index, block in enumerate(self.chain):
            print(f'Block {index}:')
            print(f'Timestamp: {block.timestamp}')
            print(f'Previous Hash: {block.previous_hash}')
            print(f'Hash: {block.hash}')
            print(f'Nonce: {block.nonce}')
            print('Transactions:')
            for tx in block.transactions:
                print(f'    Sender: {tx.sender}')
                print(f'    Recipient: {tx.recipient}')
                print(f'    Amount: {tx.amount}')
                print(f'    Signature: {tx.signature.hex()}')
            print('-' * 30)


# Usage example
if __name__ == '__main__':
    pr, pu = generate_keys()
    blockchain = Blockchain()

    message = "Hi I am moncef bahja "
    signature = sign(message, pr)

    sender = "moncef"
    recipient = "mohameden"
    amount = 10

    # Sign the transaction
    transaction_signature = sign(f'{sender}{recipient}{amount}', pr)

    # Add the transaction to the blockchain
    blockchain.add_transaction(sender, recipient, amount, transaction_signature, pu)

    # Mine a new block
    blockchain.mine_pending_transactions()

    pr1, pu1 = generate_keys()
    signature = sign(message, pr1)
    sender = "mohameden"
    recipient = "moncef"
    
    amount = 20
    transaction_signature = sign(f'{sender}{recipient}{amount}', pr1)
    blockchain.add_transaction(sender, recipient, amount, transaction_signature, pu1)

    blockchain.mine_pending_transactions()

    # Print the blockchain
    blockchain.display_blockchain()
