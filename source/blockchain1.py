import datetime
import hashlib
import json
import random

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


SYSTEM_SENDER = "SYSTEM"
GENESIS_TIMESTAMP = "2026-01-01T00:00:00Z"


def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def sha256_hex(text):
    return hashlib.sha256(text.encode()).hexdigest()


def utc_now():
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def address_from_public_key(public_key_pem):
    return sha256_hex(public_key_pem.strip())[:40]


class Transaction:
    def __init__(
        self,
        sender_address,
        recipient_address,
        amount,
        timestamp=None,
        signature="",
        public_key="",
    ):
        self.sender_address = sender_address
        self.recipient_address = recipient_address
        self.amount = float(amount)
        self.timestamp = timestamp or utc_now()
        self.signature = signature or ""
        self.public_key = public_key or ""

    def payload_dict(self):
        return {
            "sender_address": self.sender_address,
            "recipient_address": self.recipient_address,
            "amount": self.amount,
            "timestamp": self.timestamp,
        }

    def to_dict(self):
        return {
            **self.payload_dict(),
            "signature": self.signature,
            "public_key": self.public_key,
            "transaction_id": self.transaction_id(),
        }

    def transaction_id(self):
        payload = canonical_json(
            {
                **self.payload_dict(),
                "signature": self.signature,
                "public_key": self.public_key,
            }
        )
        return sha256_hex(payload)

    def print(self):
        print(self.to_dict())

    def validate_signature(self):
        if self.amount <= 0:
            return False, "Amount must be greater than 0."

        if not self.recipient_address:
            return False, "Recipient address is required."

        if self.sender_address == SYSTEM_SENDER:
            if self.signature or self.public_key:
                return False, "System transaction cannot contain a signature or public key."
            return True, "System transaction accepted."

        if not self.sender_address:
            return False, "Sender address is required."

        if not self.signature:
            return False, "Transaction signature is missing."

        if not self.public_key:
            return False, "Sender public key is missing."

        expected_address = address_from_public_key(self.public_key)
        if expected_address != self.sender_address:
            return False, "Sender address does not match the supplied public key."

        try:
            public_key = serialization.load_pem_public_key(self.public_key.encode())
            public_key.verify(
                bytes.fromhex(self.signature),
                canonical_json(self.payload_dict()).encode(),
                ec.ECDSA(hashes.SHA256()),
            )
        except (TypeError, ValueError, InvalidSignature):
            return False, "Digital signature verification failed."

        return True, "Digital signature valid."

    def verify_signature(self):
        return self.validate_signature()[0]

    @classmethod
    def from_dict(cls, data):
        return cls(
            sender_address=data["sender_address"],
            recipient_address=data["recipient_address"],
            amount=data["amount"],
            timestamp=data.get("timestamp"),
            signature=data.get("signature", ""),
            public_key=data.get("public_key", ""),
        )


class Block:
    def __init__(
        self,
        index,
        transactions,
        previous_hash,
        timestamp=None,
        nonce=0,
        block_hash=None,
    ):
        self.index = index
        self.timestamp = timestamp or utc_now()
        self.transactions = [
            transaction
            if isinstance(transaction, Transaction)
            else Transaction.from_dict(transaction)
            for transaction in transactions
        ]
        self.nonce = nonce
        self.previous_hash = previous_hash
        self.hash = block_hash or self.calculate_hash()

    def calculate_hash(self):
        block = {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [transaction.to_dict() for transaction in self.transactions],
            "nonce": self.nonce,
            "previous_hash": self.previous_hash,
        }
        return sha256_hex(canonical_json(block))

    def print_hash(self):
        print(self.calculate_hash())

    def mine_block(self, difficulty):
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()
        return self.hash

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [transaction.to_dict() for transaction in self.transactions],
            "nonce": self.nonce,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            index=data["index"],
            transactions=data.get("transactions", []),
            previous_hash=data["previous_hash"],
            timestamp=data.get("timestamp"),
            nonce=data.get("nonce", 0),
            block_hash=data.get("hash"),
        )


class Wallet:
    def __init__(self, owner_name="Node"):
        self.owner_name = owner_name
        self.private_key = ec.generate_private_key(ec.SECP256K1())
        self.public_key = self.private_key.public_key()
        self.private_key_pem = self._export_private_key()
        self.public_key_pem = self._export_public_key()
        self.address = address_from_public_key(self.public_key_pem)

    def _export_private_key(self):
        return (
            self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            .decode()
            .strip()
        )

    def _export_public_key(self):
        return (
            self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
            .strip()
        )

    def sign_payload(self, payload_dict):
        signature = self.private_key.sign(
            canonical_json(payload_dict).encode(),
            ec.ECDSA(hashes.SHA256()),
        )
        return signature.hex()

    def sign_transaction(self, transaction):
        transaction.signature = self.sign_payload(transaction.payload_dict())
        return transaction

    def create_transaction(self, recipient_address, amount):
        transaction = Transaction(
            sender_address=self.address,
            recipient_address=recipient_address,
            amount=amount,
            public_key=self.public_key_pem,
        )
        return self.sign_transaction(transaction)

    def get_balance(self, blockchain, include_pending=False):
        if include_pending:
            return blockchain.get_spendable_balance(self.address)
        return blockchain.get_balance(self.address)

    def to_public_dict(self, blockchain):
        return {
            "owner_name": self.owner_name,
            "address": self.address,
            "public_key": self.public_key_pem,
            "balance": self.get_balance(blockchain),
            "spendable_balance": self.get_balance(blockchain, include_pending=True),
        }


class Blockchain:
    def __init__(
        self,
        difficulty=3,
        mining_reward=25.0,
        node_id="local-node",
        initial_wallet_address=None,
    ):
        self.node_id = node_id
        self.difficulty = difficulty
        self.mining_reward = float(mining_reward)
        self.chain = [self.init_genesis_block()]
        self.pending_transactions = []

        if initial_wallet_address:
            self._create_initial_funding_block(initial_wallet_address)

    def init_genesis_block(self):
        return Block(0, [], "0", timestamp=GENESIS_TIMESTAMP)

    def _create_initial_funding_block(self, wallet_address):
        initial_amount = float(random.randint(50, 100))
        initial_transaction = Transaction(
            sender_address=SYSTEM_SENDER,
            recipient_address=wallet_address,
            amount=initial_amount,
            timestamp=utc_now(),
        )

        block = Block(1, [initial_transaction], self.get_latest_block().hash)
        block.mine_block(self.difficulty)
        self.chain.append(block)

    def get_latest_block(self):
        return self.chain[-1]

    def add_transaction(self, transaction):
        transaction = (
            transaction
            if isinstance(transaction, Transaction)
            else Transaction.from_dict(transaction)
        )

        is_valid, message = self.validate_transaction(transaction)
        if not is_valid:
            return False, message

        if self.has_transaction(transaction.transaction_id()):
            return False, "Transaction already exists in this node."

        self.pending_transactions.append(transaction)
        return True, "Transaction added to pending transactions."

    def add_transactions(self, transaction):
        return self.add_transaction(transaction)

    def validate_transaction(
        self,
        transaction,
        allow_system=False,
        exclude_transaction_id=None,
    ):
        is_signature_valid, message = transaction.validate_signature()
        if not is_signature_valid:
            return False, message

        if transaction.sender_address == SYSTEM_SENDER:
            if not allow_system:
                return False, "System transaction can only be created during mining."
            return True, "System transaction accepted."

        if transaction.sender_address == transaction.recipient_address:
            return False, "Sender and recipient cannot be the same wallet."

        spendable_balance = self.get_spendable_balance(
            transaction.sender_address,
            exclude_transaction_id=exclude_transaction_id,
        )
        if spendable_balance < transaction.amount:
            return False, "Insufficient spendable balance."

        return True, "Transaction valid."

    def create_reward_transaction(self, miner_address):
        return Transaction(
            sender_address=SYSTEM_SENDER,
            recipient_address=miner_address,
            amount=self.mining_reward,
            timestamp=utc_now(),
        )

    def mine_pending_transactions(self, miner_address):
        if not miner_address:
            raise ValueError("Miner address is required.")

        if not self.pending_transactions and len(self.chain) > 1:
            raise ValueError(
                "Cannot mine without pending transactions after the first block."
            )

        for transaction in self.pending_transactions:
            is_valid, message = self.validate_transaction(
                transaction,
                exclude_transaction_id=transaction.transaction_id(),
            )
            if not is_valid:
                raise ValueError(f"Invalid pending transaction: {message}")

        reward_transaction = self.create_reward_transaction(miner_address)
        transactions_to_mine = self.pending_transactions + [reward_transaction]

        index = len(self.chain)
        previous_hash = self.get_latest_block().hash
        block = Block(index, transactions_to_mine, previous_hash)
        block.mine_block(self.difficulty)

        self.chain.append(block)
        self.pending_transactions = []
        return block

    def get_balance(self, address):
        balance = 0.0
        for block in self.chain:
            for transaction in block.transactions:
                if transaction.sender_address == address:
                    balance -= transaction.amount
                if transaction.recipient_address == address:
                    balance += transaction.amount
        return round(balance, 8)

    def get_spendable_balance(self, address, exclude_transaction_id=None):
        pending_outgoing = sum(
            transaction.amount
            for transaction in self.pending_transactions
            if transaction.sender_address == address
            and transaction.transaction_id() != exclude_transaction_id
        )
        return round(self.get_balance(address) - pending_outgoing, 8)

    def serialize_chain(self):
        return [block.to_dict() for block in self.chain]

    def serialize_pending_transactions(self):
        return [transaction.to_dict() for transaction in self.pending_transactions]

    def deserialize_chain(self, chain_data):
        return [Block.from_dict(block_data) for block_data in chain_data]

    def has_transaction(self, transaction_id):
        for transaction in self.pending_transactions:
            if transaction.transaction_id() == transaction_id:
                return True

        for block in self.chain:
            for transaction in block.transactions:
                if transaction.transaction_id() == transaction_id:
                    return True

        return False

    def is_valid(self, candidate_chain=None):
        chain_to_check = candidate_chain or self.chain
        if not chain_to_check:
            return False, "Chain is empty."

        expected_genesis = self.init_genesis_block().to_dict()
        if chain_to_check[0].to_dict() != expected_genesis:
            return False, "Genesis block does not match."

        balances = {}
        for index in range(1, len(chain_to_check)):
            current = chain_to_check[index]
            previous = chain_to_check[index - 1]

            if current.previous_hash != previous.hash:
                return False, f"Block {current.index} has an invalid previous hash."

            if current.hash != current.calculate_hash():
                return False, f"Block {current.index} hash is invalid."

            if not current.hash.startswith("0" * self.difficulty):
                return False, f"Block {current.index} does not satisfy proof of work."

            reward_transactions = [
                transaction
                for transaction in current.transactions
                if transaction.sender_address == SYSTEM_SENDER
            ]

            is_bootstrap_block = (
                current.index == 1
                and len(current.transactions) == 1
                and len(reward_transactions) == 1
                and 50 <= reward_transactions[0].amount <= 100
            )

            if not is_bootstrap_block:
                if len(reward_transactions) != 1:
                    return False, f"Block {current.index} must contain exactly one reward transaction."

                if reward_transactions[0].amount != self.mining_reward:
                    return False, f"Block {current.index} reward amount is invalid."

                if current.transactions[-1].sender_address != SYSTEM_SENDER:
                    return False, f"Block {current.index} reward transaction must be placed last."

            for transaction in current.transactions:
                is_signature_valid, message = transaction.validate_signature()
                if not is_signature_valid:
                    return False, f"Block {current.index} contains invalid transaction: {message}"

                if transaction.sender_address == SYSTEM_SENDER:
                    balances[transaction.recipient_address] = round(
                        balances.get(transaction.recipient_address, 0.0)
                        + transaction.amount,
                        8,
                    )
                    continue

                sender_balance = balances.get(transaction.sender_address, 0.0)
                if sender_balance < transaction.amount:
                    return (
                        False,
                        f"Block {current.index} contains overspending transaction from "
                        f"{transaction.sender_address}.",
                    )

                balances[transaction.sender_address] = round(
                    sender_balance - transaction.amount, 8
                )
                balances[transaction.recipient_address] = round(
                    balances.get(transaction.recipient_address, 0.0)
                    + transaction.amount,
                    8,
                )

        return True, "Chain is valid."

    def replace_chain(self, chain_data):
        new_chain = self.deserialize_chain(chain_data)
        is_valid, message = self.is_valid(new_chain)
        if not is_valid:
            return False, message

        if len(new_chain) <= len(self.chain):
            return False, "Received chain is not longer than the current chain."

        self.chain = new_chain
        self._remove_confirmed_pending_transactions()
        return True, "Chain replaced with the longest valid chain."

    def _remove_confirmed_pending_transactions(self):
        confirmed_transaction_ids = {
            transaction.transaction_id()
            for block in self.chain
            for transaction in block.transactions
        }
        filtered_transactions = []
        for transaction in self.pending_transactions:
            if transaction.transaction_id() in confirmed_transaction_ids:
                continue
            is_valid, _ = self.validate_transaction(
                transaction,
                exclude_transaction_id=transaction.transaction_id(),
            )
            if is_valid:
                filtered_transactions.append(transaction)
        self.pending_transactions = filtered_transactions

    def to_dict(self):
        is_valid, validation_message = self.is_valid()
        return {
            "node_id": self.node_id,
            "difficulty": self.difficulty,
            "mining_reward": self.mining_reward,
            "length": len(self.chain),
            "pending_transactions": self.serialize_pending_transactions(),
            "chain": self.serialize_chain(),
            "valid": is_valid,
            "validation_message": validation_message,
        }


if __name__ == "__main__":
    wallet_a = Wallet("Alice Node")
    wallet_b = Wallet("Bob Node")
    blockchain = Blockchain()

    print("Wallet A:")
    print(wallet_a.to_public_dict(blockchain))
    print("\nWallet B:")
    print(wallet_b.to_public_dict(blockchain))

    print("\nMining reward for Wallet A...")
    blockchain.mine_pending_transactions(wallet_a.address)
    print("Balance A:", blockchain.get_balance(wallet_a.address))

    transaction = wallet_a.create_transaction(wallet_b.address, 10)
    added, message = blockchain.add_transaction(transaction)
    print("\nAdd transaction:", added, message)

    block = blockchain.mine_pending_transactions(wallet_a.address)
    print("New block hash:", block.hash)
    print("Chain valid?", blockchain.is_valid()[0])
