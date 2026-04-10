import argparse
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from flask import Flask, jsonify, render_template, request

from blockchain1 import Blockchain, Transaction, Wallet


class NodeState:
    def __init__(self, host, port, peers=None):
        self.host = host
        self.port = port
        self.node_url = f"http://{host}:{port}"
        self.wallet = Wallet(owner_name=f"Node {port}")
        bootstrap_wallet = self.wallet.address if port == 5001 else None
        self.blockchain = Blockchain(
            node_id=self.node_url,
            initial_wallet_address=bootstrap_wallet,
        )
        self.peer_nodes = set()
        self.register_nodes(peers or [])

    def register_nodes(self, nodes):
        registered = set()
        for node in nodes:
            if not node:
                continue
            normalized = node.rstrip("/")
            if not normalized.startswith("http://") and not normalized.startswith("https://"):
                normalized = f"http://{normalized}"
            if normalized == self.node_url:
                continue
            self.peer_nodes.add(normalized)
            registered.add(normalized)
        return sorted(registered)

    def wallet_summary(self):
        return {
            "node_url": self.node_url,
            "port": self.port,
            "address": self.wallet.address,
            "public_key": self.wallet.public_key_pem,
            "balance": self.blockchain.get_balance(self.wallet.address),
            "spendable_balance": self.blockchain.get_spendable_balance(
                self.wallet.address
            ),
        }

    def dashboard_data(self):
        chain_valid, validation_message = self.blockchain.is_valid()
        return {
            "node_url": self.node_url,
            "port": self.port,
            "wallet": self.wallet_summary(),
            "chain_length": len(self.blockchain.chain),
            "difficulty": self.blockchain.difficulty,
            "mining_reward": self.blockchain.mining_reward,
            "pending_count": len(self.blockchain.pending_transactions),
            "peers": sorted(self.peer_nodes),
            "chain_valid": chain_valid,
            "validation_message": validation_message,
            "pending_transactions": self.blockchain.serialize_pending_transactions(),
            "chain": self.blockchain.serialize_chain(),
        }

    def resolve_chain(self):
        best_chain = None
        best_source = None
        best_length = len(self.blockchain.chain)

        for peer in sorted(self.peer_nodes):
            try:
                with urlopen(f"{peer}/chain", timeout=3) as response:
                    data = json.load(response)
                peer_chain = data.get("chain", [])
                peer_length = int(data.get("length", len(peer_chain)))
                candidate_chain = self.blockchain.deserialize_chain(peer_chain)
            except (HTTPError, URLError, ValueError, KeyError, TypeError):
                continue

            if peer_length <= best_length:
                continue

            is_valid, _ = self.blockchain.is_valid(candidate_chain)
            if is_valid:
                best_chain = peer_chain
                best_source = peer
                best_length = peer_length

        if not best_chain:
            return False, "Current chain is already the longest valid chain.", None

        replaced, message = self.blockchain.replace_chain(best_chain)
        return replaced, message, best_source


def create_app(host, port, peers):
    app = Flask(__name__)
    node = NodeState(host, port, peers)

    def error_response(message, status_code=400):
        return jsonify({"message": message}), status_code

    @app.get("/")
    def dashboard():
        return render_template("index.html", node_url=node.node_url, port=node.port)

    @app.get("/dashboard-data")
    def dashboard_data():
        return jsonify(node.dashboard_data())

    @app.get("/chain")
    def get_chain():
        chain_valid, validation_message = node.blockchain.is_valid()
        return jsonify(
            {
                "node_url": node.node_url,
                "length": len(node.blockchain.chain),
                "difficulty": node.blockchain.difficulty,
                "mining_reward": node.blockchain.mining_reward,
                "valid": chain_valid,
                "validation_message": validation_message,
                "chain": node.blockchain.serialize_chain(),
            }
        )

    @app.get("/wallet")
    def get_wallet():
        wallet_data = node.wallet_summary()
        wallet_data["pending_transactions"] = len(node.blockchain.pending_transactions)
        return jsonify(wallet_data)

    @app.get("/transactions/pending")
    def get_pending_transactions():
        return jsonify(
            {
                "node_url": node.node_url,
                "count": len(node.blockchain.pending_transactions),
                "pending_transactions": node.blockchain.serialize_pending_transactions(),
            }
        )

    @app.post("/transactions/broadcast")
    def broadcast_transaction():
        payload = request.get_json(silent=True) or {}
        transaction_id = payload.get("transaction_id")
        if not isinstance(transaction_id, str) or not transaction_id.strip():
            return error_response("transaction_id is required.", 400)

        transaction_id = transaction_id.strip()
        transaction = next(
            (
                pending_transaction
                for pending_transaction in node.blockchain.pending_transactions
                if pending_transaction.transaction_id() == transaction_id
            ),
            None,
        )
        if not transaction:
            return error_response("Transaction not found in pending pool.", 404)

        success = []
        failed = []
        request_body = json.dumps(transaction.to_dict()).encode()

        for peer in sorted(node.peer_nodes):
            try:
                request_obj = Request(
                    f"{peer}/transactions/new",
                    data=request_body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urlopen(request_obj, timeout=3):
                    pass
                success.append(peer)
            except (HTTPError, URLError):
                failed.append(peer)

        return jsonify(
            {
                "message": "Broadcast complete.",
                "transaction_id": transaction_id,
                "success": success,
                "failed": failed,
            }
        )

    @app.post("/transactions/validate")
    def validate_transaction():
        payload = request.get_json(silent=True) or {}
        required_fields = {
            "sender_address",
            "recipient_address",
            "amount",
            "timestamp",
            "signature",
            "public_key",
        }
        if not required_fields.issubset(payload):
            return error_response("Full transaction payload is required for validation.", 400)

        try:
            transaction = Transaction.from_dict(payload)
        except (KeyError, TypeError, ValueError):
            return error_response("Transaction payload is invalid.", 400)

        is_valid, message = transaction.validate_signature()
        status_code = 200 if is_valid else 400
        return jsonify(
            {
                "valid": is_valid,
                "message": message,
                "transaction": transaction.to_dict(),
            }
        ), status_code

    @app.post("/transactions/new")
    def create_transaction():
        payload = request.get_json(silent=True) or {}
        is_full_payload = {
            "sender_address",
            "recipient_address",
            "amount",
            "timestamp",
            "signature",
            "public_key",
        }.issubset(payload)

        try:
            if is_full_payload:
                transaction = Transaction.from_dict(payload)
            else:
                recipient_address = payload["recipient_address"]
                amount = payload["amount"]
                transaction = node.wallet.create_transaction(recipient_address, amount)
        except KeyError:
            return error_response("recipient_address and amount are required.", 400)
        except (TypeError, ValueError):
            return error_response("Transaction amount must be numeric.", 400)

        added, message = node.blockchain.add_transaction(transaction)

        # For transactions received from peers, try to sync chain once if sender
        # balance is unknown locally but may exist on a longer valid peer chain.
        if (
            not added
            and is_full_payload
            and message == "Insufficient spendable balance."
            and node.peer_nodes
        ):
            node.resolve_chain()
            added, message = node.blockchain.add_transaction(transaction)

        status_code = 201 if added else 400
        return jsonify(
            {
                "message": message,
                "transaction": transaction.to_dict(),
                "signature_valid": transaction.verify_signature(),
                "pending_count": len(node.blockchain.pending_transactions),
            }
        ), status_code

    @app.post("/mine")
    def mine():
        try:
            block = node.blockchain.mine_pending_transactions(node.wallet.address)
        except ValueError as error:
            return error_response(str(error), 400)

        return jsonify(
            {
                "message": "New block mined successfully.",
                "block": block.to_dict(),
                "miner_wallet": node.wallet_summary(),
                "chain_length": len(node.blockchain.chain),
            }
        ), 201

    @app.post("/nodes/register")
    def register_nodes():
        payload = request.get_json(silent=True) or {}
        nodes = payload.get("nodes", [])
        if isinstance(nodes, str):
            nodes = [item.strip() for item in nodes.split(",") if item.strip()]

        if not nodes:
            return error_response("nodes must contain at least one peer node.", 400)

        registered = node.register_nodes(nodes)
        return jsonify(
            {
                "message": "Peer nodes updated.",
                "registered_now": registered,
                "total_nodes": sorted(node.peer_nodes),
            }
        )

    @app.get("/nodes")
    def get_nodes():
        nodes = sorted(node.peer_nodes)
        return jsonify(
            {
                "node_url": node.node_url,
                "total": len(nodes),
                "nodes": nodes,
            }
        )

    @app.get("/nodes/resolve")
    def resolve_nodes():
        replaced, message, source = node.resolve_chain()
        chain_valid, validation_message = node.blockchain.is_valid()
        return jsonify(
            {
                "replaced": replaced,
                "message": message,
                "source": source,
                "chain_length": len(node.blockchain.chain),
                "valid": chain_valid,
                "validation_message": validation_message,
                "chain": node.blockchain.serialize_chain(),
            }
        )

    return app


def parse_args():
    parser = argparse.ArgumentParser(
        description="Educational blockchain node built from the lecturer baseline."
    )
    parser.add_argument("--host", default="127.0.0.1", help="Flask host.")
    parser.add_argument("--port", type=int, default=5001, help="Flask port.")
    parser.add_argument(
        "--peers",
        nargs="*",
        default=[],
        help="Peer nodes, for example http://127.0.0.1:5002 http://127.0.0.1:5003",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    flask_app = create_app(args.host, args.port, args.peers)
    flask_app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
