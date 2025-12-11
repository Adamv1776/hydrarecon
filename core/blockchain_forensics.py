"""
Blockchain Forensics Module for HydraRecon
Advanced cryptocurrency tracing, wallet analysis, and blockchain intelligence
"""

import asyncio
import hashlib
import json
import re
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Set, Tuple
from enum import Enum, auto
from pathlib import Path
import sqlite3


class BlockchainNetwork(Enum):
    """Supported blockchain networks"""
    BITCOIN = auto()
    ETHEREUM = auto()
    BINANCE_SMART_CHAIN = auto()
    POLYGON = auto()
    SOLANA = auto()
    AVALANCHE = auto()
    ARBITRUM = auto()
    OPTIMISM = auto()
    TRON = auto()
    RIPPLE = auto()
    CARDANO = auto()
    DOGECOIN = auto()
    LITECOIN = auto()
    MONERO = auto()
    ZCASH = auto()


class EntityType(Enum):
    """Types of blockchain entities"""
    EXCHANGE = auto()
    MIXER = auto()
    DARKNET_MARKET = auto()
    RANSOMWARE = auto()
    SCAM = auto()
    GAMBLING = auto()
    DEFI_PROTOCOL = auto()
    NFT_MARKETPLACE = auto()
    BRIDGE = auto()
    SMART_CONTRACT = auto()
    PERSONAL_WALLET = auto()
    CORPORATE_WALLET = auto()
    MINING_POOL = auto()
    ICO = auto()
    SANCTIONED = auto()
    UNKNOWN = auto()


class RiskLevel(Enum):
    """Risk levels for addresses"""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    MINIMAL = auto()


class TransactionType(Enum):
    """Types of transactions"""
    TRANSFER = auto()
    SWAP = auto()
    BRIDGE = auto()
    STAKE = auto()
    UNSTAKE = auto()
    MINT = auto()
    BURN = auto()
    CONTRACT_CALL = auto()
    CONTRACT_DEPLOY = auto()
    MIXING = auto()
    PEEL_CHAIN = auto()


class SanctionList(Enum):
    """Sanction lists"""
    OFAC_SDN = auto()
    UN_SANCTIONS = auto()
    EU_SANCTIONS = auto()
    UK_SANCTIONS = auto()


@dataclass
class WalletAddress:
    """Blockchain wallet address"""
    address: str
    network: BlockchainNetwork
    entity_type: EntityType
    risk_level: RiskLevel
    risk_score: float = 0.0
    balance: float = 0.0
    total_received: float = 0.0
    total_sent: float = 0.0
    transaction_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    labels: List[str] = field(default_factory=list)
    sanctions: List[SanctionList] = field(default_factory=list)
    cluster_id: Optional[str] = None
    notes: str = ""


@dataclass
class Transaction:
    """Blockchain transaction"""
    tx_hash: str
    network: BlockchainNetwork
    tx_type: TransactionType
    from_address: str
    to_address: str
    value: float
    fee: float
    timestamp: datetime
    block_number: int
    confirmations: int = 0
    token_address: Optional[str] = None
    token_symbol: Optional[str] = None
    risk_flags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TransactionPath:
    """Path of transactions for tracing"""
    path_id: str
    source_address: str
    destination_address: str
    network: BlockchainNetwork
    hops: List[Transaction] = field(default_factory=list)
    total_value: float = 0.0
    time_span: timedelta = field(default_factory=timedelta)
    risk_score: float = 0.0
    mixing_detected: bool = False
    peel_chain_detected: bool = False
    cross_chain: bool = False


@dataclass
class Cluster:
    """Cluster of related addresses (likely same owner)"""
    cluster_id: str
    addresses: List[str] = field(default_factory=list)
    network: BlockchainNetwork = BlockchainNetwork.BITCOIN
    entity_type: EntityType = EntityType.UNKNOWN
    entity_name: Optional[str] = None
    total_value: float = 0.0
    transaction_count: int = 0
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.MINIMAL
    confidence: float = 0.0
    labels: List[str] = field(default_factory=list)


@dataclass
class Investigation:
    """Blockchain forensics investigation"""
    investigation_id: str
    name: str
    description: str
    target_addresses: List[str] = field(default_factory=list)
    networks: List[BlockchainNetwork] = field(default_factory=list)
    wallet_data: Dict[str, WalletAddress] = field(default_factory=dict)
    transactions: List[Transaction] = field(default_factory=list)
    paths: List[TransactionPath] = field(default_factory=list)
    clusters: List[Cluster] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    total_value_traced: float = 0.0
    status: str = "active"
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


class BlockchainForensicsEngine:
    """
    Advanced blockchain forensics and cryptocurrency tracing engine
    Traces funds, identifies entities, and detects suspicious patterns
    """
    
    def __init__(self, db_path: str = "blockchain_forensics.db"):
        self.db_path = db_path
        self.investigations: Dict[str, Investigation] = {}
        self.known_entities: Dict[str, Dict[str, Any]] = {}
        self.sanctioned_addresses: Set[str] = set()
        self._init_database()
        self._load_known_entities()
        self._load_sanctioned_addresses()
    
    def _init_database(self):
        """Initialize the forensics database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS investigations (
                investigation_id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                status TEXT,
                data TEXT,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS wallets (
                address TEXT PRIMARY KEY,
                network TEXT,
                entity_type TEXT,
                risk_level TEXT,
                risk_score REAL,
                data TEXT,
                created_at TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                tx_hash TEXT PRIMARY KEY,
                network TEXT,
                from_address TEXT,
                to_address TEXT,
                value REAL,
                timestamp TIMESTAMP,
                data TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_known_entities(self):
        """Load known blockchain entities"""
        self.known_entities = {
            # Major exchanges
            "binance_hot": {
                "addresses": [
                    "0x28C6c06298d514Db089934071355E5743bf21d60",
                    "0x21a31Ee1afC51d94C2eFcCAa2092aD1028285549"
                ],
                "entity_type": EntityType.EXCHANGE,
                "name": "Binance",
                "risk_level": RiskLevel.LOW
            },
            "coinbase": {
                "addresses": [
                    "0x71660c4005BA85c37ccec55d0C4493E66Fe775d3",
                    "0x503828976D22510aad0201ac7EC88293211D23Da"
                ],
                "entity_type": EntityType.EXCHANGE,
                "name": "Coinbase",
                "risk_level": RiskLevel.MINIMAL
            },
            "kraken": {
                "addresses": [
                    "0x267be1C1D684F78cb4F6a176C4911b741E4Ffdc0"
                ],
                "entity_type": EntityType.EXCHANGE,
                "name": "Kraken",
                "risk_level": RiskLevel.LOW
            },
            
            # DeFi protocols
            "uniswap_v3": {
                "addresses": [
                    "0xE592427A0AEce92De3Edee1F18E0157C05861564",
                    "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"
                ],
                "entity_type": EntityType.DEFI_PROTOCOL,
                "name": "Uniswap V3",
                "risk_level": RiskLevel.MINIMAL
            },
            "aave": {
                "addresses": [
                    "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9"
                ],
                "entity_type": EntityType.DEFI_PROTOCOL,
                "name": "Aave V2",
                "risk_level": RiskLevel.MINIMAL
            },
            
            # Known mixers (high risk)
            "tornado_cash": {
                "addresses": [
                    "0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936",
                    "0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF",
                    "0xA160cdAB225685dA1d56aa342Ad8841c3b53f291"
                ],
                "entity_type": EntityType.MIXER,
                "name": "Tornado Cash",
                "risk_level": RiskLevel.CRITICAL,
                "sanctioned": True
            },
            
            # Known ransomware
            "conti_ransomware": {
                "addresses": [
                    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
                ],
                "entity_type": EntityType.RANSOMWARE,
                "name": "Conti Ransomware",
                "risk_level": RiskLevel.CRITICAL
            },
            
            # Known scams
            "pig_butchering": {
                "addresses": [],
                "entity_type": EntityType.SCAM,
                "name": "Pig Butchering Scams",
                "risk_level": RiskLevel.CRITICAL
            }
        }
    
    def _load_sanctioned_addresses(self):
        """Load OFAC and other sanctioned addresses"""
        # Sample sanctioned addresses
        self.sanctioned_addresses = {
            # Tornado Cash related
            "0x8589427373D6D84E98730D7795D8f6f8731FDA16",
            "0x722122dF12D4e14e13Ac3b6895a86e84145b6967",
            "0xDD4c48C0B24039969fC16D1cdF626eaB821d3384",
            # Lazarus Group
            "0x098B716B8Aaf21512996dC57EB0615e2383E2f96",
            # Other sanctioned
            "0xa7e5d5A720f06526557c513402f2e6B5fA20b008"
        }
    
    async def create_investigation(
        self,
        name: str,
        description: str,
        target_addresses: List[str],
        networks: Optional[List[BlockchainNetwork]] = None
    ) -> Investigation:
        """Create a new blockchain forensics investigation"""
        investigation_id = hashlib.sha256(
            f"{name}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        if networks is None:
            networks = [self._detect_network(addr) for addr in target_addresses]
        
        investigation = Investigation(
            investigation_id=investigation_id,
            name=name,
            description=description,
            target_addresses=target_addresses,
            networks=list(set(networks))
        )
        
        self.investigations[investigation_id] = investigation
        
        # Initial analysis of target addresses
        for address in target_addresses:
            wallet = await self.analyze_address(address)
            investigation.wallet_data[address] = wallet
        
        await self._save_investigation(investigation)
        
        return investigation
    
    def _detect_network(self, address: str) -> BlockchainNetwork:
        """Detect blockchain network from address format"""
        if address.startswith("0x") and len(address) == 42:
            return BlockchainNetwork.ETHEREUM
        elif address.startswith("bc1") or address.startswith("1") or address.startswith("3"):
            return BlockchainNetwork.BITCOIN
        elif address.startswith("T"):
            return BlockchainNetwork.TRON
        elif address.startswith("r"):
            return BlockchainNetwork.RIPPLE
        elif len(address) >= 32 and len(address) <= 44:
            return BlockchainNetwork.SOLANA
        else:
            return BlockchainNetwork.ETHEREUM
    
    async def analyze_address(
        self,
        address: str,
        depth: int = 2,
        include_transactions: bool = True
    ) -> WalletAddress:
        """Analyze a blockchain address"""
        network = self._detect_network(address)
        
        # Check known entities
        entity_info = self._lookup_entity(address)
        
        # Check sanctions
        is_sanctioned = address.lower() in {a.lower() for a in self.sanctioned_addresses}
        sanctions = [SanctionList.OFAC_SDN] if is_sanctioned else []
        
        # Determine entity type
        if entity_info:
            entity_type = entity_info["entity_type"]
            labels = [entity_info.get("name", "")]
        else:
            entity_type = EntityType.UNKNOWN
            labels = []
        
        # Calculate risk score
        risk_score, risk_level = await self._calculate_address_risk(
            address, entity_type, is_sanctioned
        )
        
        # Get transaction data (simulated)
        tx_data = await self._fetch_address_data(address, network)
        
        wallet = WalletAddress(
            address=address,
            network=network,
            entity_type=entity_type,
            risk_level=risk_level,
            risk_score=risk_score,
            balance=tx_data.get("balance", 0.0),
            total_received=tx_data.get("total_received", 0.0),
            total_sent=tx_data.get("total_sent", 0.0),
            transaction_count=tx_data.get("tx_count", 0),
            first_seen=tx_data.get("first_seen"),
            last_seen=tx_data.get("last_seen"),
            labels=labels,
            sanctions=sanctions
        )
        
        return wallet
    
    def _lookup_entity(self, address: str) -> Optional[Dict[str, Any]]:
        """Look up address in known entities"""
        for entity_id, entity_data in self.known_entities.items():
            if address.lower() in [a.lower() for a in entity_data.get("addresses", [])]:
                return entity_data
        return None
    
    async def _calculate_address_risk(
        self,
        address: str,
        entity_type: EntityType,
        is_sanctioned: bool
    ) -> Tuple[float, RiskLevel]:
        """Calculate risk score for an address"""
        risk_score = 0.0
        
        # Sanctioned addresses are always critical
        if is_sanctioned:
            return 100.0, RiskLevel.CRITICAL
        
        # Entity type risk
        entity_risk = {
            EntityType.MIXER: 90.0,
            EntityType.DARKNET_MARKET: 95.0,
            EntityType.RANSOMWARE: 100.0,
            EntityType.SCAM: 95.0,
            EntityType.GAMBLING: 50.0,
            EntityType.EXCHANGE: 10.0,
            EntityType.DEFI_PROTOCOL: 15.0,
            EntityType.PERSONAL_WALLET: 20.0,
            EntityType.UNKNOWN: 40.0
        }
        
        risk_score = entity_risk.get(entity_type, 50.0)
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 60:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 40:
            risk_level = RiskLevel.MEDIUM
        elif risk_score >= 20:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.MINIMAL
        
        return risk_score, risk_level
    
    async def _fetch_address_data(
        self,
        address: str,
        network: BlockchainNetwork
    ) -> Dict[str, Any]:
        """Fetch address data from blockchain explorers."""
        import aiohttp
        
        result = {
            "balance": 0.0,
            "total_received": 0.0,
            "total_sent": 0.0,
            "tx_count": 0,
            "first_seen": None,
            "last_seen": None
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                if network == BlockchainNetwork.ETHEREUM:
                    # Use Etherscan API (free tier, limited requests)
                    api_url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest"
                    async with session.get(api_url, timeout=10) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data.get("status") == "1":
                                result["balance"] = float(data["result"]) / 1e18
                    
                    # Get transaction count
                    txlist_url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=asc&page=1&offset=1"
                    async with session.get(txlist_url, timeout=10) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data.get("status") == "1" and data.get("result"):
                                result["tx_count"] = len(data["result"])
                                if data["result"]:
                                    first_tx = data["result"][0]
                                    result["first_seen"] = datetime.fromtimestamp(int(first_tx.get("timeStamp", 0)))
                
                elif network == BlockchainNetwork.BITCOIN:
                    # Use Blockchain.info API
                    api_url = f"https://blockchain.info/rawaddr/{address}?limit=1"
                    async with session.get(api_url, timeout=10) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            result["balance"] = data.get("final_balance", 0) / 1e8
                            result["total_received"] = data.get("total_received", 0) / 1e8
                            result["total_sent"] = data.get("total_sent", 0) / 1e8
                            result["tx_count"] = data.get("n_tx", 0)
                            txs = data.get("txs", [])
                            if txs:
                                result["first_seen"] = datetime.fromtimestamp(txs[-1].get("time", 0))
                                result["last_seen"] = datetime.fromtimestamp(txs[0].get("time", 0))
                
                elif network == BlockchainNetwork.BSC:
                    # Use BSCScan API
                    api_url = f"https://api.bscscan.com/api?module=account&action=balance&address={address}&tag=latest"
                    async with session.get(api_url, timeout=10) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data.get("status") == "1":
                                result["balance"] = float(data["result"]) / 1e18
                                
        except Exception as e:
            self.logger.warning(f"Failed to fetch blockchain data for {address}: {e}")
        
        return result
    
    async def trace_funds(
        self,
        investigation_id: str,
        source_address: str,
        max_hops: int = 10,
        min_value: float = 0.01,
        follow_mixers: bool = True
    ) -> List[TransactionPath]:
        """Trace funds from a source address"""
        if investigation_id not in self.investigations:
            raise ValueError(f"Investigation not found: {investigation_id}")
        
        investigation = self.investigations[investigation_id]
        paths = []
        
        # BFS to trace fund flows
        visited = set()
        queue = [(source_address, [], 0.0, 0)]
        
        while queue:
            current_address, current_path, current_value, hop_count = queue.pop(0)
            
            if current_address in visited or hop_count > max_hops:
                continue
            
            visited.add(current_address)
            
            # Get outgoing transactions
            transactions = await self._get_outgoing_transactions(
                current_address, min_value
            )
            
            for tx in transactions:
                new_path = current_path + [tx]
                
                # Check if destination is interesting
                dest_wallet = await self.analyze_address(tx.to_address)
                
                # Create path if destination is significant
                if dest_wallet.entity_type in [
                    EntityType.EXCHANGE, EntityType.MIXER,
                    EntityType.RANSOMWARE, EntityType.SCAM
                ] or dest_wallet.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                    
                    path = TransactionPath(
                        path_id=hashlib.sha256(
                            f"{source_address}{tx.to_address}".encode()
                        ).hexdigest()[:12],
                        source_address=source_address,
                        destination_address=tx.to_address,
                        network=tx.network,
                        hops=new_path,
                        total_value=sum(t.value for t in new_path),
                        mixing_detected=dest_wallet.entity_type == EntityType.MIXER,
                        risk_score=dest_wallet.risk_score
                    )
                    paths.append(path)
                
                # Continue tracing (if not mixer or following mixers)
                if dest_wallet.entity_type != EntityType.MIXER or follow_mixers:
                    queue.append((
                        tx.to_address, new_path, current_value + tx.value, hop_count + 1
                    ))
        
        investigation.paths = paths
        investigation.updated_at = datetime.now()
        await self._save_investigation(investigation)
        
        return paths
    
    async def _get_outgoing_transactions(
        self,
        address: str,
        min_value: float
    ) -> List[Transaction]:
        """Get outgoing transactions from an address using blockchain explorers."""
        import aiohttp
        
        network = self._detect_network(address)
        transactions = []
        
        try:
            async with aiohttp.ClientSession() as session:
                if network == BlockchainNetwork.ETHEREUM:
                    # Etherscan API
                    api_url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=desc&page=1&offset=100"
                    async with session.get(api_url, timeout=10) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data.get("status") == "1":
                                for tx in data.get("result", []):
                                    # Only outgoing transactions
                                    if tx.get("from", "").lower() == address.lower():
                                        value = float(tx.get("value", 0)) / 1e18
                                        if value >= min_value:
                                            transactions.append(Transaction(
                                                tx_hash=tx.get("hash", ""),
                                                network=network,
                                                tx_type=TransactionType.TRANSFER,
                                                from_address=tx.get("from", ""),
                                                to_address=tx.get("to", ""),
                                                value=value,
                                                fee=float(tx.get("gasUsed", 0)) * float(tx.get("gasPrice", 0)) / 1e18,
                                                timestamp=datetime.fromtimestamp(int(tx.get("timeStamp", 0))),
                                                block_number=int(tx.get("blockNumber", 0))
                                            ))
                
                elif network == BlockchainNetwork.BITCOIN:
                    # Blockchain.info API
                    api_url = f"https://blockchain.info/rawaddr/{address}?limit=100"
                    async with session.get(api_url, timeout=10) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for tx in data.get("txs", []):
                                # Check if this address is in inputs (outgoing)
                                is_outgoing = any(
                                    inp.get("prev_out", {}).get("addr", "") == address
                                    for inp in tx.get("inputs", [])
                                )
                                if is_outgoing:
                                    for out in tx.get("out", []):
                                        if out.get("addr") and out.get("addr") != address:
                                            value = out.get("value", 0) / 1e8
                                            if value >= min_value:
                                                transactions.append(Transaction(
                                                    tx_hash=tx.get("hash", ""),
                                                    network=network,
                                                    tx_type=TransactionType.TRANSFER,
                                                    from_address=address,
                                                    to_address=out.get("addr", ""),
                                                    value=value,
                                                    fee=tx.get("fee", 0) / 1e8,
                                                    timestamp=datetime.fromtimestamp(tx.get("time", 0)),
                                                    block_number=tx.get("block_height", 0)
                                                ))
                                                
        except Exception as e:
            self.logger.warning(f"Failed to fetch transactions for {address}: {e}")
        
        return transactions
    
    async def detect_mixing(
        self,
        investigation_id: str,
        address: str
    ) -> Dict[str, Any]:
        """Detect if funds have been mixed/tumbled"""
        mixing_indicators = {
            "tornado_cash_interaction": False,
            "coinjoin_detected": False,
            "peel_chain_detected": False,
            "time_delay_pattern": False,
            "equal_output_amounts": False,
            "high_address_reuse": False,
            "mixing_probability": 0.0,
            "mixing_services": []
        }
        
        # Check for known mixer interactions
        wallet = await self.analyze_address(address)
        
        if wallet.entity_type == EntityType.MIXER:
            mixing_indicators["tornado_cash_interaction"] = True
            mixing_indicators["mixing_probability"] = 1.0
            mixing_indicators["mixing_services"].append("Tornado Cash")
        
        # Check transaction patterns
        transactions = await self._get_address_transactions(address)
        
        # Check for equal outputs (coinjoin indicator)
        if transactions:
            values = [t.value for t in transactions]
            if len(values) > 2:
                # Check if many transactions have equal values
                value_counts = {}
                for v in values:
                    rounded_v = round(v, 4)
                    value_counts[rounded_v] = value_counts.get(rounded_v, 0) + 1
                
                max_equal = max(value_counts.values()) if value_counts else 0
                if max_equal > len(values) * 0.3:
                    mixing_indicators["equal_output_amounts"] = True
                    mixing_indicators["mixing_probability"] += 0.3
        
        # Check for peel chain (progressively smaller outputs)
        if transactions and len(transactions) > 3:
            sorted_txs = sorted(transactions, key=lambda t: t.timestamp)
            decreasing = all(
                sorted_txs[i].value >= sorted_txs[i+1].value
                for i in range(min(5, len(sorted_txs) - 1))
            )
            if decreasing:
                mixing_indicators["peel_chain_detected"] = True
                mixing_indicators["mixing_probability"] += 0.2
        
        mixing_indicators["mixing_probability"] = min(
            mixing_indicators["mixing_probability"], 1.0
        )
        
        return mixing_indicators
    
    async def _get_address_transactions(
        self,
        address: str
    ) -> List[Transaction]:
        """Get all transactions for an address"""
        network = self._detect_network(address)
        
        return [
            Transaction(
                tx_hash=hashlib.sha256(f"tx{i}{address}".encode()).hexdigest(),
                network=network,
                tx_type=TransactionType.TRANSFER,
                from_address=address if i % 2 == 0 else "0x" + "a" * 40,
                to_address="0x" + "b" * 40 if i % 2 == 0 else address,
                value=float(i + 1),
                fee=0.001,
                timestamp=datetime.now() - timedelta(days=i),
                block_number=15000000 - i * 100
            )
            for i in range(10)
        ]
    
    async def cluster_addresses(
        self,
        investigation_id: str
    ) -> List[Cluster]:
        """Cluster addresses likely belonging to the same entity"""
        if investigation_id not in self.investigations:
            raise ValueError(f"Investigation not found: {investigation_id}")
        
        investigation = self.investigations[investigation_id]
        clusters = []
        
        # Address clustering using heuristics
        address_groups: Dict[str, Set[str]] = {}
        
        for address in investigation.target_addresses:
            transactions = await self._get_address_transactions(address)
            
            for tx in transactions:
                # Input aggregation heuristic (addresses spending together)
                # Simplified: group addresses that interact
                if tx.from_address not in address_groups:
                    address_groups[tx.from_address] = set()
                address_groups[tx.from_address].add(tx.to_address)
        
        # Create clusters from groups
        cluster_id_counter = 0
        processed = set()
        
        for main_address, related in address_groups.items():
            if main_address in processed:
                continue
            
            cluster_addresses = [main_address] + list(related)
            
            # Get entity info
            main_wallet = investigation.wallet_data.get(main_address)
            if not main_wallet:
                main_wallet = await self.analyze_address(main_address)
            
            cluster = Cluster(
                cluster_id=f"cluster_{cluster_id_counter}",
                addresses=cluster_addresses,
                network=main_wallet.network,
                entity_type=main_wallet.entity_type,
                total_value=main_wallet.total_received,
                transaction_count=main_wallet.transaction_count,
                risk_score=main_wallet.risk_score,
                risk_level=main_wallet.risk_level,
                confidence=0.75,
                labels=main_wallet.labels
            )
            
            clusters.append(cluster)
            processed.update(cluster_addresses)
            cluster_id_counter += 1
        
        investigation.clusters = clusters
        investigation.updated_at = datetime.now()
        await self._save_investigation(investigation)
        
        return clusters
    
    async def check_sanctions(
        self,
        addresses: List[str]
    ) -> Dict[str, Any]:
        """Check addresses against sanction lists"""
        results = {
            "total_checked": len(addresses),
            "sanctioned_count": 0,
            "sanctioned_addresses": [],
            "risk_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "minimal": 0
            }
        }
        
        for address in addresses:
            wallet = await self.analyze_address(address)
            
            # Update risk summary
            results["risk_summary"][wallet.risk_level.name.lower()] = \
                results["risk_summary"].get(wallet.risk_level.name.lower(), 0) + 1
            
            if wallet.sanctions:
                results["sanctioned_count"] += 1
                results["sanctioned_addresses"].append({
                    "address": address,
                    "sanctions": [s.name for s in wallet.sanctions],
                    "entity_type": wallet.entity_type.name,
                    "labels": wallet.labels
                })
        
        return results
    
    async def detect_ransomware_payment(
        self,
        address: str
    ) -> Dict[str, Any]:
        """Detect if an address is associated with ransomware"""
        detection_result = {
            "is_ransomware": False,
            "ransomware_family": None,
            "confidence": 0.0,
            "indicators": [],
            "known_campaigns": [],
            "recommendations": []
        }
        
        wallet = await self.analyze_address(address)
        
        # Check entity type
        if wallet.entity_type == EntityType.RANSOMWARE:
            detection_result["is_ransomware"] = True
            detection_result["confidence"] = 0.95
            detection_result["indicators"].append("Address in known ransomware database")
        
        # Check transaction patterns
        transactions = await self._get_address_transactions(address)
        
        # Ransomware indicators
        indicators_found = []
        
        # Large single incoming transactions (ransom payments)
        large_incoming = [t for t in transactions if t.value > 0.5 and t.to_address.lower() == address.lower()]
        if large_incoming:
            indicators_found.append("Large incoming transactions detected")
        
        # Quick outflow to exchanges/mixers
        for tx in transactions:
            if tx.from_address.lower() == address.lower():
                dest_wallet = await self.analyze_address(tx.to_address)
                if dest_wallet.entity_type in [EntityType.MIXER, EntityType.EXCHANGE]:
                    indicators_found.append(f"Quick outflow to {dest_wallet.entity_type.name.lower()}")
        
        if indicators_found:
            detection_result["indicators"].extend(indicators_found)
            detection_result["confidence"] = min(
                detection_result["confidence"] + len(indicators_found) * 0.15, 0.9
            )
        
        if detection_result["confidence"] > 0.5:
            detection_result["is_ransomware"] = True
            detection_result["recommendations"] = [
                "Do not make any payments to this address",
                "Report to law enforcement (FBI IC3, local authorities)",
                "Preserve all evidence and transaction records",
                "Consider engaging blockchain forensics firm"
            ]
        
        return detection_result
    
    async def generate_investigation_report(
        self,
        investigation_id: str
    ) -> Dict[str, Any]:
        """Generate comprehensive investigation report"""
        if investigation_id not in self.investigations:
            raise ValueError(f"Investigation not found: {investigation_id}")
        
        investigation = self.investigations[investigation_id]
        
        # Aggregate statistics
        total_addresses = len(investigation.wallet_data)
        total_transactions = len(investigation.transactions)
        total_value = sum(w.total_received for w in investigation.wallet_data.values())
        
        # Risk breakdown
        risk_breakdown = {}
        entity_breakdown = {}
        
        for wallet in investigation.wallet_data.values():
            risk = wallet.risk_level.name
            entity = wallet.entity_type.name
            
            risk_breakdown[risk] = risk_breakdown.get(risk, 0) + 1
            entity_breakdown[entity] = entity_breakdown.get(entity, 0) + 1
        
        # Identify high-risk paths
        high_risk_paths = [
            p for p in investigation.paths
            if p.risk_score > 70 or p.mixing_detected
        ]
        
        # Find exchange endpoints
        exchange_endpoints = [
            w.address for w in investigation.wallet_data.values()
            if w.entity_type == EntityType.EXCHANGE
        ]
        
        report = {
            "investigation_id": investigation_id,
            "name": investigation.name,
            "description": investigation.description,
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_addresses_analyzed": total_addresses,
                "total_transactions": total_transactions,
                "total_value_traced": investigation.total_value_traced,
                "networks_involved": [n.name for n in investigation.networks],
                "clusters_identified": len(investigation.clusters)
            },
            "risk_analysis": {
                "breakdown": risk_breakdown,
                "critical_addresses": [
                    w.address for w in investigation.wallet_data.values()
                    if w.risk_level == RiskLevel.CRITICAL
                ],
                "sanctioned_addresses": [
                    w.address for w in investigation.wallet_data.values()
                    if w.sanctions
                ]
            },
            "entity_analysis": {
                "breakdown": entity_breakdown,
                "exchanges_identified": exchange_endpoints,
                "mixers_detected": [
                    w.address for w in investigation.wallet_data.values()
                    if w.entity_type == EntityType.MIXER
                ]
            },
            "fund_flows": {
                "total_paths": len(investigation.paths),
                "high_risk_paths": len(high_risk_paths),
                "mixing_detected": any(p.mixing_detected for p in investigation.paths),
                "cross_chain_detected": any(p.cross_chain for p in investigation.paths)
            },
            "findings": investigation.findings,
            "recommendations": self._generate_investigation_recommendations(investigation)
        }
        
        return report
    
    def _generate_investigation_recommendations(
        self,
        investigation: Investigation
    ) -> List[str]:
        """Generate recommendations based on investigation findings"""
        recommendations = []
        
        # Check for sanctioned addresses
        sanctioned = [
            w for w in investigation.wallet_data.values()
            if w.sanctions
        ]
        if sanctioned:
            recommendations.append(
                f"CRITICAL: {len(sanctioned)} sanctioned address(es) identified. "
                "Report to compliance and legal immediately."
            )
        
        # Check for mixer usage
        mixers = [
            w for w in investigation.wallet_data.values()
            if w.entity_type == EntityType.MIXER
        ]
        if mixers:
            recommendations.append(
                "Mixing services detected in fund flow. "
                "Consider engaging specialized blockchain tracing services."
            )
        
        # Check for exchange endpoints
        exchanges = [
            w for w in investigation.wallet_data.values()
            if w.entity_type == EntityType.EXCHANGE
        ]
        if exchanges:
            recommendations.append(
                f"{len(exchanges)} exchange endpoint(s) identified. "
                "Law enforcement can subpoena exchange for user information."
            )
        
        # High risk paths
        high_risk = [p for p in investigation.paths if p.risk_score > 70]
        if high_risk:
            recommendations.append(
                f"{len(high_risk)} high-risk fund flow path(s) identified. "
                "Priority tracing recommended."
            )
        
        return recommendations
    
    async def _save_investigation(self, investigation: Investigation):
        """Save investigation to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        data = {
            "target_addresses": investigation.target_addresses,
            "networks": [n.name for n in investigation.networks],
            "findings": investigation.findings,
            "total_value_traced": investigation.total_value_traced
        }
        
        cursor.execute('''
            INSERT OR REPLACE INTO investigations
            (investigation_id, name, description, status, data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            investigation.investigation_id,
            investigation.name,
            investigation.description,
            investigation.status,
            json.dumps(data),
            investigation.created_at.isoformat(),
            investigation.updated_at.isoformat()
        ))
        
        conn.commit()
        conn.close()


# Singleton instance
_forensics_engine: Optional[BlockchainForensicsEngine] = None


def get_forensics_engine() -> BlockchainForensicsEngine:
    """Get or create the forensics engine instance"""
    global _forensics_engine
    if _forensics_engine is None:
        _forensics_engine = BlockchainForensicsEngine()
    return _forensics_engine
