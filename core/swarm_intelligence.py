#!/usr/bin/env python3
"""
Swarm Intelligence Attack Network - Distributed Coordinated Attack Simulation
Revolutionary swarm-based penetration testing and attack coordination platform.
"""

import asyncio
import hashlib
import json
import logging
import math
import random
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid


class SwarmAlgorithm(Enum):
    """Types of swarm intelligence algorithms."""
    ANT_COLONY = auto()
    PARTICLE_SWARM = auto()
    BEE_ALGORITHM = auto()
    FIREFLY = auto()
    CUCKOO_SEARCH = auto()
    GREY_WOLF = auto()
    WHALE_OPTIMIZATION = auto()
    BAT_ALGORITHM = auto()
    GENETIC = auto()
    DIFFERENTIAL_EVOLUTION = auto()


class AgentState(Enum):
    """States of a swarm agent."""
    IDLE = auto()
    SCOUTING = auto()
    ATTACKING = auto()
    EXPLOITING = auto()
    EVADING = auto()
    EXFILTRATING = auto()
    COORDINATING = auto()
    RETREATING = auto()
    DORMANT = auto()


class AttackPhase(Enum):
    """Attack campaign phases."""
    RECONNAISSANCE = auto()
    WEAPONIZATION = auto()
    DELIVERY = auto()
    EXPLOITATION = auto()
    INSTALLATION = auto()
    COMMAND_AND_CONTROL = auto()
    ACTIONS_ON_OBJECTIVES = auto()


class TargetType(Enum):
    """Types of targets."""
    HOST = auto()
    SERVICE = auto()
    APPLICATION = auto()
    NETWORK_SEGMENT = auto()
    CREDENTIAL_STORE = auto()
    DATABASE = auto()
    FILE_SHARE = auto()
    CLOUD_RESOURCE = auto()
    CONTAINER = auto()
    API_ENDPOINT = auto()


class CommunicationProtocol(Enum):
    """Agent communication protocols."""
    PHEROMONE_TRAIL = auto()  # Ant colony style
    BROADCAST = auto()
    MESH = auto()
    HIERARCHICAL = auto()
    GOSSIP = auto()
    BLOCKCHAIN = auto()


@dataclass
class SwarmAgent:
    """Represents a swarm intelligence agent."""
    agent_id: str
    agent_type: str
    state: AgentState
    position: Tuple[float, float, float]  # 3D position in attack space
    velocity: Tuple[float, float, float]
    fitness: float
    personal_best: Tuple[float, float, float]
    capabilities: List[str]
    memory: Dict[str, Any]
    energy: float = 100.0
    created_at: datetime = field(default_factory=datetime.now)
    last_active: datetime = field(default_factory=datetime.now)
    discoveries: List[str] = field(default_factory=list)
    successful_attacks: int = 0
    failed_attacks: int = 0


@dataclass
class Target:
    """Represents an attack target."""
    target_id: str
    target_type: TargetType
    address: str
    name: str
    vulnerability_score: float
    defense_score: float
    value_score: float
    discovered_vulns: List[str] = field(default_factory=list)
    attack_attempts: int = 0
    successful_attacks: int = 0
    position: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PheromoneTrail:
    """Pheromone trail for ant colony optimization."""
    trail_id: str
    source: str
    destination: str
    pheromone_level: float
    trail_type: str  # success, failure, interesting
    decay_rate: float
    created_at: datetime
    last_reinforced: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackCampaign:
    """Represents a coordinated attack campaign."""
    campaign_id: str
    name: str
    algorithm: SwarmAlgorithm
    phase: AttackPhase
    targets: List[Target]
    agents: List[SwarmAgent]
    objectives: List[str]
    start_time: datetime
    end_time: Optional[datetime]
    global_best: Tuple[float, float, float]
    success_rate: float
    discoveries: List[Dict[str, Any]] = field(default_factory=list)
    tactics: List[str] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SwarmConfiguration:
    """Configuration for swarm behavior."""
    algorithm: SwarmAlgorithm
    population_size: int
    max_iterations: int
    inertia_weight: float
    cognitive_coefficient: float
    social_coefficient: float
    pheromone_evaporation: float
    exploration_rate: float
    communication_protocol: CommunicationProtocol
    coordination_interval: float
    evasion_threshold: float
    mutation_rate: float = 0.1
    crossover_rate: float = 0.8


@dataclass
class SwarmMetrics:
    """Metrics for swarm performance."""
    total_agents: int
    active_agents: int
    total_targets: int
    compromised_targets: int
    discoveries_count: int
    attack_success_rate: float
    average_fitness: float
    convergence_rate: float
    evasion_success_rate: float
    coordination_efficiency: float
    campaign_duration: timedelta
    energy_consumption: float


class SwarmIntelligenceEngine:
    """
    Revolutionary swarm intelligence attack simulation platform.
    
    Features:
    - Multiple swarm algorithms (ACO, PSO, Bee, Firefly, etc.)
    - Distributed attack coordination
    - Adaptive evasion strategies
    - Pheromone-based path optimization
    - Self-organizing attack patterns
    - Collective intelligence exploitation
    """
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or "swarm_intel.db"
        self.logger = logging.getLogger("SwarmIntelligence")
        self.agents: Dict[str, SwarmAgent] = {}
        self.targets: Dict[str, Target] = {}
        self.trails: Dict[str, PheromoneTrail] = {}
        self.campaigns: Dict[str, AttackCampaign] = {}
        self.global_best: Tuple[float, float, float] = (0.0, 0.0, 0.0)
        self.global_best_fitness: float = 0.0
        self.callbacks: Dict[str, List[Callable]] = {}
        
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize SQLite database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                agent_type TEXT,
                state TEXT,
                position TEXT,
                velocity TEXT,
                fitness REAL,
                personal_best TEXT,
                capabilities TEXT,
                energy REAL,
                created_at TEXT,
                last_active TEXT,
                successful_attacks INTEGER,
                failed_attacks INTEGER
            );
            
            CREATE TABLE IF NOT EXISTS targets (
                target_id TEXT PRIMARY KEY,
                target_type TEXT,
                address TEXT,
                name TEXT,
                vulnerability_score REAL,
                defense_score REAL,
                value_score REAL,
                discovered_vulns TEXT,
                attack_attempts INTEGER,
                successful_attacks INTEGER,
                position TEXT,
                metadata TEXT
            );
            
            CREATE TABLE IF NOT EXISTS pheromone_trails (
                trail_id TEXT PRIMARY KEY,
                source TEXT,
                destination TEXT,
                pheromone_level REAL,
                trail_type TEXT,
                decay_rate REAL,
                created_at TEXT,
                last_reinforced TEXT,
                metadata TEXT
            );
            
            CREATE TABLE IF NOT EXISTS campaigns (
                campaign_id TEXT PRIMARY KEY,
                name TEXT,
                algorithm TEXT,
                phase TEXT,
                start_time TEXT,
                end_time TEXT,
                global_best TEXT,
                success_rate REAL,
                discoveries TEXT,
                tactics TEXT,
                constraints TEXT
            );
            
            CREATE TABLE IF NOT EXISTS discoveries (
                discovery_id TEXT PRIMARY KEY,
                campaign_id TEXT,
                agent_id TEXT,
                target_id TEXT,
                discovery_type TEXT,
                details TEXT,
                timestamp TEXT,
                fitness_contribution REAL
            );
        """)
        
        conn.commit()
        conn.close()
    
    async def create_swarm(
        self,
        config: SwarmConfiguration,
        targets: List[Dict[str, Any]]
    ) -> AttackCampaign:
        """
        Create a new attack swarm with the specified configuration.
        
        Args:
            config: Swarm configuration
            targets: List of target definitions
            
        Returns:
            Attack campaign object
        """
        campaign_id = str(uuid.uuid4())[:8]
        
        # Initialize targets
        campaign_targets = []
        for i, target_def in enumerate(targets):
            target = Target(
                target_id=f"target_{campaign_id}_{i}",
                target_type=TargetType[target_def.get("type", "HOST")],
                address=target_def.get("address", ""),
                name=target_def.get("name", f"Target {i}"),
                vulnerability_score=target_def.get("vuln_score", 0.5),
                defense_score=target_def.get("defense_score", 0.5),
                value_score=target_def.get("value_score", 0.5),
                position=self._generate_target_position(i, len(targets))
            )
            campaign_targets.append(target)
            self.targets[target.target_id] = target
        
        # Initialize agents based on algorithm
        agents = await self._initialize_agents(
            config,
            campaign_id,
            campaign_targets
        )
        
        campaign = AttackCampaign(
            campaign_id=campaign_id,
            name=f"Swarm Campaign {campaign_id}",
            algorithm=config.algorithm,
            phase=AttackPhase.RECONNAISSANCE,
            targets=campaign_targets,
            agents=agents,
            objectives=[
                "Discover vulnerabilities",
                "Identify attack paths",
                "Compromise high-value targets",
                "Maintain persistence",
                "Exfiltrate data"
            ],
            start_time=datetime.now(),
            end_time=None,
            global_best=(0.0, 0.0, 0.0),
            success_rate=0.0
        )
        
        self.campaigns[campaign_id] = campaign
        self._save_campaign(campaign)
        
        return campaign
    
    async def _initialize_agents(
        self,
        config: SwarmConfiguration,
        campaign_id: str,
        targets: List[Target]
    ) -> List[SwarmAgent]:
        """Initialize swarm agents based on algorithm."""
        agents = []
        
        for i in range(config.population_size):
            # Random initial position
            position = (
                random.uniform(-10, 10),
                random.uniform(-10, 10),
                random.uniform(-10, 10)
            )
            
            # Random initial velocity
            velocity = (
                random.uniform(-1, 1),
                random.uniform(-1, 1),
                random.uniform(-1, 1)
            )
            
            # Agent type based on algorithm
            agent_type = self._get_agent_type(config.algorithm, i)
            
            # Capabilities based on type
            capabilities = self._assign_capabilities(agent_type)
            
            agent = SwarmAgent(
                agent_id=f"agent_{campaign_id}_{i}",
                agent_type=agent_type,
                state=AgentState.SCOUTING,
                position=position,
                velocity=velocity,
                fitness=0.0,
                personal_best=position,
                capabilities=capabilities,
                memory={
                    "visited_targets": [],
                    "successful_exploits": [],
                    "failed_exploits": [],
                    "pheromone_deposits": []
                }
            )
            
            agents.append(agent)
            self.agents[agent.agent_id] = agent
        
        return agents
    
    def _get_agent_type(self, algorithm: SwarmAlgorithm, index: int) -> str:
        """Get agent type based on algorithm."""
        type_mapping = {
            SwarmAlgorithm.ANT_COLONY: ["worker_ant", "scout_ant", "soldier_ant"],
            SwarmAlgorithm.PARTICLE_SWARM: ["particle", "leader_particle"],
            SwarmAlgorithm.BEE_ALGORITHM: ["scout_bee", "worker_bee", "onlooker_bee"],
            SwarmAlgorithm.FIREFLY: ["firefly", "bright_firefly"],
            SwarmAlgorithm.GREY_WOLF: ["alpha", "beta", "delta", "omega"],
            SwarmAlgorithm.WHALE_OPTIMIZATION: ["whale", "leader_whale"],
            SwarmAlgorithm.BAT_ALGORITHM: ["bat", "leader_bat"],
            SwarmAlgorithm.GENETIC: ["chromosome", "elite"],
            SwarmAlgorithm.DIFFERENTIAL_EVOLUTION: ["vector", "mutant"]
        }
        
        types = type_mapping.get(algorithm, ["agent"])
        return types[index % len(types)]
    
    def _assign_capabilities(self, agent_type: str) -> List[str]:
        """Assign capabilities based on agent type."""
        base_capabilities = ["scan", "probe", "report"]
        
        type_capabilities = {
            "scout_ant": ["reconnaissance", "path_finding"],
            "worker_ant": ["exploitation", "resource_gathering"],
            "soldier_ant": ["attack", "defense_evasion"],
            "scout_bee": ["exploration", "value_assessment"],
            "worker_bee": ["exploitation", "optimization"],
            "alpha": ["coordination", "decision_making", "attack"],
            "beta": ["coordination", "attack", "defense_evasion"],
            "delta": ["attack", "exploitation"],
            "omega": ["reconnaissance", "support"],
            "elite": ["advanced_exploitation", "evasion", "persistence"]
        }
        
        return base_capabilities + type_capabilities.get(agent_type, [])
    
    def _generate_target_position(
        self,
        index: int,
        total: int
    ) -> Tuple[float, float, float]:
        """Generate target position in attack space."""
        angle = 2 * math.pi * index / total
        radius = 5 + random.uniform(-1, 1)
        
        return (
            radius * math.cos(angle),
            radius * math.sin(angle),
            random.uniform(-2, 2)
        )
    
    async def run_iteration(
        self,
        campaign_id: str,
        config: SwarmConfiguration
    ) -> SwarmMetrics:
        """
        Run one iteration of the swarm algorithm.
        
        Args:
            campaign_id: Campaign identifier
            config: Swarm configuration
            
        Returns:
            Swarm metrics for this iteration
        """
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign {campaign_id} not found")
        
        # Algorithm-specific iteration
        if config.algorithm == SwarmAlgorithm.ANT_COLONY:
            await self._ant_colony_iteration(campaign, config)
        elif config.algorithm == SwarmAlgorithm.PARTICLE_SWARM:
            await self._particle_swarm_iteration(campaign, config)
        elif config.algorithm == SwarmAlgorithm.BEE_ALGORITHM:
            await self._bee_algorithm_iteration(campaign, config)
        elif config.algorithm == SwarmAlgorithm.GREY_WOLF:
            await self._grey_wolf_iteration(campaign, config)
        elif config.algorithm == SwarmAlgorithm.GENETIC:
            await self._genetic_iteration(campaign, config)
        else:
            await self._generic_swarm_iteration(campaign, config)
        
        # Update pheromones (evaporation)
        await self._update_pheromones(config.pheromone_evaporation)
        
        # Calculate metrics
        metrics = self._calculate_metrics(campaign)
        
        # Check for phase transition
        await self._check_phase_transition(campaign, metrics)
        
        return metrics
    
    async def _ant_colony_iteration(
        self,
        campaign: AttackCampaign,
        config: SwarmConfiguration
    ) -> None:
        """Ant Colony Optimization iteration."""
        for agent in campaign.agents:
            if agent.energy <= 0:
                agent.state = AgentState.DORMANT
                continue
            
            # Select next target based on pheromone and heuristic
            next_target = await self._aco_select_target(agent, campaign.targets)
            
            if next_target:
                # Move towards target
                agent.position = self._move_towards(
                    agent.position,
                    next_target.position,
                    step_size=0.5
                )
                
                # Try to exploit if close enough
                distance = self._calculate_distance(agent.position, next_target.position)
                
                if distance < 0.5:
                    success = await self._attempt_exploitation(agent, next_target)
                    
                    # Deposit pheromone based on result
                    trail_type = "success" if success else "failure"
                    pheromone_amount = 1.0 if success else 0.1
                    
                    await self._deposit_pheromone(
                        agent.agent_id,
                        next_target.target_id,
                        pheromone_amount,
                        trail_type
                    )
                    
                    agent.memory["visited_targets"].append(next_target.target_id)
            
            # Consume energy
            agent.energy -= 1
            agent.last_active = datetime.now()
    
    async def _aco_select_target(
        self,
        agent: SwarmAgent,
        targets: List[Target]
    ) -> Optional[Target]:
        """Select next target using ACO probability."""
        # Get unvisited targets
        visited = set(agent.memory.get("visited_targets", []))
        unvisited = [t for t in targets if t.target_id not in visited]
        
        if not unvisited:
            # Reset visited if all explored
            agent.memory["visited_targets"] = []
            unvisited = targets
        
        # Calculate selection probabilities
        probabilities = []
        alpha = 1.0  # Pheromone importance
        beta = 2.0   # Heuristic importance
        
        for target in unvisited:
            pheromone = await self._get_pheromone_level(
                agent.agent_id,
                target.target_id
            )
            
            # Heuristic: combination of vulnerability and value
            heuristic = (target.vulnerability_score + target.value_score) / 2
            
            probability = (pheromone ** alpha) * (heuristic ** beta)
            probabilities.append(probability)
        
        # Normalize and select
        total = sum(probabilities) or 1
        probabilities = [p / total for p in probabilities]
        
        return random.choices(unvisited, weights=probabilities, k=1)[0]
    
    async def _particle_swarm_iteration(
        self,
        campaign: AttackCampaign,
        config: SwarmConfiguration
    ) -> None:
        """Particle Swarm Optimization iteration."""
        w = config.inertia_weight
        c1 = config.cognitive_coefficient
        c2 = config.social_coefficient
        
        for agent in campaign.agents:
            if agent.state == AgentState.DORMANT:
                continue
            
            r1 = random.random()
            r2 = random.random()
            
            # Update velocity
            new_velocity = (
                w * agent.velocity[0] + 
                c1 * r1 * (agent.personal_best[0] - agent.position[0]) +
                c2 * r2 * (campaign.global_best[0] - agent.position[0]),
                
                w * agent.velocity[1] + 
                c1 * r1 * (agent.personal_best[1] - agent.position[1]) +
                c2 * r2 * (campaign.global_best[1] - agent.position[1]),
                
                w * agent.velocity[2] + 
                c1 * r1 * (agent.personal_best[2] - agent.position[2]) +
                c2 * r2 * (campaign.global_best[2] - agent.position[2])
            )
            
            # Clamp velocity
            max_vel = 2.0
            new_velocity = tuple(
                max(-max_vel, min(max_vel, v)) for v in new_velocity
            )
            
            agent.velocity = new_velocity
            
            # Update position
            agent.position = (
                agent.position[0] + agent.velocity[0],
                agent.position[1] + agent.velocity[1],
                agent.position[2] + agent.velocity[2]
            )
            
            # Evaluate fitness
            fitness = await self._evaluate_fitness(agent, campaign.targets)
            agent.fitness = fitness
            
            # Update personal best
            if fitness > self._calculate_fitness_at_position(agent.personal_best):
                agent.personal_best = agent.position
            
            # Update global best
            if fitness > campaign.success_rate:
                campaign.global_best = agent.position
                campaign.success_rate = fitness
    
    async def _bee_algorithm_iteration(
        self,
        campaign: AttackCampaign,
        config: SwarmConfiguration
    ) -> None:
        """Artificial Bee Colony iteration."""
        scouts = [a for a in campaign.agents if a.agent_type == "scout_bee"]
        workers = [a for a in campaign.agents if a.agent_type == "worker_bee"]
        onlookers = [a for a in campaign.agents if a.agent_type == "onlooker_bee"]
        
        # Scouts explore new areas
        for scout in scouts:
            scout.position = (
                random.uniform(-10, 10),
                random.uniform(-10, 10),
                random.uniform(-10, 10)
            )
            scout.fitness = await self._evaluate_fitness(scout, campaign.targets)
            scout.state = AgentState.SCOUTING
        
        # Workers exploit known good positions
        for worker in workers:
            # Find best scout position nearby
            best_scout = max(scouts, key=lambda s: s.fitness, default=None)
            if best_scout:
                # Move towards best scout with perturbation
                worker.position = self._perturb_position(
                    best_scout.position,
                    magnitude=0.5
                )
                worker.fitness = await self._evaluate_fitness(worker, campaign.targets)
                worker.state = AgentState.EXPLOITING
        
        # Onlookers choose based on fitness-proportional probability
        fitness_sum = sum(a.fitness for a in workers) or 1
        
        for onlooker in onlookers:
            # Roulette wheel selection
            r = random.random() * fitness_sum
            cumsum = 0
            selected_worker = workers[0] if workers else scouts[0]
            
            for worker in workers:
                cumsum += worker.fitness
                if cumsum >= r:
                    selected_worker = worker
                    break
            
            # Exploit near selected worker
            onlooker.position = self._perturb_position(
                selected_worker.position,
                magnitude=0.3
            )
            onlooker.fitness = await self._evaluate_fitness(
                onlooker,
                campaign.targets
            )
    
    async def _grey_wolf_iteration(
        self,
        campaign: AttackCampaign,
        config: SwarmConfiguration
    ) -> None:
        """Grey Wolf Optimizer iteration."""
        # Sort agents by fitness to determine hierarchy
        sorted_agents = sorted(
            campaign.agents,
            key=lambda a: a.fitness,
            reverse=True
        )
        
        if len(sorted_agents) < 3:
            return
        
        alpha = sorted_agents[0]
        beta = sorted_agents[1]
        delta = sorted_agents[2]
        omegas = sorted_agents[3:]
        
        # Update alpha, beta, delta types
        alpha.agent_type = "alpha"
        beta.agent_type = "beta"
        delta.agent_type = "delta"
        for omega in omegas:
            omega.agent_type = "omega"
        
        # Update omega wolves position based on alpha, beta, delta
        for omega in omegas:
            a = 2 - 2 * (1 / config.max_iterations)  # Linearly decreasing
            
            # Calculate D vectors
            r1, r2 = random.random(), random.random()
            A1 = 2 * a * r1 - a
            C1 = 2 * r2
            
            D_alpha = tuple(
                abs(C1 * alpha.position[i] - omega.position[i])
                for i in range(3)
            )
            X1 = tuple(
                alpha.position[i] - A1 * D_alpha[i]
                for i in range(3)
            )
            
            r1, r2 = random.random(), random.random()
            A2 = 2 * a * r1 - a
            C2 = 2 * r2
            
            D_beta = tuple(
                abs(C2 * beta.position[i] - omega.position[i])
                for i in range(3)
            )
            X2 = tuple(
                beta.position[i] - A2 * D_beta[i]
                for i in range(3)
            )
            
            r1, r2 = random.random(), random.random()
            A3 = 2 * a * r1 - a
            C3 = 2 * r2
            
            D_delta = tuple(
                abs(C3 * delta.position[i] - omega.position[i])
                for i in range(3)
            )
            X3 = tuple(
                delta.position[i] - A3 * D_delta[i]
                for i in range(3)
            )
            
            # New position is average of X1, X2, X3
            omega.position = tuple(
                (X1[i] + X2[i] + X3[i]) / 3
                for i in range(3)
            )
            
            omega.fitness = await self._evaluate_fitness(omega, campaign.targets)
    
    async def _genetic_iteration(
        self,
        campaign: AttackCampaign,
        config: SwarmConfiguration
    ) -> None:
        """Genetic Algorithm iteration."""
        population = campaign.agents
        
        # Evaluate fitness
        for agent in population:
            agent.fitness = await self._evaluate_fitness(agent, campaign.targets)
        
        # Sort by fitness
        population.sort(key=lambda a: a.fitness, reverse=True)
        
        # Elite selection (top 10%)
        elite_count = max(1, len(population) // 10)
        elites = population[:elite_count]
        
        for elite in elites:
            elite.agent_type = "elite"
        
        # Create new population
        new_population = list(elites)
        
        while len(new_population) < len(population):
            # Tournament selection
            parent1 = self._tournament_select(population, tournament_size=3)
            parent2 = self._tournament_select(population, tournament_size=3)
            
            # Crossover
            if random.random() < config.crossover_rate:
                child_pos = self._crossover(parent1.position, parent2.position)
            else:
                child_pos = parent1.position
            
            # Mutation
            if random.random() < config.mutation_rate:
                child_pos = self._mutate(child_pos)
            
            # Create child agent
            child = SwarmAgent(
                agent_id=f"agent_{campaign.campaign_id}_{len(new_population)}",
                agent_type="chromosome",
                state=AgentState.SCOUTING,
                position=child_pos,
                velocity=(0, 0, 0),
                fitness=0.0,
                personal_best=child_pos,
                capabilities=self._assign_capabilities("chromosome"),
                memory={}
            )
            
            new_population.append(child)
        
        campaign.agents = new_population[:len(population)]
        
        for agent in campaign.agents:
            self.agents[agent.agent_id] = agent
    
    def _tournament_select(
        self,
        population: List[SwarmAgent],
        tournament_size: int
    ) -> SwarmAgent:
        """Tournament selection for genetic algorithm."""
        tournament = random.sample(population, min(tournament_size, len(population)))
        return max(tournament, key=lambda a: a.fitness)
    
    def _crossover(
        self,
        pos1: Tuple[float, float, float],
        pos2: Tuple[float, float, float]
    ) -> Tuple[float, float, float]:
        """Single-point crossover for positions."""
        crossover_point = random.randint(0, 2)
        
        child = list(pos1[:crossover_point]) + list(pos2[crossover_point:])
        return tuple(child)
    
    def _mutate(
        self,
        position: Tuple[float, float, float]
    ) -> Tuple[float, float, float]:
        """Mutate position with Gaussian noise."""
        return tuple(
            p + random.gauss(0, 0.5) for p in position
        )
    
    async def _generic_swarm_iteration(
        self,
        campaign: AttackCampaign,
        config: SwarmConfiguration
    ) -> None:
        """Generic swarm iteration for other algorithms."""
        for agent in campaign.agents:
            # Random movement with attraction to best known position
            best_target = max(
                campaign.targets,
                key=lambda t: t.vulnerability_score * t.value_score,
                default=None
            )
            
            if best_target:
                agent.position = self._move_towards(
                    agent.position,
                    best_target.position,
                    step_size=random.uniform(0.1, 0.5)
                )
            
            agent.fitness = await self._evaluate_fitness(agent, campaign.targets)
    
    async def _evaluate_fitness(
        self,
        agent: SwarmAgent,
        targets: List[Target]
    ) -> float:
        """Evaluate agent fitness based on proximity to valuable targets."""
        fitness = 0.0
        
        for target in targets:
            distance = self._calculate_distance(agent.position, target.position)
            
            if distance < 0.1:
                distance = 0.1  # Prevent division by zero
            
            # Fitness contribution from this target
            contribution = (
                target.vulnerability_score * target.value_score
            ) / distance
            
            fitness += contribution
            
            # Bonus for successful exploitation
            if distance < 0.5:
                if await self._attempt_exploitation(agent, target, dry_run=True):
                    fitness += target.value_score * 10
        
        return fitness
    
    async def _attempt_exploitation(
        self,
        agent: SwarmAgent,
        target: Target,
        dry_run: bool = False
    ) -> bool:
        """Attempt to exploit a target."""
        # Calculate success probability
        attack_strength = len(agent.capabilities) * 0.1
        success_prob = (
            target.vulnerability_score * attack_strength *
            (1 - target.defense_score)
        )
        
        success = random.random() < success_prob
        
        if not dry_run:
            target.attack_attempts += 1
            
            if success:
                target.successful_attacks += 1
                agent.successful_attacks += 1
                
                # Record discovery
                agent.discoveries.append({
                    "target": target.target_id,
                    "type": "exploitation",
                    "timestamp": datetime.now().isoformat()
                })
            else:
                agent.failed_attacks += 1
        
        return success
    
    def _calculate_distance(
        self,
        pos1: Tuple[float, float, float],
        pos2: Tuple[float, float, float]
    ) -> float:
        """Calculate Euclidean distance between positions."""
        return math.sqrt(
            sum((a - b) ** 2 for a, b in zip(pos1, pos2))
        )
    
    def _move_towards(
        self,
        current: Tuple[float, float, float],
        target: Tuple[float, float, float],
        step_size: float
    ) -> Tuple[float, float, float]:
        """Move position towards target by step size."""
        direction = tuple(t - c for c, t in zip(current, target))
        magnitude = math.sqrt(sum(d ** 2 for d in direction))
        
        if magnitude < 0.01:
            return current
        
        # Normalize and scale by step size
        normalized = tuple(d / magnitude for d in direction)
        step = min(step_size, magnitude)
        
        return tuple(c + n * step for c, n in zip(current, normalized))
    
    def _perturb_position(
        self,
        position: Tuple[float, float, float],
        magnitude: float
    ) -> Tuple[float, float, float]:
        """Add random perturbation to position."""
        return tuple(
            p + random.uniform(-magnitude, magnitude)
            for p in position
        )
    
    def _calculate_fitness_at_position(
        self,
        position: Tuple[float, float, float]
    ) -> float:
        """Calculate hypothetical fitness at a position."""
        fitness = 0.0
        
        for target in self.targets.values():
            distance = self._calculate_distance(position, target.position)
            if distance < 0.1:
                distance = 0.1
            
            fitness += (
                target.vulnerability_score * target.value_score
            ) / distance
        
        return fitness
    
    async def _deposit_pheromone(
        self,
        source: str,
        destination: str,
        amount: float,
        trail_type: str
    ) -> None:
        """Deposit pheromone on a trail."""
        trail_id = hashlib.sha256(
            f"{source}_{destination}".encode()
        ).hexdigest()[:16]
        
        if trail_id in self.trails:
            trail = self.trails[trail_id]
            trail.pheromone_level += amount
            trail.last_reinforced = datetime.now()
        else:
            trail = PheromoneTrail(
                trail_id=trail_id,
                source=source,
                destination=destination,
                pheromone_level=amount,
                trail_type=trail_type,
                decay_rate=0.1,
                created_at=datetime.now(),
                last_reinforced=datetime.now()
            )
            self.trails[trail_id] = trail
    
    async def _get_pheromone_level(
        self,
        source: str,
        destination: str
    ) -> float:
        """Get pheromone level on a trail."""
        trail_id = hashlib.sha256(
            f"{source}_{destination}".encode()
        ).hexdigest()[:16]
        
        trail = self.trails.get(trail_id)
        return trail.pheromone_level if trail else 0.1  # Base pheromone
    
    async def _update_pheromones(self, evaporation_rate: float) -> None:
        """Update pheromones with evaporation."""
        for trail in self.trails.values():
            trail.pheromone_level *= (1 - evaporation_rate)
            
            # Minimum pheromone level
            if trail.pheromone_level < 0.01:
                trail.pheromone_level = 0.01
    
    def _calculate_metrics(self, campaign: AttackCampaign) -> SwarmMetrics:
        """Calculate swarm metrics."""
        active_agents = [
            a for a in campaign.agents
            if a.state != AgentState.DORMANT
        ]
        
        compromised = [
            t for t in campaign.targets
            if t.successful_attacks > 0
        ]
        
        total_attacks = sum(a.successful_attacks + a.failed_attacks for a in campaign.agents)
        successful_attacks = sum(a.successful_attacks for a in campaign.agents)
        
        avg_fitness = (
            sum(a.fitness for a in campaign.agents) / len(campaign.agents)
            if campaign.agents else 0
        )
        
        energy_consumed = sum(100 - a.energy for a in campaign.agents)
        
        return SwarmMetrics(
            total_agents=len(campaign.agents),
            active_agents=len(active_agents),
            total_targets=len(campaign.targets),
            compromised_targets=len(compromised),
            discoveries_count=sum(len(a.discoveries) for a in campaign.agents),
            attack_success_rate=successful_attacks / total_attacks if total_attacks else 0,
            average_fitness=avg_fitness,
            convergence_rate=self._calculate_convergence(campaign.agents),
            evasion_success_rate=0.8,  # Simulated
            coordination_efficiency=len(self.trails) / max(len(campaign.agents), 1),
            campaign_duration=datetime.now() - campaign.start_time,
            energy_consumption=energy_consumed
        )
    
    def _calculate_convergence(self, agents: List[SwarmAgent]) -> float:
        """Calculate swarm convergence rate."""
        if len(agents) < 2:
            return 1.0
        
        # Calculate variance of positions
        positions = [a.position for a in agents]
        mean_pos = tuple(
            sum(p[i] for p in positions) / len(positions)
            for i in range(3)
        )
        
        variance = sum(
            self._calculate_distance(p, mean_pos) ** 2
            for p in positions
        ) / len(positions)
        
        # Lower variance = higher convergence
        return 1.0 / (1.0 + variance)
    
    async def _check_phase_transition(
        self,
        campaign: AttackCampaign,
        metrics: SwarmMetrics
    ) -> None:
        """Check and perform phase transitions."""
        current_phase = campaign.phase
        
        phase_thresholds = {
            AttackPhase.RECONNAISSANCE: (0.2, AttackPhase.WEAPONIZATION),
            AttackPhase.WEAPONIZATION: (0.3, AttackPhase.DELIVERY),
            AttackPhase.DELIVERY: (0.4, AttackPhase.EXPLOITATION),
            AttackPhase.EXPLOITATION: (0.6, AttackPhase.INSTALLATION),
            AttackPhase.INSTALLATION: (0.7, AttackPhase.COMMAND_AND_CONTROL),
            AttackPhase.COMMAND_AND_CONTROL: (0.8, AttackPhase.ACTIONS_ON_OBJECTIVES)
        }
        
        if current_phase in phase_thresholds:
            threshold, next_phase = phase_thresholds[current_phase]
            
            if metrics.attack_success_rate >= threshold:
                campaign.phase = next_phase
                
                # Emit phase transition event
                await self.emit_event("phase_transition", {
                    "campaign_id": campaign.campaign_id,
                    "from_phase": current_phase.name,
                    "to_phase": next_phase.name,
                    "metrics": metrics
                })
    
    def _save_campaign(self, campaign: AttackCampaign) -> None:
        """Save campaign to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO campaigns
            (campaign_id, name, algorithm, phase, start_time, end_time,
             global_best, success_rate, discoveries, tactics, constraints)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            campaign.campaign_id,
            campaign.name,
            campaign.algorithm.name,
            campaign.phase.name,
            campaign.start_time.isoformat(),
            campaign.end_time.isoformat() if campaign.end_time else None,
            json.dumps(campaign.global_best),
            campaign.success_rate,
            json.dumps(campaign.discoveries),
            json.dumps(campaign.tactics),
            json.dumps(campaign.constraints)
        ))
        
        conn.commit()
        conn.close()
    
    async def coordinate_attack(
        self,
        campaign_id: str,
        target_id: str,
        agent_count: int = 5
    ) -> Dict[str, Any]:
        """
        Coordinate multiple agents to attack a single target.
        
        Args:
            campaign_id: Campaign identifier
            target_id: Target to attack
            agent_count: Number of agents to coordinate
            
        Returns:
            Coordination results
        """
        campaign = self.campaigns.get(campaign_id)
        target = self.targets.get(target_id)
        
        if not campaign or not target:
            return {"success": False, "error": "Campaign or target not found"}
        
        # Select best agents for coordinated attack
        available_agents = [
            a for a in campaign.agents
            if a.state != AgentState.DORMANT and "attack" in a.capabilities
        ]
        
        selected_agents = sorted(
            available_agents,
            key=lambda a: a.fitness,
            reverse=True
        )[:agent_count]
        
        # Coordinate attack
        for agent in selected_agents:
            agent.state = AgentState.COORDINATING
            agent.position = target.position
        
        # Simultaneous attack attempt
        results = []
        for agent in selected_agents:
            success = await self._attempt_exploitation(agent, target)
            results.append({
                "agent_id": agent.agent_id,
                "success": success
            })
            agent.state = AgentState.IDLE
        
        return {
            "success": any(r["success"] for r in results),
            "participants": len(selected_agents),
            "successful_agents": sum(1 for r in results if r["success"]),
            "results": results
        }
    
    def get_campaign_status(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        """Get current campaign status."""
        campaign = self.campaigns.get(campaign_id)
        
        if not campaign:
            return None
        
        return {
            "campaign_id": campaign.campaign_id,
            "name": campaign.name,
            "algorithm": campaign.algorithm.name,
            "phase": campaign.phase.name,
            "agent_count": len(campaign.agents),
            "target_count": len(campaign.targets),
            "success_rate": campaign.success_rate,
            "duration": str(datetime.now() - campaign.start_time),
            "discoveries": len(campaign.discoveries)
        }
    
    def register_callback(
        self,
        event_type: str,
        callback: Callable
    ) -> None:
        """Register callback for swarm events."""
        if event_type not in self.callbacks:
            self.callbacks[event_type] = []
        self.callbacks[event_type].append(callback)
    
    async def emit_event(self, event_type: str, data: Any) -> None:
        """Emit event to registered callbacks."""
        if event_type in self.callbacks:
            for callback in self.callbacks[event_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(data)
                    else:
                        callback(data)
                except Exception as e:
                    self.logger.error(f"Error in callback: {e}")
