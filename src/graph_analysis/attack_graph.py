"""
Graph-theoretic analysis for ICS attack modeling and visualization.
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict, deque

import networkx as nx
import matplotlib.pyplot as plt
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from loguru import logger

try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    logger.warning("Neo4j not available. Graph database features disabled.")


@dataclass
class Node:
    """Represents a node in the attack graph."""
    id: str
    type: str  # 'plc', 'rtu', 'scada', 'firewall', 'hmi', 'database'
    ip_address: str
    hostname: str
    vulnerabilities: List[str]
    criticality: float  # 0.0 to 1.0
    location: str
    description: str = ""


@dataclass
class Edge:
    """Represents an edge in the attack graph."""
    source: str
    target: str
    protocol: str
    port: int
    vulnerability: Optional[str] = None
    attack_probability: float = 0.5
    impact: float = 0.5
    description: str = ""


@dataclass
class AttackPath:
    """Represents a complete attack path."""
    path_id: str
    nodes: List[str]
    edges: List[Tuple[str, str]]
    total_risk: float
    attack_steps: List[str]
    mitre_techniques: List[str]
    estimated_time: int  # in minutes


class AttackGraphAnalyzer:
    """Graph-theoretic analysis for ICS attack modeling."""
    
    def __init__(self, config: Dict):
        """Initialize attack graph analyzer."""
        self.config = config
        self.graph = nx.DiGraph()
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[Tuple[str, str], Edge] = {}
        self.attack_paths: List[AttackPath] = []
        
        # Neo4j connection
        self.neo4j_driver = None
        if NEO4J_AVAILABLE and config.get('use_neo4j', False):
            self._init_neo4j()
        
        # Analysis parameters
        self.centrality_metrics = config.get('centrality_metrics', 
                                           ['betweenness', 'closeness', 'eigenvector'])
        self.max_path_length = config.get('max_path_length', 10)
        
        # Visualization settings
        self.layout_algorithm = config.get('graph_layout', 'spring')
        self.node_size = config.get('node_size', 20)
        self.edge_width = config.get('edge_width', 2)
        
        # Callbacks
        self.path_callbacks = []
        self.threat_callbacks = []
        
        logger.info("Attack graph analyzer initialized")
    
    def _init_neo4j(self):
        """Initialize Neo4j database connection."""
        try:
            uri = self.config.get('neo4j_uri', 'bolt://localhost:7687')
            user = self.config.get('neo4j_user', 'neo4j')
            password = self.config.get('neo4j_password', 'password')
            
            self.neo4j_driver = GraphDatabase.driver(uri, auth=(user, password))
            logger.info("Neo4j connection established")
            
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            self.neo4j_driver = None
    
    def add_node(self, node: Node):
        """Add a node to the attack graph."""
        self.nodes[node.id] = node
        
        # Add to NetworkX graph
        self.graph.add_node(node.id, **asdict(node))
        
        # Add to Neo4j if available
        if self.neo4j_driver:
            self._add_node_to_neo4j(node)
        
        logger.debug(f"Added node: {node.id} ({node.type})")
    
    def add_edge(self, edge: Edge):
        """Add an edge to the attack graph."""
        self.edges[(edge.source, edge.target)] = edge
        
        # Add to NetworkX graph
        self.graph.add_edge(edge.source, edge.target, **asdict(edge))
        
        # Add to Neo4j if available
        if self.neo4j_driver:
            self._add_edge_to_neo4j(edge)
        
        logger.debug(f"Added edge: {edge.source} -> {edge.target}")
    
    def _add_node_to_neo4j(self, node: Node):
        """Add node to Neo4j database."""
        if not self.neo4j_driver:
            return
        
        with self.neo4j_driver.session() as session:
            query = """
            MERGE (n:Node {id: $id})
            SET n.type = $type,
                n.ip_address = $ip_address,
                n.hostname = $hostname,
                n.criticality = $criticality,
                n.location = $location,
                n.description = $description
            """
            session.run(query, **asdict(node))
    
    def _add_edge_to_neo4j(self, edge: Edge):
        """Add edge to Neo4j database."""
        if not self.neo4j_driver:
            return
        
        with self.neo4j_driver.session() as session:
            query = """
            MATCH (source:Node {id: $source})
            MATCH (target:Node {id: $target})
            MERGE (source)-[r:CONNECTS_TO]->(target)
            SET r.protocol = $protocol,
                r.port = $port,
                r.attack_probability = $attack_probability,
                r.impact = $impact,
                r.description = $description
            """
            session.run(query, **asdict(edge))
    
    def compute_centrality_measures(self) -> Dict[str, Dict[str, float]]:
        """Compute centrality measures for all nodes."""
        centrality_results = {}
        
        for metric in self.centrality_metrics:
            try:
                if metric == 'betweenness':
                    centrality = nx.betweenness_centrality(self.graph)
                elif metric == 'closeness':
                    centrality = nx.closeness_centrality(self.graph)
                elif metric == 'eigenvector':
                    centrality = nx.eigenvector_centrality_numpy(self.graph)
                elif metric == 'pagerank':
                    centrality = nx.pagerank(self.graph)
                else:
                    logger.warning(f"Unknown centrality metric: {metric}")
                    continue
                
                centrality_results[metric] = centrality
                logger.info(f"Computed {metric} centrality for {len(centrality)} nodes")
                
            except Exception as e:
                logger.error(f"Error computing {metric} centrality: {e}")
        
        return centrality_results
    
    def find_attack_paths(self, source_node: str, target_node: str, 
                         max_paths: int = 10) -> List[AttackPath]:
        """Find all possible attack paths between two nodes."""
        try:
            # Find all simple paths
            paths = list(nx.all_simple_paths(self.graph, source_node, target_node, 
                                           cutoff=self.max_path_length))
            
            attack_paths = []
            
            for i, path in enumerate(paths[:max_paths]):
                # Calculate path risk
                total_risk = self._calculate_path_risk(path)
                
                # Extract edges
                edges = list(zip(path[:-1], path[1:]))
                
                # Generate attack steps
                attack_steps = self._generate_attack_steps(path)
                
                # Extract MITRE techniques
                mitre_techniques = self._extract_mitre_techniques(path)
                
                # Estimate attack time
                estimated_time = self._estimate_attack_time(path)
                
                attack_path = AttackPath(
                    path_id=f"path_{i}_{int(time.time())}",
                    nodes=path,
                    edges=edges,
                    total_risk=total_risk,
                    attack_steps=attack_steps,
                    mitre_techniques=mitre_techniques,
                    estimated_time=estimated_time
                )
                
                attack_paths.append(attack_path)
            
            # Sort by risk (highest first)
            attack_paths.sort(key=lambda x: x.total_risk, reverse=True)
            
            logger.info(f"Found {len(attack_paths)} attack paths from {source_node} to {target_node}")
            return attack_paths
            
        except Exception as e:
            logger.error(f"Error finding attack paths: {e}")
            return []
    
    def _calculate_path_risk(self, path: List[str]) -> float:
        """Calculate total risk for an attack path."""
        if len(path) < 2:
            return 0.0
        
        total_risk = 0.0
        
        for i in range(len(path) - 1):
            source = path[i]
            target = path[i + 1]
            
            # Get edge risk
            edge_key = (source, target)
            if edge_key in self.edges:
                edge = self.edges[edge_key]
                edge_risk = edge.attack_probability * edge.impact
            else:
                edge_risk = 0.5  # Default risk
            
            # Get node criticality
            if target in self.nodes:
                node_criticality = self.nodes[target].criticality
            else:
                node_criticality = 0.5  # Default criticality
            
            # Path risk is cumulative
            total_risk += edge_risk * node_criticality
        
        return min(total_risk, 1.0)  # Cap at 1.0
    
    def _generate_attack_steps(self, path: List[str]) -> List[str]:
        """Generate human-readable attack steps for a path."""
        steps = []
        
        for i in range(len(path) - 1):
            source = path[i]
            target = path[i + 1]
            
            edge_key = (source, target)
            if edge_key in self.edges:
                edge = self.edges[edge_key]
                step = f"Exploit {edge.protocol} connection on port {edge.port} from {source} to {target}"
                if edge.vulnerability:
                    step += f" using {edge.vulnerability}"
            else:
                step = f"Move from {source} to {target}"
            
            steps.append(step)
        
        return steps
    
    def _extract_mitre_techniques(self, path: List[str]) -> List[str]:
        """Extract MITRE ATT&CK techniques from attack path."""
        techniques = set()
        
        for i in range(len(path) - 1):
            source = path[i]
            target = path[i + 1]
            
            edge_key = (source, target)
            if edge_key in self.edges:
                edge = self.edges[edge_key]
                if hasattr(edge, 'mitre_technique') and edge.mitre_technique:
                    techniques.add(edge.mitre_technique)
        
        return list(techniques)
    
    def _estimate_attack_time(self, path: List[str]) -> int:
        """Estimate time required for attack path execution."""
        base_time = 30  # Base time in minutes
        
        # Add time for each step
        for i in range(len(path) - 1):
            source = path[i]
            target = path[i + 1]
            
            edge_key = (source, target)
            if edge_key in self.edges:
                edge = self.edges[edge_key]
                # More complex attacks take longer
                if edge.vulnerability:
                    base_time += 15
                else:
                    base_time += 5
        
        return base_time
    
    def identify_critical_nodes(self, top_k: int = 10) -> List[Tuple[str, float]]:
        """Identify the most critical nodes in the network."""
        try:
            # Compute centrality measures
            centrality_results = self.compute_centrality_measures()
            
            # Combine centrality scores
            node_scores = defaultdict(float)
            
            for metric, scores in centrality_results.items():
                for node, score in scores.items():
                    node_scores[node] += score
            
            # Add node criticality
            for node_id, node in self.nodes.items():
                node_scores[node_id] += node.criticality
            
            # Sort by score
            critical_nodes = sorted(node_scores.items(), key=lambda x: x[1], reverse=True)
            
            logger.info(f"Identified {len(critical_nodes)} critical nodes")
            return critical_nodes[:top_k]
            
        except Exception as e:
            logger.error(f"Error identifying critical nodes: {e}")
            return []
    
    def detect_attack_vectors(self) -> List[Dict]:
        """Detect potential attack vectors in the network."""
        attack_vectors = []
        
        try:
            # Find nodes with external connectivity
            external_nodes = []
            for node_id, node in self.nodes.items():
                if node.type in ['firewall', 'router', 'gateway']:
                    external_nodes.append(node_id)
            
            # Find paths from external nodes to critical assets
            critical_assets = [node_id for node_id, node in self.nodes.items() 
                             if node.criticality > 0.7]
            
            for external_node in external_nodes:
                for critical_asset in critical_assets:
                    if external_node != critical_asset:
                        paths = self.find_attack_paths(external_node, critical_asset, max_paths=5)
                        
                        for path in paths:
                            attack_vector = {
                                'entry_point': external_node,
                                'target': critical_asset,
                                'path': path.nodes,
                                'risk': path.total_risk,
                                'steps': path.attack_steps,
                                'mitre_techniques': path.mitre_techniques,
                                'estimated_time': path.estimated_time
                            }
                            attack_vectors.append(attack_vector)
            
            logger.info(f"Detected {len(attack_vectors)} attack vectors")
            return attack_vectors
            
        except Exception as e:
            logger.error(f"Error detecting attack vectors: {e}")
            return []
    
    def create_visualization(self, output_path: str = "attack_graph.html"):
        """Create interactive visualization of the attack graph."""
        try:
            # Create Plotly figure
            fig = go.Figure()
            
            # Add edges
            edge_x = []
            edge_y = []
            edge_text = []
            
            for edge in self.edges.values():
                source_node = self.nodes.get(edge.source)
                target_node = self.nodes.get(edge.target)
                
                if source_node and target_node:
                    # Simple positioning (you might want to use a layout algorithm)
                    edge_x.extend([0, 1, None])
                    edge_y.extend([0, 1, None])
                    edge_text.append(f"{edge.source} → {edge.target}<br>Protocol: {edge.protocol}<br>Risk: {edge.attack_probability:.2f}")
            
            # Add edges to figure
            fig.add_trace(go.Scatter(
                x=edge_x, y=edge_y,
                line=dict(width=0.5, color='#888'),
                hoverinfo='none',
                mode='lines'))
            
            # Add nodes
            node_x = []
            node_y = []
            node_text = []
            node_colors = []
            
            for node in self.nodes.values():
                node_x.append(0)  # Simple positioning
                node_y.append(0)
                node_text.append(f"Node: {node.hostname}<br>Type: {node.type}<br>Criticality: {node.criticality:.2f}")
                
                # Color by criticality
                if node.criticality > 0.8:
                    node_colors.append('red')
                elif node.criticality > 0.5:
                    node_colors.append('orange')
                else:
                    node_colors.append('green')
            
            fig.add_trace(go.Scatter(
                x=node_x, y=node_y,
                mode='markers',
                hoverinfo='text',
                text=node_text,
                marker=dict(
                    size=20,
                    color=node_colors,
                    line_width=2)))
            
            # Update layout
            fig.update_layout(
                title='ICS Attack Graph',
                showlegend=False,
                hovermode='closest',
                margin=dict(b=20,l=5,r=5,t=40),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
            
            # Save to file
            fig.write_html(output_path)
            logger.info(f"Attack graph visualization saved to {output_path}")
            
        except Exception as e:
            logger.error(f"Error creating visualization: {e}")
    
    async def start(self):
        """Start the graph analysis service."""
        logger.info("Starting attack graph analysis service")
        
        # Load initial graph data if available
        await self._load_graph_data()
        
        # Start periodic analysis
        asyncio.create_task(self._periodic_analysis())
    
    async def _load_graph_data(self):
        """Load graph data from file or database."""
        data_path = Path("data/attack_graph.json")
        
        if data_path.exists():
            try:
                with open(data_path, 'r') as f:
                    data = json.load(f)
                
                # Load nodes
                for node_data in data.get('nodes', []):
                    node = Node(**node_data)
                    self.add_node(node)
                
                # Load edges
                for edge_data in data.get('edges', []):
                    edge = Edge(**edge_data)
                    self.add_edge(edge)
                
                logger.info(f"Loaded {len(data.get('nodes', []))} nodes and {len(data.get('edges', []))} edges")
                
            except Exception as e:
                logger.error(f"Error loading graph data: {e}")
    
    async def _periodic_analysis(self):
        """Perform periodic graph analysis."""
        while True:
            try:
                # Update centrality measures
                centrality_results = self.compute_centrality_measures()
                
                # Detect new attack vectors
                attack_vectors = self.detect_attack_vectors()
                
                # Notify callbacks
                for callback in self.threat_callbacks:
                    try:
                        callback(attack_vectors)
                    except Exception as e:
                        logger.error(f"Error in threat callback: {e}")
                
                # Wait before next analysis
                await asyncio.sleep(300)  # 5 minutes
                
            except Exception as e:
                logger.error(f"Error in periodic analysis: {e}")
                await asyncio.sleep(60)
    
    async def stop(self):
        """Stop the graph analysis service."""
        logger.info("Stopping attack graph analysis service")
        
        if self.neo4j_driver:
            self.neo4j_driver.close()
    
    def get_graph_statistics(self) -> Dict:
        """Get graph statistics."""
        return {
            'total_nodes': len(self.nodes),
            'total_edges': len(self.edges),
            'node_types': self._count_node_types(),
            'connectivity': nx.density(self.graph),
            'diameter': nx.diameter(self.graph) if nx.is_connected(self.graph.to_undirected()) else None,
            'average_clustering': nx.average_clustering(self.graph.to_undirected())
        }
    
    def _count_node_types(self) -> Dict[str, int]:
        """Count nodes by type."""
        type_counts = defaultdict(int)
        for node in self.nodes.values():
            type_counts[node.type] += 1
        return dict(type_counts) 