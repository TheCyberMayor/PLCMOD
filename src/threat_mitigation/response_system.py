"""
Dynamic threat mitigation system for ICS cybersecurity.
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict, deque
import random

import numpy as np
from loguru import logger


@dataclass
class MitigationAction:
    """Represents a mitigation action."""
    action_id: str
    action_type: str  # 'block_ip', 'isolate_device', 'update_rules', 'alert', 'shutdown'
    target: str
    parameters: Dict[str, Any]
    priority: int  # 1-5, higher is more urgent
    estimated_impact: float  # 0.0 to 1.0
    execution_time: int  # seconds
    description: str
    mitre_technique: Optional[str] = None


@dataclass
class ResponseStrategy:
    """Represents a response strategy."""
    strategy_id: str
    name: str
    threat_level: str  # 'low', 'medium', 'high', 'critical'
    actions: List[MitigationAction]
    conditions: Dict[str, Any]
    success_rate: float
    last_used: Optional[float] = None
    description: str = ""


@dataclass
class ResponseResult:
    """Represents the result of a mitigation action."""
    action_id: str
    success: bool
    execution_time: float
    impact_assessment: Dict[str, float]
    side_effects: List[str]
    timestamp: float
    description: str = ""


class QLearningAgent:
    """Q-Learning agent for adaptive threat response."""
    
    def __init__(self, config: Dict):
        """Initialize Q-Learning agent."""
        self.config = config
        self.learning_rate = config.get('learning_rate', 0.1)
        self.discount_factor = config.get('discount_factor', 0.9)
        self.epsilon = config.get('epsilon', 0.1)  # Exploration rate
        
        # Q-table: state -> action -> value
        self.q_table = defaultdict(lambda: defaultdict(float))
        
        # State and action spaces
        self.states = self._define_states()
        self.actions = self._define_actions()
        
        # Experience replay
        self.experience_buffer = deque(maxlen=1000)
        
        logger.info("Q-Learning agent initialized")
    
    def _define_states(self) -> List[str]:
        """Define possible states."""
        threat_levels = ['low', 'medium', 'high', 'critical']
        attack_types = ['port_scan', 'unauthorized_access', 'malicious_payload', 'data_exfiltration']
        system_states = ['normal', 'compromised', 'isolated', 'recovering']
        
        states = []
        for threat in threat_levels:
            for attack in attack_types:
                for system in system_states:
                    states.append(f"{threat}_{attack}_{system}")
        
        return states
    
    def _define_actions(self) -> List[str]:
        """Define possible actions."""
        return [
            'monitor_only',
            'log_alert',
            'increase_monitoring',
            'block_ip',
            'isolate_device',
            'update_firewall_rules',
            'disable_service',
            'emergency_shutdown',
            'alert_authorities'
        ]
    
    def get_state(self, threat_data: Dict, system_status: Dict) -> str:
        """Convert current situation to state representation."""
        threat_level = threat_data.get('threat_level', 'low')
        attack_type = threat_data.get('threat_type', 'port_scan')
        system_state = system_status.get('overall_status', 'normal')
        
        return f"{threat_level}_{attack_type}_{system_state}"
    
    def select_action(self, state: str) -> str:
        """Select action using epsilon-greedy policy."""
        if random.random() < self.epsilon:
            # Exploration: random action
            return random.choice(self.actions)
        else:
            # Exploitation: best action
            return self._get_best_action(state)
    
    def _get_best_action(self, state: str) -> str:
        """Get the best action for a given state."""
        if state not in self.q_table:
            return random.choice(self.actions)
        
        actions = self.q_table[state]
        if not actions:
            return random.choice(self.actions)
        
        return max(actions.items(), key=lambda x: x[1])[0]
    
    def update_q_value(self, state: str, action: str, reward: float, next_state: str):
        """Update Q-value using Q-learning formula."""
        current_q = self.q_table[state][action]
        
        # Get max Q-value for next state
        next_max_q = max(self.q_table[next_state].values()) if self.q_table[next_state] else 0
        
        # Q-learning update formula
        new_q = current_q + self.learning_rate * (reward + self.discount_factor * next_max_q - current_q)
        
        self.q_table[state][action] = new_q
        
        # Store experience
        self.experience_buffer.append((state, action, reward, next_state))
    
    def get_q_table(self) -> Dict[str, Dict[str, float]]:
        """Get current Q-table."""
        return dict(self.q_table)


class ThreatResponseSystem:
    """Dynamic threat mitigation system."""
    
    def __init__(self, config: Dict):
        """Initialize threat response system."""
        self.config = config
        self.running = False
        
        # Response strategies
        self.response_strategies: Dict[str, ResponseStrategy] = {}
        self.active_responses: Dict[str, ResponseResult] = {}
        
        # Q-Learning agent
        self.q_agent = QLearningAgent(config)
        
        # Automation settings
        self.auto_response = config.get('auto_response', True)
        self.manual_approval = config.get('manual_approval', False)
        
        # Response history
        self.response_history: List[ResponseResult] = []
        self.strategy_performance = defaultdict(list)
        
        # Callbacks
        self.action_callbacks: List[Callable] = []
        self.response_callbacks: List[Callable] = []
        
        # Initialize strategies
        self._initialize_strategies()
        
        logger.info("Threat response system initialized")
    
    def _initialize_strategies(self):
        """Initialize predefined response strategies."""
        # Low threat strategies
        self.response_strategies['low_monitoring'] = ResponseStrategy(
            strategy_id='low_monitoring',
            name='Enhanced Monitoring',
            threat_level='low',
            actions=[
                MitigationAction(
                    action_id='log_alert',
                    action_type='log_alert',
                    target='system',
                    parameters={'log_level': 'warning'},
                    priority=1,
                    estimated_impact=0.1,
                    execution_time=1,
                    description='Log security alert',
                    mitre_technique='T1562.001'  # Impair Defenses: Disable or Modify Tools
                ),
                MitigationAction(
                    action_id='increase_monitoring',
                    action_type='increase_monitoring',
                    target='network',
                    parameters={'monitoring_level': 'enhanced'},
                    priority=2,
                    estimated_impact=0.2,
                    execution_time=5,
                    description='Increase network monitoring',
                    mitre_technique='T1595.001'  # Active Scanning: Scanning IP Blocks
                )
            ],
            conditions={'threat_level': 'low', 'confidence': '>0.5'},
            success_rate=0.8,
            description='Enhanced monitoring for low-level threats'
        )
        
        # Medium threat strategies
        self.response_strategies['medium_isolation'] = ResponseStrategy(
            strategy_id='medium_isolation',
            name='Selective Isolation',
            threat_level='medium',
            actions=[
                MitigationAction(
                    action_id='block_ip',
                    action_type='block_ip',
                    target='source_ip',
                    parameters={'duration': 3600, 'reason': 'suspicious_activity'},
                    priority=3,
                    estimated_impact=0.5,
                    execution_time=10,
                    description='Block suspicious IP address',
                    mitre_technique='T1078'  # Valid Accounts
                ),
                MitigationAction(
                    action_id='update_firewall_rules',
                    action_type='update_rules',
                    target='firewall',
                    parameters={'rule_type': 'deny', 'protocol': 'any'},
                    priority=3,
                    estimated_impact=0.4,
                    execution_time=15,
                    description='Update firewall rules',
                    mitre_technique='T1562.001'  # Impair Defenses: Disable or Modify Tools
                )
            ],
            conditions={'threat_level': 'medium', 'confidence': '>0.7'},
            success_rate=0.7,
            description='Selective isolation for medium-level threats'
        )
        
        # High threat strategies
        self.response_strategies['high_lockdown'] = ResponseStrategy(
            strategy_id='high_lockdown',
            name='System Lockdown',
            threat_level='high',
            actions=[
                MitigationAction(
                    action_id='isolate_device',
                    action_type='isolate_device',
                    target='compromised_device',
                    parameters={'isolation_type': 'network', 'duration': 7200},
                    priority=4,
                    estimated_impact=0.8,
                    execution_time=30,
                    description='Isolate compromised device',
                    mitre_technique='T1078'  # Valid Accounts
                ),
                MitigationAction(
                    action_id='disable_service',
                    action_type='disable_service',
                    target='affected_service',
                    parameters={'service_name': 'unknown', 'reason': 'security_threat'},
                    priority=4,
                    estimated_impact=0.7,
                    execution_time=20,
                    description='Disable affected service',
                    mitre_technique='T1562.001'  # Impair Defenses: Disable or Modify Tools
                )
            ],
            conditions={'threat_level': 'high', 'confidence': '>0.8'},
            success_rate=0.6,
            description='System lockdown for high-level threats'
        )
        
        # Critical threat strategies
        self.response_strategies['critical_shutdown'] = ResponseStrategy(
            strategy_id='critical_shutdown',
            name='Emergency Shutdown',
            threat_level='critical',
            actions=[
                MitigationAction(
                    action_id='emergency_shutdown',
                    action_type='emergency_shutdown',
                    target='critical_systems',
                    parameters={'shutdown_type': 'controlled', 'reason': 'critical_threat'},
                    priority=5,
                    estimated_impact=1.0,
                    execution_time=60,
                    description='Emergency shutdown of critical systems',
                    mitre_technique='T1565'  # Data Manipulation
                ),
                MitigationAction(
                    action_id='alert_authorities',
                    action_type='alert',
                    target='security_team',
                    parameters={'alert_level': 'critical', 'escalation': True},
                    priority=5,
                    estimated_impact=0.9,
                    execution_time=5,
                    description='Alert security authorities',
                    mitre_technique='T1078'  # Valid Accounts
                )
            ],
            conditions={'threat_level': 'critical', 'confidence': '>0.9'},
            success_rate=0.5,
            description='Emergency shutdown for critical threats'
        )
    
    def add_action_callback(self, callback: Callable):
        """Add callback for action execution."""
        self.action_callbacks.append(callback)
    
    def add_response_callback(self, callback: Callable):
        """Add callback for response results."""
        self.response_callbacks.append(callback)
    
    def select_response_strategy(self, threat_data: Dict, system_status: Dict) -> Optional[ResponseStrategy]:
        """Select appropriate response strategy based on threat and system status."""
        threat_level = threat_data.get('threat_level', 'low')
        confidence = threat_data.get('confidence', 0.0)
        
        # Filter strategies by threat level
        applicable_strategies = [
            strategy for strategy in self.response_strategies.values()
            if strategy.threat_level == threat_level
        ]
        
        if not applicable_strategies:
            logger.warning(f"No applicable strategies for threat level: {threat_level}")
            return None
        
        # Use Q-Learning to select strategy
        state = self.q_agent.get_state(threat_data, system_status)
        action = self.q_agent.select_action(state)
        
        # Map action to strategy (simplified mapping)
        if action == 'monitor_only':
            return self.response_strategies.get('low_monitoring')
        elif action in ['block_ip', 'isolate_device']:
            return self.response_strategies.get('medium_isolation')
        elif action in ['disable_service', 'update_firewall_rules']:
            return self.response_strategies.get('high_lockdown')
        elif action in ['emergency_shutdown', 'alert_authorities']:
            return self.response_strategies.get('critical_shutdown')
        else:
            # Default to medium isolation
            return self.response_strategies.get('medium_isolation')
    
    async def execute_response(self, threat_data: Dict, system_status: Dict) -> ResponseResult:
        """Execute response strategy for a threat."""
        try:
            # Select strategy
            strategy = self.select_response_strategy(threat_data, system_status)
            if not strategy:
                logger.warning("No response strategy selected")
                return None
            
            # Check if manual approval is required
            if self.manual_approval and strategy.threat_level in ['high', 'critical']:
                logger.info(f"Manual approval required for {strategy.name}")
                # In a real system, this would trigger a manual approval workflow
                return None
            
            # Execute actions
            results = []
            for action in strategy.actions:
                result = await self._execute_action(action, threat_data)
                results.append(result)
                
                # Check if action was successful
                if not result.success:
                    logger.warning(f"Action {action.action_id} failed: {result.description}")
                    break
            
            # Update strategy performance
            success_rate = sum(1 for r in results if r.success) / len(results) if results else 0
            self.strategy_performance[strategy.strategy_id].append(success_rate)
            
            # Update Q-Learning agent
            self._update_q_learning(threat_data, strategy, success_rate)
            
            # Store response history
            for result in results:
                self.response_history.append(result)
            
            # Notify callbacks
            for callback in self.response_callbacks:
                try:
                    callback(results)
                except Exception as e:
                    logger.error(f"Error in response callback: {e}")
            
            return results[0] if results else None
            
        except Exception as e:
            logger.error(f"Error executing response: {e}")
            return None
    
    async def _execute_action(self, action: MitigationAction, threat_data: Dict) -> ResponseResult:
        """Execute a single mitigation action."""
        start_time = time.time()
        
        try:
            logger.info(f"Executing action: {action.action_id} - {action.description}")
            
            # Notify action callbacks
            for callback in self.action_callbacks:
                try:
                    callback(action)
                except Exception as e:
                    logger.error(f"Error in action callback: {e}")
            
            # Simulate action execution
            await asyncio.sleep(action.execution_time)
            
            # Determine success based on action type and conditions
            success = self._evaluate_action_success(action, threat_data)
            
            # Calculate impact assessment
            impact_assessment = self._assess_action_impact(action, success)
            
            # Identify side effects
            side_effects = self._identify_side_effects(action, success)
            
            execution_time = time.time() - start_time
            
            result = ResponseResult(
                action_id=action.action_id,
                success=success,
                execution_time=execution_time,
                impact_assessment=impact_assessment,
                side_effects=side_effects,
                timestamp=time.time(),
                description=f"Action {action.action_id} {'succeeded' if success else 'failed'}"
            )
            
            logger.info(f"Action {action.action_id} completed: {'SUCCESS' if success else 'FAILED'}")
            return result
            
        except Exception as e:
            logger.error(f"Error executing action {action.action_id}: {e}")
            return ResponseResult(
                action_id=action.action_id,
                success=False,
                execution_time=time.time() - start_time,
                impact_assessment={'error': 1.0},
                side_effects=['execution_error'],
                timestamp=time.time(),
                description=f"Error executing action: {e}"
            )
    
    def _evaluate_action_success(self, action: MitigationAction, threat_data: Dict) -> bool:
        """Evaluate whether an action was successful."""
        # Base success rate
        base_success_rate = 0.8
        
        # Adjust based on action type
        if action.action_type == 'emergency_shutdown':
            base_success_rate = 0.95  # High success rate for critical actions
        elif action.action_type == 'block_ip':
            base_success_rate = 0.9
        elif action.action_type == 'isolate_device':
            base_success_rate = 0.85
        elif action.action_type == 'update_rules':
            base_success_rate = 0.75
        
        # Adjust based on threat level
        threat_level = threat_data.get('threat_level', 'low')
        if threat_level == 'critical':
            base_success_rate *= 1.1  # Slightly higher success for critical threats
        elif threat_level == 'low':
            base_success_rate *= 0.9  # Slightly lower for low threats
        
        # Random success based on success rate
        return random.random() < base_success_rate
    
    def _assess_action_impact(self, action: MitigationAction, success: bool) -> Dict[str, float]:
        """Assess the impact of an action."""
        impact = {
            'threat_mitigation': 0.0,
            'system_availability': 0.0,
            'user_experience': 0.0,
            'security_posture': 0.0
        }
        
        if success:
            # Positive impact on security
            impact['threat_mitigation'] = action.estimated_impact
            impact['security_posture'] = action.estimated_impact * 0.8
            
            # Potential negative impact on availability
            if action.action_type in ['emergency_shutdown', 'isolate_device']:
                impact['system_availability'] = -0.7
                impact['user_experience'] = -0.6
            elif action.action_type == 'block_ip':
                impact['system_availability'] = -0.3
                impact['user_experience'] = -0.2
        else:
            # Failed actions have negative impact
            impact['threat_mitigation'] = -0.2
            impact['security_posture'] = -0.3
        
        return impact
    
    def _identify_side_effects(self, action: MitigationAction, success: bool) -> List[str]:
        """Identify potential side effects of an action."""
        side_effects = []
        
        if not success:
            side_effects.append('action_failure')
            return side_effects
        
        # Action-specific side effects
        if action.action_type == 'emergency_shutdown':
            side_effects.extend(['production_stopped', 'data_loss_risk', 'recovery_time_needed'])
        elif action.action_type == 'isolate_device':
            side_effects.extend(['service_disruption', 'communication_loss'])
        elif action.action_type == 'block_ip':
            side_effects.extend(['legitimate_traffic_blocked', 'connectivity_issues'])
        elif action.action_type == 'update_rules':
            side_effects.extend(['configuration_changes', 'temporary_disruption'])
        
        return side_effects
    
    def _update_q_learning(self, threat_data: Dict, strategy: ResponseStrategy, success_rate: float):
        """Update Q-Learning agent with response results."""
        try:
            # Create system status for state representation
            system_status = {
                'overall_status': 'normal' if success_rate > 0.7 else 'compromised'
            }
            
            current_state = self.q_agent.get_state(threat_data, system_status)
            
            # Determine reward based on success rate and threat level
            base_reward = success_rate * 10  # Scale reward
            
            # Adjust reward based on threat level
            threat_level = threat_data.get('threat_level', 'low')
            if threat_level == 'critical':
                base_reward *= 2  # Higher reward for critical threats
            elif threat_level == 'low':
                base_reward *= 0.5  # Lower reward for low threats
            
            # Penalty for failed actions
            if success_rate < 0.5:
                base_reward -= 5
            
            # Map strategy to action
            action = self._strategy_to_action(strategy)
            
            # Create next state (simplified)
            next_state = current_state  # In reality, this would be the new state after action
            
            # Update Q-value
            self.q_agent.update_q_value(current_state, action, base_reward, next_state)
            
        except Exception as e:
            logger.error(f"Error updating Q-Learning: {e}")
    
    def _strategy_to_action(self, strategy: ResponseStrategy) -> str:
        """Map strategy to Q-Learning action."""
        if strategy.threat_level == 'low':
            return 'monitor_only'
        elif strategy.threat_level == 'medium':
            return 'block_ip'
        elif strategy.threat_level == 'high':
            return 'isolate_device'
        elif strategy.threat_level == 'critical':
            return 'emergency_shutdown'
        else:
            return 'monitor_only'
    
    async def start(self):
        """Start the threat response system."""
        self.running = True
        logger.info("Threat response system started")
        
        # Start periodic strategy evaluation
        asyncio.create_task(self._periodic_evaluation())
    
    async def _periodic_evaluation(self):
        """Periodically evaluate and update response strategies."""
        while self.running:
            try:
                # Evaluate strategy performance
                for strategy_id, performance_history in self.strategy_performance.items():
                    if performance_history:
                        avg_performance = np.mean(performance_history[-10:])  # Last 10 results
                        logger.info(f"Strategy {strategy_id} average performance: {avg_performance:.3f}")
                
                # Clean up old response history
                cutoff_time = time.time() - 86400  # 24 hours
                self.response_history = [
                    r for r in self.response_history 
                    if r.timestamp > cutoff_time
                ]
                
                await asyncio.sleep(300)  # 5 minutes
                
            except Exception as e:
                logger.error(f"Error in periodic evaluation: {e}")
                await asyncio.sleep(60)
    
    async def stop(self):
        """Stop the threat response system."""
        self.running = False
        logger.info("Threat response system stopped")
    
    def get_response_statistics(self) -> Dict:
        """Get response system statistics."""
        total_responses = len(self.response_history)
        successful_responses = sum(1 for r in self.response_history if r.success)
        
        return {
            'total_responses': total_responses,
            'successful_responses': successful_responses,
            'success_rate': successful_responses / total_responses if total_responses > 0 else 0,
            'active_strategies': len(self.response_strategies),
            'q_table_size': len(self.q_agent.q_table),
            'strategy_performance': dict(self.strategy_performance)
        }
    
    def get_recent_responses(self, limit: int = 50) -> List[Dict]:
        """Get recent response results."""
        return [asdict(result) for result in self.response_history[-limit:]]
    
    def get_q_table(self) -> Dict[str, Dict[str, float]]:
        """Get current Q-table from the learning agent."""
        return self.q_agent.get_q_table() 