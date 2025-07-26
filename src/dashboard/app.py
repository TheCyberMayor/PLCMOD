"""
Interactive dashboard for ICS cybersecurity monitoring.
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.graph_analysis.attack_graph import Node, Edge

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path

import dash
from dash import dcc, html, Input, Output, State, callback_context
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
from loguru import logger


def create_dashboard_app(components: Dict[str, Any]) -> dash.Dash:
    """Create the main dashboard application."""
    
    # Initialize Dash app
    app = dash.Dash(
        __name__,
        external_stylesheets=[dbc.themes.DARKLY],
        suppress_callback_exceptions=True
    )
    
    app.title = "ICS Cybersecurity Dashboard"
    
    # Create layout
    app.layout = create_dashboard_layout(components)
    
    # Register callbacks
    register_dashboard_callbacks(app, components)
    
    logger.info("Dashboard application created")
    return app


def create_dashboard_layout(components: Dict[str, Any]) -> html.Div:
    """Create the main dashboard layout."""
    
    return html.Div([
        # Header
        dbc.Navbar(
            dbc.Container([
                dbc.NavbarBrand("ICS Cybersecurity System", className="ms-2"),
                dbc.Nav([
                    dbc.NavItem(dbc.NavLink("Overview", href="#overview")),
                    dbc.NavItem(dbc.NavLink("Threats", href="#threats")),
                    dbc.NavItem(dbc.NavLink("Network", href="#network")),
                    dbc.NavItem(dbc.NavLink("Graph", href="#graph")),
                    dbc.NavItem(dbc.NavLink("Response", href="#response")),
                ]),
                dbc.Nav([
                    dbc.NavItem(html.Span(id="system-status", className="badge bg-success")),
                    dbc.NavItem(html.Span(id="last-update", className="text-light ms-3")),
                ], className="ms-auto"),
            ]),
            color="dark",
            dark=True,
        ),
        
        # Main content
        dbc.Container([
            # Overview Section
            html.Div(id="overview-section", children=[
                dbc.Row([
                    dbc.Col([
                        html.H2("System Overview", className="mb-4"),
                        dbc.Row([
                            # Key metrics cards
                            dbc.Col(create_metric_card("Total Threats", "threat-count", "danger"), width=3),
                            dbc.Col(create_metric_card("Active Alerts", "active-alerts", "warning"), width=3),
                            dbc.Col(create_metric_card("Risk Score", "risk-score", "info"), width=3),
                            dbc.Col(create_metric_card("System Status", "system-status-card", "success"), width=3),
                        ], className="mb-4"),
                        
                        # Real-time charts
                        dbc.Row([
                            dbc.Col([
                                dcc.Graph(id="threat-timeline", style={'height': '300px'})
                            ], width=6),
                            dbc.Col([
                                dcc.Graph(id="risk-distribution", style={'height': '300px'})
                            ], width=6),
                        ]),
                    ]),
                ]),
            ]),
            
            # Threats Section
            html.Div(id="threats-section", children=[
                dbc.Row([
                    dbc.Col([
                        html.H2("Threat Analysis", className="mb-4"),
                        
                        # Threat filters
                        dbc.Row([
                            dbc.Col([
                                dbc.Label("Threat Level"),
                                dcc.Dropdown(
                                    id="threat-level-filter",
                                    options=[
                                        {"label": "All", "value": "all"},
                                        {"label": "Low", "value": "low"},
                                        {"label": "Medium", "value": "medium"},
                                        {"label": "High", "value": "high"},
                                        {"label": "Critical", "value": "critical"},
                                    ],
                                    value="all",
                                    clearable=False
                                )
                            ], width=3),
                            dbc.Col([
                                dbc.Label("Time Range"),
                                dcc.Dropdown(
                                    id="time-range-filter",
                                    options=[
                                        {"label": "Last Hour", "value": "1h"},
                                        {"label": "Last 6 Hours", "value": "6h"},
                                        {"label": "Last 24 Hours", "value": "24h"},
                                        {"label": "Last 7 Days", "value": "7d"},
                                    ],
                                    value="24h",
                                    clearable=False
                                )
                            ], width=3),
                            dbc.Col([
                                dbc.Label("Source IP"),
                                dcc.Input(
                                    id="source-ip-filter",
                                    type="text",
                                    placeholder="Filter by source IP"
                                )
                            ], width=3),
                            dbc.Col([
                                dbc.Button("Refresh", id="refresh-threats", color="primary", className="mt-4")
                            ], width=3),
                        ], className="mb-4"),
                        
                        # Threat table
                        html.Div(id="threat-table-container"),
                        
                        # Threat details
                        html.Div(id="threat-details", className="mt-4"),
                    ]),
                ]),
            ]),
            
            # Network Section
            html.Div(id="network-section", children=[
                dbc.Row([
                    dbc.Col([
                        html.H2("Network Monitoring", className="mb-4"),
                        
                        # Network statistics
                        dbc.Row([
                            dbc.Col(create_metric_card("Packets/sec", "packets-per-sec", "info"), width=3),
                            dbc.Col(create_metric_card("ICS Packets", "ics-packets", "warning"), width=3),
                            dbc.Col(create_metric_card("Blocked IPs", "blocked-ips", "danger"), width=3),
                            dbc.Col(create_metric_card("Active Connections", "active-connections", "success"), width=3),
                        ], className="mb-4"),
                        
                        # Network charts
                        dbc.Row([
                            dbc.Col([
                                dcc.Graph(id="protocol-distribution", style={'height': '300px'})
                            ], width=6),
                            dbc.Col([
                                dcc.Graph(id="traffic-flow", style={'height': '300px'})
                            ], width=6),
                        ]),
                        
                        # Packet capture controls
                        dbc.Row([
                            dbc.Col([
                                dbc.Button("Start Capture", id="start-capture", color="success", className="me-2"),
                                dbc.Button("Stop Capture", id="stop-capture", color="danger", className="me-2"),
                                dbc.Button("Export Data", id="export-data", color="info"),
                            ], className="mt-4"),
                        ]),
                    ]),
                ]),
            ]),
            
            # Graph Section
            html.Div(id="graph-section", children=[
                dbc.Row([
                    dbc.Col([
                        html.H2("Attack Graph Analysis", className="mb-4"),
                        
                        # Graph controls
                        dbc.Row([
                            dbc.Col([
                                dbc.Label("Layout Algorithm"),
                                dcc.Dropdown(
                                    id="graph-layout",
                                    options=[
                                        {"label": "Spring", "value": "spring"},
                                        {"label": "Circular", "value": "circular"},
                                        {"label": "Random", "value": "random"},
                                        {"label": "Shell", "value": "shell"},
                                    ],
                                    value="spring",
                                    clearable=False
                                )
                            ], width=3),
                            dbc.Col([
                                dbc.Label("Node Size"),
                                dcc.Slider(
                                    id="node-size-slider",
                                    min=10,
                                    max=50,
                                    step=5,
                                    value=20,
                                    marks={i: str(i) for i in range(10, 51, 10)}
                                )
                            ], width=3),
                            dbc.Col([
                                dbc.Label("Show Labels"),
                                dcc.Checklist(
                                    id="show-labels",
                                    options=[{"label": "Show", "value": "show"}],
                                    value=["show"]
                                )
                            ], width=3),
                            dbc.Col([
                                dbc.Button("Update Graph", id="update-graph", color="primary", className="mt-4")
                            ], width=3),
                        ], className="mb-4"),
                        
                        # Attack graph visualization
                        dcc.Graph(id="attack-graph", style={'height': '600px'}),
                        
                        # Graph statistics
                        dbc.Row([
                            dbc.Col([
                                html.H4("Graph Statistics"),
                                html.Div(id="graph-stats")
                            ], width=6),
                            dbc.Col([
                                html.H4("Critical Nodes"),
                                html.Div(id="critical-nodes")
                            ], width=6),
                        ], className="mt-4"),
                    ]),
                ]),
            ]),
            
            # Response Section
            html.Div(id="response-section", children=[
                dbc.Row([
                    dbc.Col([
                        html.H2("Threat Response", className="mb-4"),
                        
                        # Response statistics
                        dbc.Row([
                            dbc.Col(create_metric_card("Total Responses", "total-responses", "info"), width=3),
                            dbc.Col(create_metric_card("Success Rate", "response-success-rate", "success"), width=3),
                            dbc.Col(create_metric_card("Active Strategies", "active-strategies", "warning"), width=3),
                            dbc.Col(create_metric_card("Auto Response", "auto-response-status", "primary"), width=3),
                        ], className="mb-4"),
                        
                        # Response controls
                        dbc.Row([
                            dbc.Col([
                                dbc.Label("Response Mode"),
                                dcc.Dropdown(
                                    id="response-mode",
                                    options=[
                                        {"label": "Automatic", "value": "auto"},
                                        {"label": "Manual Approval", "value": "manual"},
                                        {"label": "Disabled", "value": "disabled"},
                                    ],
                                    value="auto",
                                    clearable=False
                                )
                            ], width=3),
                            dbc.Col([
                                dbc.Label("Response Level"),
                                dcc.Dropdown(
                                    id="response-level",
                                    options=[
                                        {"label": "Low", "value": "low"},
                                        {"label": "Medium", "value": "medium"},
                                        {"label": "High", "value": "high"},
                                        {"label": "Critical", "value": "critical"},
                                    ],
                                    value="medium",
                                    clearable=False
                                )
                            ], width=3),
                            dbc.Col([
                                dbc.Button("Execute Response", id="execute-response", color="danger", className="mt-4")
                            ], width=3),
                            dbc.Col([
                                dbc.Button("View Q-Table", id="view-q-table", color="info", className="mt-4")
                            ], width=3),
                        ], className="mb-4"),
                        
                        # Response history
                        html.Div(id="response-history"),
                        
                        # Q-Learning visualization
                        html.Div(id="q-learning-viz"),
                    ]),
                ]),
            ]),
            
            # Hidden divs for storing data
            dcc.Store(id="threat-data"),
            dcc.Store(id="network-data"),
            dcc.Store(id="graph-data"),
            dcc.Store(id="response-data"),
            
            # Interval component for updates
            dcc.Interval(
                id="update-interval",
                interval=5000,  # 5 seconds
                n_intervals=0
            ),
            
        ], fluid=True, className="mt-4"),
        
        # Footer
        dbc.Navbar(
            dbc.Container([
                html.Span("ICS Cybersecurity System v1.0", className="text-light"),
                html.Span(id="footer-status", className="text-light ms-auto"),
            ]),
            color="dark",
            dark=True,
            className="mt-5"
        ),
    ])


def create_metric_card(title: str, id: str, color: str) -> dbc.Card:
    """Create a metric card component."""
    return dbc.Card([
        dbc.CardBody([
            html.H4(title, className="card-title"),
            html.H2(id=id, children="0", className=f"text-{color}"),
        ])
    ])


def register_dashboard_callbacks(app: dash.Dash, components: Dict[str, Any]):
    """Register all dashboard callbacks."""
    
    @app.callback(
        [Output("system-status", "children"),
         Output("last-update", "children"),
         Output("footer-status", "children")],
        [Input("update-interval", "n_intervals")]
    )
    def update_system_status(n):
        """Update system status indicators."""
        try:
            # Get system status from components
            network_stats = components.get('network_monitor', {}).get_statistics() if hasattr(components.get('network_monitor'), 'get_statistics') else {}
            response_stats = components.get('response_system', {}).get_response_statistics() if hasattr(components.get('response_system'), 'get_response_statistics') else {}
            
            # Determine overall system status
            if network_stats.get('threats_detected', 0) > 10:
                status = "HIGH THREAT"
                status_class = "danger"
            elif network_stats.get('threats_detected', 0) > 5:
                status = "MEDIUM THREAT"
                status_class = "warning"
            else:
                status = "SECURE"
                status_class = "success"
            
            last_update = datetime.now().strftime("%H:%M:%S")
            footer_text = f"Last updated: {last_update} | Threats: {network_stats.get('threats_detected', 0)} | Responses: {response_stats.get('total_responses', 0)}"
            
            return status, last_update, footer_text
            
        except Exception as e:
            logger.error(f"Error updating system status: {e}")
            return "ERROR", "N/A", "System error"
    
    @app.callback(
        [Output("threat-count", "children"),
         Output("active-alerts", "children"),
         Output("risk-score", "children"),
         Output("system-status-card", "children")],
        [Input("update-interval", "n_intervals")]
    )
    def update_overview_metrics(n):
        """Update overview metrics."""
        try:
            # Get data from components
            network_monitor = components.get('network_monitor')
            risk_scorer = components.get('risk_scorer')
            response_system = components.get('response_system')
            
            # Calculate metrics
            threat_count = len(network_monitor.get_recent_threats()) if network_monitor else 0
            active_alerts = len([t for t in network_monitor.get_recent_threats() if t.get('severity') in ['high', 'critical']]) if network_monitor else 0
            
            # Calculate average risk score
            risk_scores = risk_scorer.get_recent_risk_scores() if risk_scorer else []
            avg_risk = sum(r.get('risk_score', 0) for r in risk_scores) / len(risk_scores) if risk_scores else 0
            
            # System status
            response_stats = response_system.get_response_statistics() if response_system else {}
            system_status = "OPERATIONAL" if response_stats.get('success_rate', 1) > 0.8 else "DEGRADED"
            
            return (
                str(threat_count),
                str(active_alerts),
                f"{avg_risk:.2f}",
                system_status
            )
            
        except Exception as e:
            logger.error(f"Error updating overview metrics: {e}")
            return "0", "0", "0.00", "ERROR"
    
    @app.callback(
        Output("threat-timeline", "figure"),
        [Input("update-interval", "n_intervals"),
         Input("time-range-filter", "value")]
    )
    def update_threat_timeline(n, time_range):
        """Update threat timeline chart."""
        try:
            network_monitor = components.get('network_monitor')
            if not network_monitor:
                return create_empty_figure("No threat data available")
            
            threats = network_monitor.get_recent_threats(limit=100)
            if not threats:
                return create_empty_figure("No threats detected")
            
            # Convert to DataFrame
            df = pd.DataFrame(threats)
            df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
            
            # Filter by time range
            if time_range:
                cutoff_time = datetime.now() - parse_time_range(time_range)
                df = df[df['timestamp'] > cutoff_time]
            
            # Group by time and severity
            df['hour'] = df['timestamp'].dt.floor('H')
            threat_counts = df.groupby(['hour', 'severity']).size().reset_index(name='count')
            
            # Create figure
            fig = px.line(
                threat_counts,
                x='hour',
                y='count',
                color='severity',
                title="Threat Timeline",
                labels={'hour': 'Time', 'count': 'Threat Count', 'severity': 'Severity'}
            )
            
            fig.update_layout(
                template="plotly_dark",
                xaxis_title="Time",
                yaxis_title="Threat Count",
                showlegend=True
            )
            
            return fig
            
        except Exception as e:
            logger.error(f"Error updating threat timeline: {e}")
            return create_empty_figure("Error loading threat data")
    
    @app.callback(
        Output("risk-distribution", "figure"),
        [Input("update-interval", "n_intervals")]
    )
    def update_risk_distribution(n):
        """Update risk distribution chart."""
        try:
            risk_scorer = components.get('risk_scorer')
            if not risk_scorer:
                return create_empty_figure("No risk data available")
            
            risk_scores = risk_scorer.get_recent_risk_scores(limit=100)
            if not risk_scores:
                return create_empty_figure("No risk assessments available")
            
            # Extract risk scores
            scores = [r.get('risk_score', 0) for r in risk_scores]
            
            # Create histogram
            fig = px.histogram(
                x=scores,
                nbins=20,
                title="Risk Score Distribution",
                labels={'x': 'Risk Score', 'y': 'Frequency'}
            )
            
            fig.update_layout(
                template="plotly_dark",
                xaxis_title="Risk Score",
                yaxis_title="Frequency",
                showlegend=False
            )
            
            # Add vertical line for threshold
            fig.add_vline(x=0.8, line_dash="dash", line_color="red", annotation_text="High Risk Threshold")
            fig.add_vline(x=0.6, line_dash="dash", line_color="orange", annotation_text="Medium Risk Threshold")
            
            return fig
            
        except Exception as e:
            logger.error(f"Error updating risk distribution: {e}")
            return create_empty_figure("Error loading risk data")
    
    @app.callback(
        Output("threat-table-container", "children"),
        [Input("update-interval", "n_intervals"),
         Input("threat-level-filter", "value"),
         Input("source-ip-filter", "value"),
         Input("refresh-threats", "n_clicks")]
    )
    def update_threat_table(n, threat_level, source_ip, refresh_clicks):
        """Update threat table."""
        try:
            network_monitor = components.get('network_monitor')
            if not network_monitor:
                return html.Div("No threat data available", className="text-muted")
            
            threats = network_monitor.get_recent_threats(limit=50)
            
            # Apply filters
            if threat_level and threat_level != "all":
                threats = [t for t in threats if t.get('severity') == threat_level]
            
            if source_ip:
                threats = [t for t in threats if source_ip in t.get('source_ip', '')]
            
            if not threats:
                return html.Div("No threats match the current filters", className="text-muted")
            
            # Create table
            table_rows = []
            for threat in threats:
                severity_color = {
                    'low': 'success',
                    'medium': 'warning',
                    'high': 'danger',
                    'critical': 'danger'
                }.get(threat.get('severity', 'medium'), 'secondary')
                
                table_rows.append(html.Tr([
                    html.Td(threat.get('source_ip', 'N/A')),
                    html.Td(threat.get('destination_ip', 'N/A')),
                    html.Td(threat.get('threat_type', 'N/A')),
                    html.Td(dbc.Badge(threat.get('severity', 'medium'), color=severity_color)),
                    html.Td(f"{threat.get('confidence', 0):.2f}"),
                    html.Td(datetime.fromtimestamp(threat.get('timestamp', 0)).strftime("%H:%M:%S")),
                ]))
            
            table = dbc.Table([
                html.Thead(html.Tr([
                    html.Th("Source IP"),
                    html.Th("Destination IP"),
                    html.Th("Threat Type"),
                    html.Th("Severity"),
                    html.Th("Confidence"),
                    html.Th("Time"),
                ])),
                html.Tbody(table_rows)
            ], striped=True, bordered=True, hover=True)
            
            return table
            
        except Exception as e:
            logger.error(f"Error updating threat table: {e}")
            return html.Div("Error loading threat data", className="text-danger")
    
    @app.callback(
        Output("attack-graph", "figure"),
        [Input("update-graph", "n_clicks"),
         Input("graph-layout", "value"),
         Input("node-size-slider", "value"),
         Input("show-labels", "value")]
    )
    def update_attack_graph(n_clicks, layout, node_size, show_labels):
        """Update attack graph visualization."""
        try:
            graph_analyzer = components.get('graph_analyzer')
            if not graph_analyzer:
                return create_empty_figure("No graph data available")
            
            # Get graph data
            nodes = list(graph_analyzer.nodes.values())
            edges = list(graph_analyzer.edges.values())
            
            if not nodes:
                return create_empty_figure("No nodes in graph")
            
            # Create network graph
            fig = go.Figure()
            
            # Add edges
            edge_x = []
            edge_y = []
            edge_text = []
            
            for edge in edges:
                source_node = graph_analyzer.nodes.get(edge.source)
                target_node = graph_analyzer.nodes.get(edge.target)
                
                if source_node and target_node:
                    # Simple positioning (in real implementation, use layout algorithm)
                    edge_x.extend([0, 1, None])
                    edge_y.extend([0, 1, None])
                    edge_text.append(f"{edge.source} → {edge.target}<br>Protocol: {edge.protocol}<br>Risk: {edge.attack_probability:.2f}")
            
            if edge_x:
                fig.add_trace(go.Scatter(
                    x=edge_x, y=edge_y,
                    line=dict(width=1, color='#888'),
                    hoverinfo='none',
                    mode='lines',
                    name='Connections'
                ))
            
            # Add nodes
            node_x = []
            node_y = []
            node_text = []
            node_colors = []
            node_sizes = []
            
            for node in nodes:
                node_x.append(random.uniform(-1, 1))  # Random positioning
                node_y.append(random.uniform(-1, 1))
                
                node_text.append(f"Node: {node.hostname}<br>Type: {node.type}<br>Criticality: {node.criticality:.2f}")
                
                # Color by criticality
                if node.criticality > 0.8:
                    node_colors.append('red')
                elif node.criticality > 0.5:
                    node_colors.append('orange')
                else:
                    node_colors.append('green')
                
                # Size by criticality
                node_sizes.append(node_size * (1 + node.criticality))
            
            fig.add_trace(go.Scatter(
                x=node_x, y=node_y,
                mode='markers',
                hoverinfo='text',
                text=node_text,
                marker=dict(
                    size=node_sizes,
                    color=node_colors,
                    line_width=2
                ),
                name='Nodes'
            ))
            
            # Update layout
            fig.update_layout(
                title='ICS Attack Graph',
                showlegend=True,
                hovermode='closest',
                template="plotly_dark",
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                height=600
            )
            
            return fig
            
        except Exception as e:
            logger.error(f"Error updating attack graph: {e}")
            return create_empty_figure("Error loading graph data")
    
    @app.callback(
        Output("response-history", "children"),
        [Input("update-interval", "n_intervals")]
    )
    def update_response_history(n):
        """Update response history table."""
        try:
            response_system = components.get('response_system')
            if not response_system:
                return html.Div("No response data available", className="text-muted")
            
            responses = response_system.get_recent_responses(limit=20)
            
            if not responses:
                return html.Div("No recent responses", className="text-muted")
            
            # Create table
            table_rows = []
            for response in responses:
                success_color = "success" if response.get('success') else "danger"
                success_text = "SUCCESS" if response.get('success') else "FAILED"
                
                table_rows.append(html.Tr([
                    html.Td(response.get('action_id', 'N/A')),
                    html.Td(dbc.Badge(success_text, color=success_color)),
                    html.Td(f"{response.get('execution_time', 0):.2f}s"),
                    html.Td(datetime.fromtimestamp(response.get('timestamp', 0)).strftime("%H:%M:%S")),
                    html.Td(response.get('description', 'N/A')),
                ]))
            
            table = dbc.Table([
                html.Thead(html.Tr([
                    html.Th("Action ID"),
                    html.Th("Status"),
                    html.Th("Execution Time"),
                    html.Th("Timestamp"),
                    html.Th("Description"),
                ])),
                html.Tbody(table_rows)
            ], striped=True, bordered=True, hover=True)
            
            return table
            
        except Exception as e:
            logger.error(f"Error updating response history: {e}")
            return html.Div("Error loading response data", className="text-danger")


def create_empty_figure(message: str) -> go.Figure:
    """Create an empty figure with a message."""
    fig = go.Figure()
    fig.add_annotation(
        text=message,
        xref="paper", yref="paper",
        x=0.5, y=0.5,
        showarrow=False,
        font=dict(size=16, color="gray")
    )
    fig.update_layout(
        template="plotly_dark",
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
    )
    return fig


def parse_time_range(time_range: str) -> timedelta:
    """Parse time range string to timedelta."""
    if time_range == "1h":
        return timedelta(hours=1)
    elif time_range == "6h":
        return timedelta(hours=6)
    elif time_range == "24h":
        return timedelta(days=1)
    elif time_range == "7d":
        return timedelta(days=7)
    else:
        return timedelta(hours=24)  # Default to 24 hours


if __name__ == "__main__":
    """Run the dashboard as a standalone server."""
    import yaml
    from pathlib import Path
    
    # Load configuration
    config_path = Path("config/settings.yaml")
    if config_path.exists():
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
    else:
        config = {
            'dashboard': {
                'host': '0.0.0.0',
                'port': 8050
            }
        }
    
    # Create mock components for standalone dashboard
    mock_components = {
        'network_monitor': None,
        'graph_analyzer': None,
        'risk_scorer': None,
        'response_system': None,
        'model_validator': None
    }
    
    # Create and run the dashboard app
    app = create_dashboard_app(mock_components)
    
    print(f"Starting ICS Cybersecurity Dashboard...")
    print(f"Dashboard will be available at: http://{config['dashboard']['host']}:{config['dashboard']['port']}")
    print("Press Ctrl+C to stop the server")
    
    app.run_server(
        host=config['dashboard']['host'],
        port=config['dashboard']['port'],
        debug=False
    ) 