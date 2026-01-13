#!/usr/bin/env python3
"""
Wazuh MCP CLI Client

A feature-complete Python CLI tool for communicating with the Wazuh MCP server
via JSON-RPC over HTTP. Designed for cybersecurity and threat hunting operations.
"""

import argparse
import json
import os
import sys
import uuid
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    print("Error: 'requests' package is required. Install with: pip install requests")
    sys.exit(1)

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.json import JSON
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    # Fallback console
    class Console:
        def print(self, *args, **kwargs):
            print(*args, **kwargs)


class MCPError(Exception):
    """Base exception for MCP-related errors"""
    pass


class MCPHttpClient:
    """
    MCP HTTP Client for JSON-RPC communication with Wazuh MCP server.
    
    Handles the complete MCP message flow:
    - initialize
    - notifications/initialized
    - tools/list
    - tools/call
    """
    
    def __init__(self, endpoint: str = "http://127.0.0.1:8080/mcp"):
        """
        Initialize MCP HTTP client.
        
        Args:
            endpoint: MCP server endpoint URL
        """
        self.endpoint = endpoint
        self.session_id = str(uuid.uuid4())
        self.headers = {
            "Content-Type": "application/json",
            "MCP-Session-Id": self.session_id
        }
        self.initialized = False
        self.server_info: Optional[Dict[str, Any]] = None
        
    def send_request(
        self, 
        method: str, 
        params: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send JSON-RPC 2.0 request to MCP server.
        
        Args:
            method: JSON-RPC method name
            params: Method parameters
            request_id: Optional request ID (generated if not provided)
            
        Returns:
            JSON-RPC response dictionary
            
        Raises:
            MCPError: If request fails or returns error
        """
        if request_id is None:
            request_id = str(uuid.uuid4())
            
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "id": request_id
        }
        
        if params is not None:
            payload["params"] = params
            
        try:
            response = requests.post(
                self.endpoint,
                headers=self.headers,
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            result = response.json()
            
            # Check for JSON-RPC error
            if "error" in result:
                error = result["error"]
                raise MCPError(
                    f"JSON-RPC Error [{error.get('code', 'unknown')}]: "
                    f"{error.get('message', 'Unknown error')}"
                )
                
            return result
            
        except requests.exceptions.RequestException as e:
            raise MCPError(f"HTTP request failed: {str(e)}")
        except json.JSONDecodeError as e:
            raise MCPError(f"Invalid JSON response: {str(e)}")
    
    def send_notification(
        self, 
        method: str, 
        params: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Send JSON-RPC 2.0 notification (no response expected).
        
        Args:
            method: JSON-RPC method name
            params: Method parameters
        """
        payload = {
            "jsonrpc": "2.0",
            "method": method
        }
        
        if params is not None:
            payload["params"] = params
            
        try:
            requests.post(
                self.endpoint,
                headers=self.headers,
                json=payload,
                timeout=30
            )
        except requests.exceptions.RequestException as e:
            # Notifications don't return responses, so we log but don't raise
            print(f"Warning: Notification failed: {str(e)}", file=sys.stderr)
    
    def initialize(self) -> Dict[str, Any]:
        """
        Initialize MCP session.
        
        Returns:
            Initialize response containing server info
        """
        response = self.send_request(
            "initialize",
            params={
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "wazuh_mcp_cli",
                    "version": "1.0.0"
                }
            }
        )
        
        self.server_info = response.get("result", {})
        self.initialized = True
        
        # Send initialized notification
        self.send_notification("notifications/initialized")
        
        return response
    
    def list_tools(self) -> Dict[str, Any]:
        """
        List all available MCP tools.
        
        Returns:
            Tools list response
        """
        if not self.initialized:
            raise MCPError("Client not initialized. Run 'init' command first.")
            
        return self.send_request("tools/list")
    
    def call_tool(
        self, 
        tool_name: str, 
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Call an MCP tool.
        
        Args:
            tool_name: Name of the tool to call
            params: Tool parameters
            
        Returns:
            Tool call response
        """
        if not self.initialized:
            raise MCPError("Client not initialized. Run 'init' command first.")
            
        return self.send_request(
            "tools/call",
            params={
                "name": tool_name,
                "arguments": params or {}
            }
        )


def print_json(data: Any, console: Optional[Console] = None) -> None:
    """Pretty print JSON data"""
    if RICH_AVAILABLE and console:
        console.print(JSON(json.dumps(data)))
    else:
        print(json.dumps(data, indent=2, ensure_ascii=False))


def init_command(client: MCPHttpClient, console: Console) -> None:
    """Initialize MCP session and display server info"""
    try:
        response = client.initialize()
        result = response.get("result", {})
        
        if RICH_AVAILABLE:
            console.print(Panel.fit(
                "[bold green]✓ MCP Session Initialized[/bold green]",
                title="Initialization"
            ))
            console.print("\n[bold]Server Info:[/bold]")
            print_json(result, console)
        else:
            print("✓ MCP Session Initialized")
            print("\nServer Info:")
            print_json(result)
            
    except MCPError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


def tools_command(client: MCPHttpClient, console: Console) -> None:
    """List all available Wazuh MCP tools"""
    try:
        response = client.list_tools()
        tools = response.get("result", {}).get("tools", [])
        
        if not tools:
            console.print("[yellow]No tools available[/yellow]")
            return
            
        if RICH_AVAILABLE:
            table = Table(title="Available Wazuh MCP Tools", show_header=True, header_style="bold magenta")
            table.add_column("Tool Name", style="cyan", no_wrap=True)
            table.add_column("Description", style="white")
            table.add_column("Input Schema", style="dim")
            
            for tool in tools:
                name = tool.get("name", "unknown")
                description = tool.get("description", "No description")
                input_schema = tool.get("inputSchema", {})
                schema_str = json.dumps(input_schema, indent=2) if input_schema else "N/A"
                
                table.add_row(name, description, schema_str)
                
            console.print(table)
        else:
            print("Available Wazuh MCP Tools:")
            print("=" * 60)
            for tool in tools:
                print(f"\nTool: {tool.get('name', 'unknown')}")
                print(f"Description: {tool.get('description', 'No description')}")
                print(f"Input Schema: {json.dumps(tool.get('inputSchema', {}), indent=2)}")
                print("-" * 60)
                
    except MCPError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


def alerts_command(client: MCPHttpClient, limit: int, console: Console) -> None:
    """Retrieve and display Wazuh alerts"""
    try:
        response = client.call_tool("get_wazuh_alert_summary", {"limit": limit})
        alerts = response.get("result", {}).get("content", [])
        
        if isinstance(alerts, str):
            # If result is a JSON string, parse it
            try:
                alerts = json.loads(alerts)
            except json.JSONDecodeError:
                alerts = []
        
        if not alerts:
            console.print("[yellow]No alerts found[/yellow]")
            return
            
        if RICH_AVAILABLE:
            table = Table(title=f"Wazuh Alerts (showing {len(alerts)} of {limit})", show_header=True)
            table.add_column("ID", style="cyan")
            table.add_column("Level", style="yellow")
            table.add_column("Agent", style="green")
            table.add_column("Rule ID", style="magenta")
            table.add_column("Description", style="white")
            table.add_column("Timestamp", style="dim")
            
            for alert in alerts[:limit]:
                alert_id = str(alert.get("id", "N/A"))
                level = str(alert.get("level", alert.get("level", "N/A")))
                agent_info = alert.get("agent", {})
                agent_name = agent_info.get("name", "N/A") if isinstance(agent_info, dict) else str(agent_info)
                rule_info = alert.get("rule", {})
                rule_id = str(rule_info.get("id", "N/A")) if isinstance(rule_info, dict) else str(rule_info)
                description = str(alert.get("description", alert.get("rule", {}).get("description", "N/A")))
                timestamp = str(alert.get("timestamp", alert.get("@timestamp", "N/A")))
                
                table.add_row(alert_id, level, agent_name, rule_id, description[:50], timestamp[:20])
                
            console.print(table)
        else:
            print(f"Wazuh Alerts (showing {len(alerts)}):")
            print("=" * 80)
            for alert in alerts[:limit]:
                print(f"\nID: {alert.get('id', 'N/A')}")
                print(f"Level: {alert.get('level', 'N/A')}")
                print(f"Agent: {alert.get('agent', {}).get('name', 'N/A')}")
                print(f"Rule ID: {alert.get('rule', {}).get('id', 'N/A')}")
                print(f"Description: {alert.get('description', 'N/A')}")
                print("-" * 80)
                
    except MCPError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


def test_agents_command(client: MCPHttpClient, console: Console) -> None:
    """Test Wazuh agents - list online/offline agents"""
    try:
        # Try different possible tool names
        tool_names = ["list_wazuh_agents", "list_agents", "get_agents"]
        agents_data = None
        
        for tool_name in tool_names:
            try:
                response = client.call_tool(tool_name)
                result = response.get("result", {})
                if isinstance(result, str):
                    result = json.loads(result)
                content = result.get("content", result) if isinstance(result, dict) else result
                if content:
                    agents_data = content if isinstance(content, list) else [content]
                    break
            except MCPError:
                continue
        
        if agents_data is None:
            console.print("[yellow]Warning: Could not retrieve agents. Trying alternative method...[/yellow]")
            # Fallback: try to get agents from alerts
            response = client.call_tool("get_wazuh_alert_summary", {"limit": 1000})
            alerts = response.get("result", {}).get("content", [])
            if isinstance(alerts, str):
                alerts = json.loads(alerts)
            
            agents_dict = {}
            for alert in alerts:
                agent_info = alert.get("agent", {})
                if isinstance(agent_info, dict):
                    agent_id = agent_info.get("id")
                    if agent_id:
                        agents_dict[agent_id] = {
                            "id": agent_id,
                            "name": agent_info.get("name", f"Agent-{agent_id}"),
                            "os": agent_info.get("os", {}).get("name", "Unknown") if isinstance(agent_info.get("os"), dict) else "Unknown",
                            "status": "online"  # Assume online if we see alerts
                        }
            agents_data = list(agents_dict.values())
        
        if not agents_data:
            console.print("[yellow]No agents found[/yellow]")
            return
        
        # Categorize agents
        online_agents = []
        offline_agents = []
        
        for agent in agents_data:
            status = str(agent.get("status", "unknown")).lower()
            if status == "online" or status == "active":
                online_agents.append(agent)
            else:
                offline_agents.append(agent)
        
        if RICH_AVAILABLE:
            table = Table(title="Wazuh Agents Status", show_header=True, header_style="bold")
            table.add_column("Agent ID", style="cyan")
            table.add_column("Name", style="white")
            table.add_column("OS", style="green")
            table.add_column("Status", style="yellow")
            
            for agent in agents_data:
                agent_id = str(agent.get("id", "N/A"))
                name = str(agent.get("name", "N/A"))
                os_name = str(agent.get("os", {}).get("name", "Unknown")) if isinstance(agent.get("os"), dict) else str(agent.get("os", "Unknown"))
                status = str(agent.get("status", "unknown"))
                status_style = "[green]online[/green]" if status.lower() == "online" else "[red]offline[/red]"
                
                table.add_row(agent_id, name, os_name, status)
            
            console.print(table)
            console.print(f"\n[bold]Summary:[/bold]")
            console.print(f"  Online Agents: [green]{len(online_agents)}[/green]")
            console.print(f"  Offline Agents: [red]{len(offline_agents)}[/red]")
            console.print(f"  Total Agents: [cyan]{len(agents_data)}[/cyan]")
        else:
            print("Wazuh Agents Status:")
            print("=" * 80)
            for agent in agents_data:
                print(f"ID: {agent.get('id', 'N/A')}, Name: {agent.get('name', 'N/A')}, "
                      f"OS: {agent.get('os', {}).get('name', 'Unknown')}, Status: {agent.get('status', 'unknown')}")
            print(f"\nSummary: Online: {len(online_agents)}, Offline: {len(offline_agents)}, Total: {len(agents_data)}")
            
    except MCPError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


def test_risks_command(client: MCPHttpClient, limit: int, console: Console) -> None:
    """Test high-risk agents based on alert analysis"""
    try:
        response = client.call_tool("get_wazuh_alert_summary", {"limit": limit})
        alerts = response.get("result", {}).get("content", [])
        
        if isinstance(alerts, str):
            alerts = json.loads(alerts)
        
        if not alerts:
            console.print("[yellow]No alerts found for risk analysis[/yellow]")
            return
        
        # Analyze alerts for high-risk agents
        agent_risks: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "name": "Unknown",
            "high_level_alerts": 0,
            "total_alerts": 0,
            "alert_levels": [],
            "rule_ids": set(),
            "mitre_tactics": set()
        })
        
        for alert in alerts:
            agent_info = alert.get("agent", {})
            if isinstance(agent_info, dict):
                agent_id = str(agent_info.get("id", "unknown"))
                agent_name = agent_info.get("name", "Unknown")
            else:
                agent_id = str(agent_info) if agent_info else "unknown"
                agent_name = "Unknown"
            
            level = alert.get("level", 0)
            rule_info = alert.get("rule", {})
            rule_id = str(rule_info.get("id", "N/A")) if isinstance(rule_info, dict) else str(rule_info)
            
            agent_risks[agent_id]["name"] = agent_name
            agent_risks[agent_id]["total_alerts"] += 1
            agent_risks[agent_id]["alert_levels"].append(level)
            agent_risks[agent_id]["rule_ids"].add(rule_id)
            
            if level >= 7:
                agent_risks[agent_id]["high_level_alerts"] += 1
            
            # Extract MITRE tactics if available
            mitre_info = alert.get("rule", {}).get("mitre", {}) if isinstance(alert.get("rule"), dict) else {}
            if isinstance(mitre_info, dict):
                tactics = mitre_info.get("tactic", [])
                if isinstance(tactics, list):
                    agent_risks[agent_id]["mitre_tactics"].update(tactics)
        
        # Calculate risk scores
        risk_scores = []
        for agent_id, data in agent_risks.items():
            # Risk score = (high_level_alerts * 10) + (total_alerts * 0.5) + (unique_rules * 2)
            risk_score = (
                data["high_level_alerts"] * 10 +
                data["total_alerts"] * 0.5 +
                len(data["rule_ids"]) * 2
            )
            
            # Reasons for ranking
            reasons = []
            if data["high_level_alerts"] > 0:
                reasons.append(f"{data['high_level_alerts']} high-level alerts (>=7)")
            if data["total_alerts"] > 10:
                reasons.append(f"{data['total_alerts']} total alerts")
            if len(data["rule_ids"]) > 5:
                reasons.append(f"{len(data['rule_ids'])} unique rule violations")
            if data["mitre_tactics"]:
                reasons.append(f"MITRE tactics: {', '.join(list(data['mitre_tactics'])[:3])}")
            
            risk_scores.append({
                "agent_id": agent_id,
                "name": data["name"],
                "risk_score": risk_score,
                "high_level_alerts": data["high_level_alerts"],
                "total_alerts": data["total_alerts"],
                "unique_rules": len(data["rule_ids"]),
                "reasons": reasons,
                "mitre_tactics": list(data["mitre_tactics"])
            })
        
        # Sort by risk score and get top 5
        risk_scores.sort(key=lambda x: x["risk_score"], reverse=True)
        top_risks = risk_scores[:5]
        
        if RICH_AVAILABLE:
            table = Table(title="Top 5 High-Risk Agents", show_header=True, header_style="bold red")
            table.add_column("Rank", style="cyan")
            table.add_column("Agent ID", style="white")
            table.add_column("Name", style="green")
            table.add_column("Risk Score", style="red", justify="right")
            table.add_column("High-Level Alerts", style="yellow", justify="right")
            table.add_column("Total Alerts", style="yellow", justify="right")
            table.add_column("Reasons", style="dim")
            
            for idx, risk in enumerate(top_risks, 1):
                reasons_str = "; ".join(risk["reasons"][:2]) if risk["reasons"] else "Multiple alert patterns"
                table.add_row(
                    str(idx),
                    risk["agent_id"],
                    risk["name"],
                    f"{risk['risk_score']:.1f}",
                    str(risk["high_level_alerts"]),
                    str(risk["total_alerts"]),
                    reasons_str
                )
            
            console.print(table)
            
            # Detailed reasons for top agent
            if top_risks:
                top_agent = top_risks[0]
                console.print(f"\n[bold]Detailed Analysis for Top Risk Agent ({top_agent['name']}):[/bold]")
                console.print(f"  Risk Score: [red]{top_agent['risk_score']:.1f}[/red]")
                console.print(f"  High-Level Alerts: [yellow]{top_agent['high_level_alerts']}[/yellow]")
                console.print(f"  Total Alerts: [yellow]{top_agent['total_alerts']}[/yellow]")
                console.print(f"  Unique Rule Violations: [cyan]{top_agent['unique_rules']}[/cyan]")
                if top_agent["mitre_tactics"]:
                    console.print(f"  MITRE ATT&CK Tactics: [magenta]{', '.join(top_agent['mitre_tactics'])}[/magenta]")
                console.print(f"  Reasons: {'; '.join(top_agent['reasons'])}")
        else:
            print("Top 5 High-Risk Agents:")
            print("=" * 100)
            for idx, risk in enumerate(top_risks, 1):
                print(f"\nRank {idx}: {risk['name']} (ID: {risk['agent_id']})")
                print(f"  Risk Score: {risk['risk_score']:.1f}")
                print(f"  High-Level Alerts: {risk['high_level_alerts']}")
                print(f"  Total Alerts: {risk['total_alerts']}")
                print(f"  Reasons: {'; '.join(risk['reasons'])}")
                
    except MCPError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


def test_connectivity_command(client: MCPHttpClient, console: Console) -> None:
    """Test connectivity to MCP endpoint and related services"""
    results = []
    
    # Test MCP endpoint
    try:
        response = requests.get(client.endpoint.replace("/mcp", ""), timeout=5)
        results.append(("MCP Endpoint", True, f"HTTP {response.status_code}"))
    except Exception as e:
        results.append(("MCP Endpoint", False, str(e)))
    
    # Test MCP initialization
    try:
        client.initialize()
        results.append(("MCP Initialization", True, "Success"))
    except Exception as e:
        results.append(("MCP Initialization", False, str(e)))
    
    if RICH_AVAILABLE:
        table = Table(title="Connectivity Test Results", show_header=True)
        table.add_column("Service", style="cyan")
        table.add_column("Status", style="yellow")
        table.add_column("Details", style="white")
        
        for service, success, details in results:
            status = "[green]✓ PASS[/green]" if success else "[red]✗ FAIL[/red]"
            table.add_row(service, status, details)
        
        console.print(table)
    else:
        print("Connectivity Test Results:")
        print("=" * 80)
        for service, success, details in results:
            status = "✓ PASS" if success else "✗ FAIL"
            print(f"{service}: {status} - {details}")


def hunt_command(
    client: MCPHttpClient, 
    openai_key: Optional[str], 
    limit: int, 
    model: str,
    console: Console
) -> None:
    """Automated threat hunting using OpenAI LLM analysis"""
    if OpenAI is None:
        console.print("[bold red]Error:[/bold red] OpenAI package not installed. Install with: pip install openai")
        sys.exit(1)
    
    if not openai_key:
        openai_key = os.getenv("OPENAI_API_KEY")
        if not openai_key:
            console.print("[bold red]Error:[/bold red] OpenAI API key required. Set OPENAI_API_KEY env var or use --openai-key")
            sys.exit(1)
    
    try:
        console.print("[cyan]Retrieving alerts and agent information...[/cyan]")
        
        # Retrieve alerts
        alerts_response = client.call_tool("get_wazuh_alert_summary", {"limit": limit})
        alerts = alerts_response.get("result", {}).get("content", [])
        if isinstance(alerts, str):
            alerts = json.loads(alerts)
        
        # Retrieve agent info
        agents_data = []
        try:
            agents_response = client.call_tool("list_wazuh_agents")
            agents_result = agents_response.get("result", {})
            if isinstance(agents_result, str):
                agents_result = json.loads(agents_result)
            agents_content = agents_result.get("content", agents_result) if isinstance(agents_result, dict) else agents_result
            agents_data = agents_content if isinstance(agents_content, list) else [agents_content]
        except MCPError:
            # Fallback: extract agent info from alerts
            agents_dict = {}
            for alert in alerts:
                agent_info = alert.get("agent", {})
                if isinstance(agent_info, dict) and agent_info.get("id"):
                    agent_id = agent_info.get("id")
                    if agent_id not in agents_dict:
                        agents_dict[agent_id] = agent_info
            agents_data = list(agents_dict.values())
        
        # Build analysis JSON
        high_risk_alerts = [a for a in alerts if a.get("level", 0) >= 7]
        
        analysis_data = {
            "summary": {
                "total_alerts": len(alerts),
                "high_risk_alerts": len(high_risk_alerts),
                "unique_agents": len(set(str(a.get("agent", {}).get("id", "")) for a in alerts)),
                "time_range": {
                    "earliest": min((a.get("timestamp", a.get("@timestamp", "")) for a in alerts), default="N/A"),
                    "latest": max((a.get("timestamp", a.get("@timestamp", "")) for a in alerts), default="N/A")
                }
            },
            "high_risk_alerts": high_risk_alerts[:50],  # Limit to 50 for LLM
            "host_metadata": agents_data[:20],  # Limit to 20 agents
            "rule_ids": list(set(str(a.get("rule", {}).get("id", "")) for a in alerts if isinstance(a.get("rule"), dict))),
            "mitre_mappings": []
        }
        
        # Extract MITRE mappings
        for alert in alerts[:100]:
            rule_info = alert.get("rule", {})
            if isinstance(rule_info, dict):
                mitre = rule_info.get("mitre", {})
                if isinstance(mitre, dict) and mitre:
                    analysis_data["mitre_mappings"].append({
                        "rule_id": rule_info.get("id"),
                        "tactics": mitre.get("tactic", []),
                        "techniques": mitre.get("technique", [])
                    })
        
        console.print(f"[cyan]Analyzing {len(alerts)} alerts with OpenAI {model}...[/cyan]")
        
        # Call OpenAI API
        openai_client = OpenAI(api_key=openai_key)
        
        system_prompt = (
            "You are a senior cybersecurity analyst specializing in threat hunting and incident response. "
            "Analyze the provided Wazuh security alerts and identify:\n\n"
            "1. Possible attack paths and kill chains\n"
            "2. High-risk hosts requiring immediate attention\n"
            "3. Indicators of lateral movement\n"
            "4. Privilege escalation attempts\n"
            "5. Suspicious network activity patterns\n"
            "6. MITRE ATT&CK tactic and technique mappings\n"
            "7. Recommended remediation actions prioritized by severity\n\n"
            "Provide a structured threat hunting report with actionable insights."
        )
        
        user_prompt = (
            f"Please analyze the following Wazuh security data:\n\n"
            f"{json.dumps(analysis_data, indent=2)}"
        )
        
        response = openai_client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.3,
            max_tokens=2000
        )
        
        report = response.choices[0].message.content
        
        if RICH_AVAILABLE:
            console.print(Panel(
                report,
                title="[bold red]Threat Hunting Report[/bold red]",
                border_style="red"
            ))
        else:
            print("\n" + "=" * 80)
            print("THREAT HUNTING REPORT")
            print("=" * 80)
            print(report)
            print("=" * 80)
            
    except MCPError as e:
        console.print(f"[bold red]Error:[/bold red] MCP operation failed: {str(e)}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Threat hunting failed: {str(e)}")
        sys.exit(1)


def main() -> None:
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Wazuh MCP CLI - Cybersecurity and Threat Hunting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Initialize MCP session
  python wazuh_mcp_cli.py init

  # List available tools
  python wazuh_mcp_cli.py tools

  # Retrieve alerts
  python wazuh_mcp_cli.py alerts --limit 20

  # Test agents
  python wazuh_mcp_cli.py test agents

  # Test high-risk agents
  python wazuh_mcp_cli.py test risks --limit 100

  # Threat hunting with OpenAI
  python wazuh_mcp_cli.py hunt --limit 50 --model gpt-4o-mini
        """
    )
    
    parser.add_argument(
        "--endpoint",
        default="http://127.0.0.1:8080/mcp",
        help="MCP server endpoint URL (default: http://127.0.0.1:8080/mcp)"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Init command
    subparsers.add_parser("init", help="Initialize MCP session")
    
    # Tools command
    subparsers.add_parser("tools", help="List all available Wazuh MCP tools")
    
    # Alerts command
    alerts_parser = subparsers.add_parser("alerts", help="Retrieve Wazuh alerts")
    alerts_parser.add_argument("--limit", type=int, default=10, help="Number of alerts to retrieve (default: 10)")
    
    # Test command group
    test_parser = subparsers.add_parser("test", help="Run automated test routines")
    test_subparsers = test_parser.add_subparsers(dest="test_command", help="Test subcommands")
    
    test_subparsers.add_parser("agents", help="Test Wazuh agents (list online/offline)")
    
    test_risks_parser = test_subparsers.add_parser("risks", help="Test high-risk agents analysis")
    test_risks_parser.add_argument("--limit", type=int, default=100, help="Number of alerts to analyze (default: 100)")
    
    test_subparsers.add_parser("connectivity", help="Test connectivity to MCP endpoint")
    
    # Hunt command
    hunt_parser = subparsers.add_parser("hunt", help="Automated threat hunting using OpenAI LLM")
    hunt_parser.add_argument("--openai-key", help="OpenAI API key (or set OPENAI_API_KEY env var)")
    hunt_parser.add_argument("--limit", type=int, default=50, help="Number of alerts to analyze (default: 50)")
    hunt_parser.add_argument("--model", default="gpt-4o-mini", help="OpenAI model to use (default: gpt-4o-mini)")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    console = Console() if RICH_AVAILABLE else Console()
    client = MCPHttpClient(endpoint=args.endpoint)
    
    try:
        if args.command == "init":
            init_command(client, console)
        elif args.command == "tools":
            tools_command(client, console)
        elif args.command == "alerts":
            alerts_command(client, args.limit, console)
        elif args.command == "test":
            if args.test_command == "agents":
                test_agents_command(client, console)
            elif args.test_command == "risks":
                test_risks_command(client, args.limit, console)
            elif args.test_command == "connectivity":
                test_connectivity_command(client, console)
            else:
                test_parser.print_help()
        elif args.command == "hunt":
            hunt_command(client, args.openai_key, args.limit, args.model, console)
        else:
            parser.print_help()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[bold red]Unexpected error:[/bold red] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()


# ============================================================================
# Example Executions and Usage
# ============================================================================

"""
Example 1: Initialize MCP Session
---------------------------------
$ python wazuh_mcp_cli.py init

Output:
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ✓ MCP Session Initialized                                                   ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

Server Info:
{
  "protocolVersion": "2024-11-05",
  "serverInfo": {
    "name": "wazuh-mcp-server",
    "version": "1.0.0"
  },
  "capabilities": {
    "tools": {}
  }
}


Example 2: List Available Tools
--------------------------------
$ python wazuh_mcp_cli.py tools

Output:
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                        Available Wazuh MCP Tools                             ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Tool Name              │ Description              │ Input Schema            ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ get_wazuh_alert_summary│ Retrieve Wazuh alerts    │ {"limit": {"type":...} ┃
┃ list_wazuh_agents      │ List all Wazuh agents    │ {}                      ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛


Example 3: Retrieve Alerts
---------------------------
$ python wazuh_mcp_cli.py alerts --limit 5

Output:
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃              Wazuh Alerts (showing 5 of 5)                                  ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ ID  │ Level │ Agent      │ Rule ID │ Description          │ Timestamp        ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ 123 │ 7     │ agent-001  │ 1001    │ Unauthorized access  │ 2024-01-15T10:30 ┃
┃ 124 │ 5     │ agent-002  │ 1002    │ Suspicious login     │ 2024-01-15T10:31 ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛


Example 4: Test Agents
-----------------------
$ python wazuh_mcp_cli.py test agents

Output:
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                        Wazuh Agents Status                                  ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Agent ID │ Name      │ OS        │ Status                                  ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ 001      │ agent-001 │ Ubuntu    │ online                                  ┃
┃ 002      │ agent-002 │ CentOS    │ online                                  ┃
┃ 003      │ agent-003 │ Windows   │ offline                                 ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

Summary:
  Online Agents: 2
  Offline Agents: 1
  Total Agents: 3


Example 5: Test High-Risk Agents
---------------------------------
$ python wazuh_mcp_cli.py test risks --limit 100

Output:
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                      Top 5 High-Risk Agents                                 ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Rank │ Agent ID │ Name      │ Risk Score │ High-Level │ Total │ Reasons    ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ 1    │ 001      │ agent-001 │ 125.5      │ 8          │ 45    │ 8 high...  ┃
┃ 2    │ 002      │ agent-002 │ 98.2       │ 5          │ 32    │ 5 high...  ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

Detailed Analysis for Top Risk Agent (agent-001):
  Risk Score: 125.5
  High-Level Alerts: 8
  Total Alerts: 45
  Unique Rule Violations: 12
  MITRE ATT&CK Tactics: Initial Access, Execution, Persistence
  Reasons: 8 high-level alerts (>=7); 45 total alerts; 12 unique rule violations


Example 6: Threat Hunting with OpenAI
--------------------------------------
$ python wazuh_mcp_cli.py hunt --limit 50 --model gpt-4o-mini

Output:
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                    Threat Hunting Report                                    ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                                              ┃
┃ ## Executive Summary                                                         ┃
┃ Analysis of 50 Wazuh alerts identified 3 high-risk hosts requiring         ┃
┃ immediate attention...                                                      ┃
┃                                                                              ┃
┃ ## High-Risk Hosts                                                          ┃
┃ 1. agent-001 (ID: 001)                                                      ┃
┃    - 8 high-level alerts (level >= 7)                                       ┃
┃    - Potential lateral movement indicators                                   ┃
┃    - MITRE ATT&CK: T1021 (Remote Services)                                  ┃
┃                                                                              ┃
┃ ## Attack Chains                                                           ┃
┃ ...                                                                          ┃
┃                                                                              ┃
┃ ## Recommended Remediation Actions                                          ┃
┃ 1. Immediate: Isolate agent-001 for forensic analysis                       ┃
┃ 2. Short-term: Review authentication logs for agent-002                     ┃
┃ ...                                                                          ┃
┃                                                                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛


Future Extensions Suggestions:
------------------------------
1. IOC Scanning: Add command to scan alerts for known Indicators of Compromise
   - Hash-based IOC matching
   - IP address reputation checking
   - Domain name analysis

2. JA3 Fingerprint Analysis: Implement SSL/TLS fingerprint detection
   - Analyze network traffic alerts
   - Match against known malicious JA3 fingerprints
   - Detect botnet communication patterns

3. Lateral Movement Detection: Enhanced correlation engine
   - Track authentication patterns across hosts
   - Detect unusual SMB/RDP connections
   - Identify privilege escalation chains

4. Real-time Monitoring: Add streaming alert monitoring
   - WebSocket support for live alerts
   - Alert filtering and routing
   - Custom alert rules

5. Report Generation: Export threat hunting reports
   - PDF report generation
   - JSON/CSV export for SIEM integration
   - Automated email notifications

6. Agent Management: Extended agent operations
   - Remote agent configuration
   - Agent health monitoring
   - Automated remediation actions
"""

