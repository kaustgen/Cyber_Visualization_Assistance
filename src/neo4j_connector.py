# Author: Kaleb Austgen
# Date: 2/16/2026
# Description: Neo4j database connector for creating and managing pentesting note graph structure

from neo4j import GraphDatabase
from typing import Dict, List, Optional
import os
from dotenv import load_dotenv


class Neo4jConnector:
    """
    Manages connections to Neo4j and provides methods to create/update/delete nodes
    following the HAS_* relationship pattern.
    """
    
    def __init__(self, uri: str, username: str, password: str, database: str = "neo4j"):
        """
        Initialize Neo4j connection.
        
        Args:
            uri: Neo4j connection URI (e.g., bolt://localhost:7687)
            username: Neo4j username
            password: Neo4j password
            database: Database name (default: neo4j)
        """
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
        self.database = database
    
    def close(self):
        """Close the Neo4j driver connection."""
        if self.driver:
            self.driver.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
    
    def clear_database(self):
        """
        Clear all nodes and relationships from the database.
        WARNING: This deletes all data!
        """
        with self.driver.session(database=self.database) as session:
            session.run("MATCH (n) DETACH DELETE n")
            print("Database cleared.")
    
    def create_host(self, name: str, os: str = "Unknown", cves: List[str] = None) -> Dict:
        """
        Create or update a Host node.
        
        Args:
            name: Host name (unique identifier)
            os: Operating system
            cves: List of CVE identifiers
            
        Returns:
            Dictionary containing the created/updated host node
        """
        if cves is None:
            cves = []
        
        with self.driver.session(database=self.database) as session:
            result = session.run("""
                MERGE (h:Host {name: $name})
                SET h.os = $os, h.cves = $cves
                RETURN h
            """, name=name, os=os, cves=cves)
            
            record = result.single()
            if record:
                return dict(record["h"])
            return {}
    
    def create_application(self, host_name: str, app_name: str, cves: List[str] = None) -> Dict:
        """
        Create or update an Application node and link it to a Host via HAS_APPLICATION.
        
        Args:
            host_name: Name of the host that has this application
            app_name: Application name
            cves: List of CVE identifiers for the application
            
        Returns:
            Dictionary containing the created/updated application node
        """
        if cves is None:
            cves = []
        
        with self.driver.session(database=self.database) as session:
            result = session.run("""
                MATCH (h:Host {name: $host_name})
                MERGE (a:Application {name: $app_name, host: $host_name})
                SET a.cves = $cves
                MERGE (h)-[:HAS_APPLICATION]->(a)
                RETURN a
            """, host_name=host_name, app_name=app_name, cves=cves)
            
            record = result.single()
            if record:
                return dict(record["a"])
            return {}
    
    def create_user(self, host_name: str, username: str, permission_level: str = "Unknown") -> Dict:
        """
        Create or update a User node and link it to a Host via HAS_USER.
        
        Args:
            host_name: Name of the host that has this user
            username: Username
            permission_level: User's permission level (e.g., admin, user, guest)
            
        Returns:
            Dictionary containing the created/updated user node
        """
        with self.driver.session(database=self.database) as session:
            result = session.run("""
                MATCH (h:Host {name: $host_name})
                MERGE (u:User {username: $username, host: $host_name})
                SET u.permission_level = $permission_level
                MERGE (h)-[:HAS_USER]->(u)
                RETURN u
            """, host_name=host_name, username=username, permission_level=permission_level)
            
            record = result.single()
            if record:
                return dict(record["u"])
            return {}
    
    def create_port(self, host_name: str, port_number: int, service: str = "Unknown") -> Dict:
        """
        Create or update a Port node and link it to a Host via HAS_PORT.
        
        Args:
            host_name: Name of the host that has this port
            port_number: Port number
            service: Service running on the port
            
        Returns:
            Dictionary containing the created/updated port node
        """
        with self.driver.session(database=self.database) as session:
            result = session.run("""
                MATCH (h:Host {name: $host_name})
                MERGE (p:Port {number: $port_number, host: $host_name})
                SET p.service = $service
                MERGE (h)-[:HAS_PORT]->(p)
                RETURN p
            """, host_name=host_name, port_number=port_number, service=service)
            
            record = result.single()
            if record:
                return dict(record["p"])
            return {}
    
    def create_nic(self, host_name: str, mac: str = "Unknown", ip: str = "Unknown", connects_to: List[str] = None) -> Dict:
        """
        Create or update a NIC (Network Interface Card) node and link it to a Host via HAS_NIC.
        
        Args:
            host_name: Name of the host that has this NIC
            mac: MAC address
            ip: IP address
            connects_to: List of IP addresses this NIC connects to
            
        Returns:
            Dictionary containing the created/updated NIC node
        """
        if connects_to is None:
            connects_to = []
        
        with self.driver.session(database=self.database) as session:
            result = session.run("""
                MATCH (h:Host {name: $host_name})
                MERGE (n:NIC {mac: $mac, ip: $ip, host: $host_name})
                SET n.connects_to = $connects_to
                MERGE (h)-[:HAS_NIC]->(n)
                RETURN n
            """, host_name=host_name, mac=mac, ip=ip, connects_to=connects_to)
            
            record = result.single()
            if record:
                return dict(record["n"])
            return {}
    
    def create_nic_connection(self, source_ip: str, target_ip: str) -> bool:
        """
        Create a CONNECTS_TO relationship between two NICs.
        
        Args:
            source_ip: IP address of the source NIC
            target_ip: IP address of the target NIC
            
        Returns:
            True if connection was created, False otherwise
        """
        with self.driver.session(database=self.database) as session:
            result = session.run("""
                MATCH (n1:NIC {ip: $source_ip})
                MATCH (n2:NIC {ip: $target_ip})
                MERGE (n1)-[:CONNECTS_TO]->(n2)
                RETURN n1, n2
            """, source_ip=source_ip, target_ip=target_ip)
            
            return result.single() is not None
    
    def import_parsed_data(self, parsed_data: Dict) -> Dict:
        """
        Import parsed data from LLM into Neo4j database.
        Creates all hosts and their related nodes with proper HAS_* relationships.
        
        Args:
            parsed_data: Dictionary containing hosts and their attributes from LLM parser
            
        Returns:
            Dictionary with statistics about imported data
        """
        stats = {
            "hosts": 0,
            "applications": 0,
            "users": 0,
            "ports": 0,
            "nics": 0
        }
        
        for host_data in parsed_data.get("hosts", []):
            # Create host node
            host_name = host_data.get("name", "Unknown")
            self.create_host(
                name=host_name,
                os=host_data.get("os", "Unknown"),
                cves=host_data.get("cves", [])
            )
            stats["hosts"] += 1
            
            # Create application nodes
            for app in host_data.get("applications", []):
                self.create_application(
                    host_name=host_name,
                    app_name=app.get("name", "Unknown"),
                    cves=app.get("cves", [])
                )
                stats["applications"] += 1
            
            # Create user nodes
            for user in host_data.get("users", []):
                self.create_user(
                    host_name=host_name,
                    username=user.get("username", "Unknown"),
                    permission_level=user.get("permission_level", "Unknown")
                )
                stats["users"] += 1
            
            # Create port nodes
            for port in host_data.get("ports", []):
                self.create_port(
                    host_name=host_name,
                    port_number=port.get("number", 0),
                    service=port.get("service", "Unknown")
                )
                stats["ports"] += 1
            
            # Create NIC nodes
            for nic in host_data.get("nics", []):
                self.create_nic(
                    host_name=host_name,
                    mac=nic.get("mac", "Unknown"),
                    ip=nic.get("ip", "Unknown"),
                    connects_to=nic.get("connects_to", [])
                )
                stats["nics"] += 1
        
        # Create CONNECTS_TO relationships between NICs
        for host_data in parsed_data.get("hosts", []):
            for nic in host_data.get("nics", []):
                source_ip = nic.get("ip", "Unknown")
                for target_ip in nic.get("connects_to", []):
                    if source_ip != "Unknown" and target_ip:
                        self.create_nic_connection(source_ip, target_ip)
        
        return stats
    
    def get_host(self, name: str) -> Optional[Dict]:
        """
        Retrieve a host and all its connected nodes.
        
        Args:
            name: Host name
            
        Returns:
            Dictionary containing host and all connected nodes, or None if not found
        """
        with self.driver.session(database=self.database) as session:
            result = session.run("""
                MATCH (h:Host {name: $name})
                OPTIONAL MATCH (h)-[:HAS_APPLICATION]->(app)
                OPTIONAL MATCH (h)-[:HAS_USER]->(user)
                OPTIONAL MATCH (h)-[:HAS_PORT]->(port)
                OPTIONAL MATCH (h)-[:HAS_NIC]->(nic)
                RETURN h, 
                       collect(DISTINCT app) as applications,
                       collect(DISTINCT user) as users,
                       collect(DISTINCT port) as ports,
                       collect(DISTINCT nic) as nics
            """, name=name)
            
            record = result.single()
            if record and record["h"]:
                return {
                    "host": dict(record["h"]),
                    "applications": [dict(a) for a in record["applications"] if a],
                    "users": [dict(u) for u in record["users"] if u],
                    "ports": [dict(p) for p in record["ports"] if p],
                    "nics": [dict(n) for n in record["nics"] if n]
                }
            return None
    
    def list_all_hosts(self) -> List[str]:
        """
        Get a list of all host names in the database.
        
        Returns:
            List of host names
        """
        with self.driver.session(database=self.database) as session:
            result = session.run("MATCH (h:Host) RETURN h.name as name ORDER BY name")
            return [record["name"] for record in result]
    
    def delete_host(self, name: str, cascade: bool = True):
        """
        Delete a host from the database.
        
        Args:
            name: Host name to delete
            cascade: If True, also delete all connected nodes (default: True)
        """
        with self.driver.session(database=self.database) as session:
            if cascade:
                # Delete host and all connected nodes
                session.run("""
                    MATCH (h:Host {name: $name})
                    DETACH DELETE h
                """, name=name)
            else:
                # Only delete host, leave orphaned nodes
                session.run("""
                    MATCH (h:Host {name: $name})
                    DELETE h
                """, name=name)
            print(f"Host '{name}' deleted (cascade={cascade}).")


def load_env_config() -> Dict:
    """
    Load Neo4j configuration from .env file.
    
    Returns:
        Configuration dictionary
    """
    load_dotenv()
    
    return {
        "uri": os.getenv("NEO4J_URL", "bolt://localhost:7687"),
        "username": os.getenv("NEO4J_USERNAME", "neo4j"),
        "password": os.getenv("NEO4J_PASSWORD", "password"),
        "database": os.getenv("NEO4J_DATABASE", "neo4j")
    }


def create_connector_from_env() -> Neo4jConnector:
    """
    Create a Neo4j connector from .env file configuration.
    
    Returns:
        Configured Neo4jConnector instance
    """
    config = load_env_config()
    
    return Neo4jConnector(
        uri=config["uri"],
        username=config["username"],
        password=config["password"],
        database=config["database"]
    )
