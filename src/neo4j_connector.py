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
    following the refined schema with HAS_*, RUNS_SERVICE, HAS_ACCESS, and CONNECTS_TO relationships.
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
    
    def test_connection(self) -> tuple[bool, str]:
        """
        Test Neo4j connection and authentication.
        
        Returns:
            (success: bool, message: str)
        """
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run("RETURN 1 as test")
                result.single()
                return True, "Neo4j connection successful"
        except Exception as e:
            error_msg = str(e).lower()
            
            if "authentication" in error_msg or "unauthorized" in error_msg:
                return False, f"Neo4j authentication failed. Check NEO4J_USERNAME and NEO4J_PASSWORD in .env file.\nError: {e}"
            elif "connection refused" in error_msg or "unable to connect" in error_msg:
                return False, f"Cannot connect to Neo4j at {self.driver._pool.address}. Is Neo4j running?\nError: {e}"
            elif "database" in error_msg:
                return False, f"Database '{self.database}' not found. Check NEO4J_DATABASE in .env file.\nError: {e}"
            else:
                return False, f"Neo4j connection error: {e}"
    
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
    
    def create_host(self, name: str, os: str = "Unknown", notes: str = "") -> Dict:
        """
        Create or update a Host node.
        
        Args:
            name: Host name (unique identifier)
            os: Operating system
            notes: Host notes
            
        Returns:
            Dictionary containing the created/updated host node
        """
        with self.driver.session(database=self.database) as session:
            result = session.run("""
                MERGE (h:Host {name: $name})
                SET h.os = $os, h.notes = $notes
                RETURN h
            """, name=name, os=os, notes=notes)
            
            record = result.single()
            if record:
                return dict(record["h"])
            return {}
    
    def create_vulnerability(self, cve_id: str, severity_score: float = 0.0, 
                           exploitable: bool = False, patched: bool = False, 
                           notes: str = "") -> Dict:
        """
        Create or update a Vulnerability node (shared across hosts/services).
        
        Args:
            cve_id: CVE identifier (unique)
            severity_score: CVSS score
            exploitable: Whether exploitable
            patched: Whether patched
            notes: Vulnerability notes
            
        Returns:
            Dictionary containing the created/updated vulnerability node
        """
        with self.driver.session(database=self.database) as session:
            result = session.run("""
                MERGE (v:Vulnerability {cve_id: $cve_id})
                SET v.severity_score = $severity_score, 
                    v.exploitable = $exploitable,
                    v.patched = $patched,
                    v.notes = $notes
                RETURN v
            """, cve_id=cve_id, severity_score=severity_score, 
                 exploitable=exploitable, patched=patched, notes=notes)
            
            record = result.single()
            if record:
                return dict(record["v"])
            return {}
    
    def link_vulnerability_to_host(self, host_name: str, cve_id: str):
        """Create HAS_VULNERABILITY relationship between Host and Vulnerability."""
        with self.driver.session(database=self.database) as session:
            session.run("""
                MATCH (h:Host {name: $host_name})
                MATCH (v:Vulnerability {cve_id: $cve_id})
                MERGE (h)-[:HAS_VULNERABILITY]->(v)
            """, host_name=host_name, cve_id=cve_id)
    
    def link_vulnerability_to_service(self, service_name: str, host_name: str, cve_id: str):
        """Create HAS_VULNERABILITY relationship between Service and Vulnerability."""
        with self.driver.session(database=self.database) as session:
            session.run("""
                MATCH (s:Service {name: $service_name, host: $host_name})
                MATCH (v:Vulnerability {cve_id: $cve_id})
                MERGE (s)-[:HAS_VULNERABILITY]->(v)
            """, service_name=service_name, host_name=host_name, cve_id=cve_id)
    
    def create_port(self, host_name: str, port_number: int, protocol: str = "TCP") -> Dict:
        """
        Create or update a Port node and link it to a Host via HAS_PORT.
        
        Args:
            host_name: Name of the host that has this port
            port_number: Port number
            protocol: Protocol (TCP/UDP)
            
        Returns:
            Dictionary containing the created/updated port node
        """
        with self.driver.session(database=self.database) as session:
            result = session.run("""
                MATCH (h:Host {name: $host_name})
                MERGE (p:Port {number: $port_number, host: $host_name})
                SET p.protocol = $protocol
                MERGE (h)-[:HAS_PORT]->(p)
                RETURN p
            """, host_name=host_name, port_number=port_number, protocol=protocol)
            
            record = result.single()
            if record:
                return dict(record["p"])
            return {}
    
    def create_service(self, host_name: str, service_name: str, version: str = "", 
                      notes: str = "", port_number: Optional[int] = None) -> Dict:
        """
        Create or update a Service node.
        
        Args:
            host_name: Name of the host
            service_name: Service name
            version: Service version
            notes: Service notes
            port_number: Optional port number (if service runs on a port)
            
        Returns:
            Dictionary containing the created/updated service node
        """
        with self.driver.session(database=self.database) as session:
            result = session.run("""
                MATCH (h:Host {name: $host_name})
                MERGE (s:Service {name: $service_name, host: $host_name})
                SET s.version = $version, s.notes = $notes
                RETURN s
            """, host_name=host_name, service_name=service_name, 
                 version=version, notes=notes)
            
            # Create relationship: Host -> Service or Port -> Service
            if port_number is not None:
                session.run("""
                    MATCH (p:Port {number: $port_number, host: $host_name})
                    MATCH (s:Service {name: $service_name, host: $host_name})
                    MERGE (p)-[:RUNS_SERVICE]->(s)
                """, port_number=port_number, host_name=host_name, service_name=service_name)
            else:
                session.run("""
                    MATCH (h:Host {name: $host_name})
                    MATCH (s:Service {name: $service_name, host: $host_name})
                    MERGE (h)-[:RUNS_SERVICE]->(s)
                """, host_name=host_name, service_name=service_name)
            
            record = result.single()
            if record:
                return dict(record["s"])
            return {}
    
    def create_user(self, username: str, source: str, permission_level: str = "Unknown", password: str = "") -> Dict:
        """
        Create or update a User node.
        
        Args:
            username: Username
            source: Source (hostname or service name)
            permission_level: User's permission level
            password: User's password if discovered
            
        Returns:
            Dictionary containing the created/updated user node
        """
        with self.driver.session(database=self.database) as session:
            result = session.run("""
                MERGE (u:User {username: $username, source: $source})
                SET u.permission_level = $permission_level,
                    u.password = $password
                RETURN u
            """, username=username, source=source, permission_level=permission_level, password=password)
            
            record = result.single()
            if record:
                return dict(record["u"])
            return {}
    
    def link_user_to_host(self, username: str, source: str, host_name: str):
        """Create HAS_USER relationship between Host and User."""
        with self.driver.session(database=self.database) as session:
            session.run("""
                MATCH (h:Host {name: $host_name})
                MATCH (u:User {username: $username, source: $source})
                MERGE (h)-[:HAS_USER]->(u)
            """, host_name=host_name, username=username, source=source)
    
    def link_user_to_service(self, username: str, source: str, service_name: str, host_name: str):
        """Create HAS_USER relationship between Service and User."""
        with self.driver.session(database=self.database) as session:
            session.run("""
                MATCH (s:Service {name: $service_name, host: $host_name})
                MATCH (u:User {username: $username, source: $source})
                MERGE (s)-[:HAS_USER]->(u)
            """, service_name=service_name, host_name=host_name, username=username, source=source)
    
    # DEPRECATED: HAS_ACCESS relationship removed from schema
    # def link_user_access_to_service(self, username: str, source: str, service_name: str, host_name: str):
    #     """Create HAS_ACCESS relationship between User and Service."""
    #     with self.driver.session(database=self.database) as session:
    #         session.run("""
    #             MATCH (u:User {username: $username, source: $source})
    #             MATCH (s:Service {name: $service_name, host: $host_name})
    #             MERGE (u)-[:HAS_ACCESS]->(s)
    #         """, username=username, source=source, service_name=service_name, host_name=host_name)
    
    def create_nic(self, host_name: str, ip: str = "Unknown", mac: str = "Unknown") -> Dict:
        """
        Create or update a NIC (Network Interface Card) node and link it to a Host via HAS_NIC.
        IP is the primary key (often discovered first via netstat), MAC is an optional attribute.
        Uses host as source for uniqueness when multiple NICs have same IP.
        
        Args:
            host_name: Name of the host that has this NIC (source for uniqueness)
            ip: IP address (primary key - discovered via netstat/connections)
            mac: MAC address (optional attribute - discovered later)
            
        Returns:
            Dictionary containing the created/updated NIC node
        """
        with self.driver.session(database=self.database) as session:
            result = session.run("""
                MATCH (h:Host {name: $host_name})
                MERGE (n:NIC {ip: $ip})
                SET n.mac = $mac
                MERGE (h)-[:HAS_NIC]->(n)
                RETURN n
            """, host_name=host_name, ip=ip, mac=mac)
            
            record = result.single()
            if record:
                return dict(record["n"])
            return {}
    
    def create_nic_connection(self, source_ip: str, target_ip: str) -> bool:
        """
        Create a CONNECTS_TO relationship between two NICs.
        Creates the target NIC if it doesn't exist yet (for network enumeration visibility).
        
        Args:
            source_ip: IP address of the source NIC
            target_ip: IP address of the target NIC
            
        Returns:
            True if connection was created, False otherwise
        """
        with self.driver.session(database=self.database) as session:
            result = session.run("""
                MATCH (n1:NIC {ip: $source_ip})
                MERGE (n2:NIC {ip: $target_ip})
                ON CREATE SET n2.mac = "Unknown", n2.host = "Unknown"
                MERGE (n1)-[:CONNECTS_TO]->(n2)
                RETURN n1, n2
            """, source_ip=source_ip, target_ip=target_ip)
            
            return result.single() is not None
    
    def import_parsed_data(self, parsed_data: Dict) -> Dict:
        """
        Import parsed data from LLM into Neo4j database.
        Creates all hosts and their related nodes with proper relationships.
        
        Args:
            parsed_data: Dictionary containing hosts and their attributes from LLM parser
            
        Returns:
            Dictionary with statistics about imported data
        """
        stats = {
            "hosts": 0,
            "vulnerabilities": 0,
            "services": 0,
            "users": 0,
            "ports": 0,
            "nics": 0
        }
        
        for host_data in parsed_data.get("hosts", []):
            host_name = host_data.get("name", "Unknown")
            
            # Create host node
            self.create_host(
                name=host_name,
                os=host_data.get("os", "Unknown"),
                notes=host_data.get("notes", "")
            )
            stats["hosts"] += 1
            
            # Create host vulnerabilities
            for vuln in host_data.get("vulnerabilities", []):
                self.create_vulnerability(
                    cve_id=vuln.get("cve_id", "Unknown"),
                    severity_score=float(vuln.get("severity_score", 0.0)),
                    exploitable=bool(vuln.get("exploitable", False)),
                    patched=bool(vuln.get("patched", False)),
                    notes=vuln.get("notes", "")
                )
                self.link_vulnerability_to_host(host_name, vuln.get("cve_id", "Unknown"))
                stats["vulnerabilities"] += 1
            
            # Create ports and their services
            for port_data in host_data.get("ports", []):
                port_number = int(port_data.get("number", 0))
                self.create_port(
                    host_name=host_name,
                    port_number=port_number,
                    protocol=port_data.get("protocol", "TCP")
                )
                stats["ports"] += 1
                
                # Create services on this port
                for svc_data in port_data.get("services", []):
                    service_name = svc_data.get("name", "Unknown")
                    self.create_service(
                        host_name=host_name,
                        service_name=service_name,
                        version=svc_data.get("version", ""),
                        notes=svc_data.get("notes", ""),
                        port_number=port_number
                    )
                    stats["services"] += 1
                    
                    # Create service vulnerabilities
                    for vuln in svc_data.get("vulnerabilities", []):
                        self.create_vulnerability(
                            cve_id=vuln.get("cve_id", "Unknown"),
                            severity_score=float(vuln.get("severity_score", 0.0)),
                            exploitable=bool(vuln.get("exploitable", False)),
                            patched=bool(vuln.get("patched", False)),
                            notes=vuln.get("notes", "")
                        )
                        self.link_vulnerability_to_service(service_name, host_name, vuln.get("cve_id", "Unknown"))
                        stats["vulnerabilities"] += 1
                    
                    # Create service users
                    for user_data in svc_data.get("users", []):
                        username = user_data.get("username", "Unknown")
                        source = user_data.get("source", service_name)
                        self.create_user(
                            username=username,
                            source=source,
                            permission_level=user_data.get("permission_level", "Unknown"),
                            password=user_data.get("password", "")
                        )
                        self.link_user_to_service(username, source, service_name, host_name)
                        stats["users"] += 1
            
            # Create direct host services
            for svc_data in host_data.get("services", []):
                service_name = svc_data.get("name", "Unknown")
                self.create_service(
                    host_name=host_name,
                    service_name=service_name,
                    version=svc_data.get("version", ""),
                    notes=svc_data.get("notes", ""),
                    port_number=None  # Direct host service
                )
                stats["services"] += 1
                
                # Create service vulnerabilities
                for vuln in svc_data.get("vulnerabilities", []):
                    self.create_vulnerability(
                        cve_id=vuln.get("cve_id", "Unknown"),
                        severity_score=float(vuln.get("severity_score", 0.0)),
                        exploitable=bool(vuln.get("exploitable", False)),
                        patched=bool(vuln.get("patched", False)),
                        notes=vuln.get("notes", "")
                    )
                    self.link_vulnerability_to_service(service_name, host_name, vuln.get("cve_id", "Unknown"))
                    stats["vulnerabilities"] += 1
                
                # Create service users
                for user_data in svc_data.get("users", []):
                    username = user_data.get("username", "Unknown")
                    source = user_data.get("source", service_name)
                    self.create_user(
                        username=username,
                        source=source,
                        permission_level=user_data.get("permission_level", "Unknown"),
                        password=user_data.get("password", "")
                    )
                    self.link_user_to_service(username, source, service_name, host_name)
                    stats["users"] += 1
            
            # Create host users
            for user_data in host_data.get("users", []):
                username = user_data.get("username", "Unknown")
                source = user_data.get("source", host_name)
                self.create_user(
                    username=username,
                    source=source,
                    permission_level=user_data.get("permission_level", "Unknown"),
                    password=user_data.get("password", "")
                )
                self.link_user_to_host(username, source, host_name)
                stats["users"] += 1
                
                # DEPRECATED: HAS_ACCESS relationship removed
                # Create HAS_ACCESS relationships
                # for service_name in user_data.get("has_access_to", []):
                #     self.link_user_access_to_service(username, source, service_name, host_name)
            
            # Create NIC nodes
            for nic in host_data.get("nics", []):
                self.create_nic(
                    host_name=host_name,
                    ip=nic.get("ip", "Unknown"),
                    mac=nic.get("mac", "Unknown")
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
    
    def list_all_hosts(self) -> List[str]:
        """
        Get a list of all host names in the database.
        
        Returns:
            List of host names
        """
        with self.driver.session(database=self.database) as session:
            result = session.run("MATCH (h:Host) RETURN h.name as name ORDER BY name")
            return [record["name"] for record in result]


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
