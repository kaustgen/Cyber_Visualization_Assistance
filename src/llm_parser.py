# Author: Kaleb Austgen
# Date: 2/16/2026
# Description: LLM-based markdown parser that extracts Neo4j node structure from pentesting notes

import json
import requests
import os
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from dotenv import load_dotenv


@dataclass
class Vulnerability:
    cve_id: str
    severity_score: float = 0.0
    exploitable: bool = False
    patched: bool = False
    notes: str = ""


@dataclass
class User:
    username: str
    permission_level: str = "Unknown"
    source: str = ""  # hostname or service name
    has_access_to: List[str] = None  # List of service names
    
    def __post_init__(self):
        if self.has_access_to is None:
            self.has_access_to = []


@dataclass
class Service:
    name: str
    version: str = ""
    notes: str = ""
    vulnerabilities: List[Vulnerability] = None
    users: List[User] = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.users is None:
            self.users = []


@dataclass
class Port:
    number: int
    protocol: str = "TCP"
    services: List[Service] = None
    
    def __post_init__(self):
        if self.services is None:
            self.services = []


@dataclass
class NIC:
    mac: str = "Unknown"
    ip: str = "Unknown"
    connects_to: List[str] = None
    
    def __post_init__(self):
        if self.connects_to is None:
            self.connects_to = []


@dataclass
class Host:
    name: str
    os: str = "Unknown"
    notes: str = ""
    vulnerabilities: List[Vulnerability] = None
    ports: List[Port] = None
    services: List[Service] = None  # Direct host services
    users: List[User] = None
    nics: List[NIC] = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.ports is None:
            self.ports = []
        if self.services is None:
            self.services = []
        if self.users is None:
            self.users = []
        if self.nics is None:
            self.nics = []


class LLMParser:
    """
    Parses markdown files using a local LLM (Ollama) to extract Neo4j node structures.
    """
    
    def __init__(self, model: str = None, ollama_url: str = None):
        """
        Initialize the LLM parser.
        
        Args:
            model: The Ollama model to use (default: from .env or llama3)
            ollama_url: The URL of the local Ollama server (default: from .env or http://localhost:11434)
        """
        load_dotenv()
        self.model = model or os.getenv("LLM_MODEL", "llama3")
        self.ollama_url = ollama_url or os.getenv("LLM_OLLAMA_URL", "http://localhost:11434")
    
    def parse_markdown_file(self, file_path: str) -> Dict:
        """
        Parse a markdown file and extract Neo4j node structure.
        
        Args:
            file_path: Path to the markdown file
            
        Returns:
            Dictionary containing extracted hosts and their relationships
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return self.parse_markdown(content)
    
    def parse_markdown(self, content: str) -> Dict:
        """
        Parse markdown content and extract Neo4j node structure.
        
        Args:
            content: Markdown content string
            
        Returns:
            Dictionary containing extracted hosts and their relationships
        """
        prompt = self._build_extraction_prompt(content)
        
        try:
            response = self._call_ollama(prompt)
            parsed_data = self._extract_json_from_response(response)
            validated_data = self._validate_and_structure(parsed_data)
            return validated_data
        except Exception as e:
            print(f"Error parsing markdown: {e}")
            return {"hosts": []}
    
    def _build_extraction_prompt(self, content: str) -> str:
        """Build the prompt for the LLM to extract structured data."""
        return f"""You are a penetration testing note parser. Extract structured information from the markdown content below.

Extract the following information about hosts/machines on the network:
- Host/Machine names
- Operating Systems  
- Host-level Vulnerabilities (CVEs with severity scores, exploitability, patch status)
- Open Ports (with services running on them)
- Services (can run on ports OR directly on host)
- Service-level Vulnerabilities
- Users (at host level OR service level)
- User access relationships (Has Access to services)
- Network Interface Cards (with MAC addresses, IP addresses, and connections to other IPs)

CRITICAL PARSING RULES:
1. NEVER infer or make up any data - only extract what is explicitly mentioned
2. Service naming: "Port 443 - HTTPS (Apache 2.4.41)" means Service name="Apache", version="2.4.41", notes="Running over HTTPS"
3. Users nested under Services belong to that service (source="ServiceName")
4. Users at Host level belong to host (source="hostname")
5. Parse vulnerability attributes: severity_score (float), exploitable (bool), patched (bool) from markdown
6. "Has Access: ServiceName" means create has_access_to relationship

Return ONLY a valid JSON object in this exact format:
{{
  "hosts": [
    {{
      "name": "hostname",
      "os": "operating system",
      "notes": "host notes from Notes section",
      "vulnerabilities": [
        {{
          "cve_id": "CVE-XXXX-YYYY",
          "severity_score": 7.8,
          "exploitable": true,
          "patched": false,
          "notes": "vulnerability notes"
        }}
      ],
      "ports": [
        {{
          "number": 80,
          "protocol": "TCP",
          "services": [
            {{
              "name": "Apache",
              "version": "2.4.41",
              "notes": "service notes",
              "vulnerabilities": [
                {{
                  "cve_id": "CVE-2021-44790",
                  "severity_score": 6.5,
                  "exploitable": false,
                  "patched": false,
                  "notes": ""
                }}
              ],
              "users": [
                {{
                  "username": "service_user",
                  "permission_level": "admin",
                  "source": "Apache"
                }}
              ]
            }}
          ]
        }}
      ],
      "services": [
        {{
          "name": "cron",
          "version": "",
          "notes": "Direct host service",
          "vulnerabilities": [],
          "users": [
            {{
              "username": "cron_admin",
              "permission_level": "Administrator",
              "source": "cron"
            }}
          ]
        }}
      ],
      "users": [
        {{
          "username": "admin",
          "permission_level": "Administrator",
          "source": "hostname",
          "has_access_to": ["Apache", "MySQL"]
        }}
      ],
      "nics": [
        {{
          "mac": "00:00:00:00:00:00",
          "ip": "192.168.1.1",
          "connects_to": ["192.168.1.2"]
        }}
      ]
    }}
  ]
}}

Markdown content:
{content}

JSON output:"""
    
    def _call_ollama(self, prompt: str) -> str:
        """
        Call the local Ollama API.
        
        Args:
            prompt: The prompt to send to the LLM
            
        Returns:
            Response text from the LLM
        """
        url = f"{self.ollama_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }
        
        response = requests.post(url, json=payload, timeout=120)
        response.raise_for_status()
        
        result = response.json()
        return result.get("response", "")
    
    def _extract_json_from_response(self, response: str) -> Dict:
        """
        Extract JSON from LLM response, handling potential formatting issues.
        
        Args:
            response: Raw response from LLM
            
        Returns:
            Parsed JSON dictionary
        """
        # Try to parse the response as-is
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            # Try to find JSON in the response
            start = response.find('{')
            end = response.rfind('}') + 1
            if start != -1 and end > start:
                try:
                    return json.loads(response[start:end])
                except json.JSONDecodeError:
                    pass
        
        # If all else fails, return empty structure
        return {"hosts": []}
    
    def _validate_and_structure(self, data: Dict) -> Dict:
        """
        Validate and structure the parsed data into proper dataclasses.
        
        Args:
            data: Raw parsed data from LLM
            
        Returns:
            Validated and structured dictionary
        """
        if "hosts" not in data:
            return {"hosts": []}
        
        structured_hosts = []
        
        for host_data in data.get("hosts", []):
            host_name = host_data.get("name", "Unknown")
            
            # Parse host vulnerabilities
            host_vulns = []
            for vuln in host_data.get("vulnerabilities", []):
                severity = vuln.get("severity_score")
                host_vulns.append(Vulnerability(
                    cve_id=vuln.get("cve_id", "Unknown"),
                    severity_score=float(severity) if severity is not None else 0.0,
                    exploitable=bool(vuln.get("exploitable", False)),
                    patched=bool(vuln.get("patched", False)),
                    notes=vuln.get("notes", "")
                ))
            
            # Parse ports and their services
            ports = []
            for port_data in host_data.get("ports", []):
                port_services = []
                for svc_data in port_data.get("services", []):
                    # Parse service vulnerabilities
                    svc_vulns = []
                    for vuln in svc_data.get("vulnerabilities", []):
                        severity = vuln.get("severity_score")
                        svc_vulns.append(Vulnerability(
                            cve_id=vuln.get("cve_id", "Unknown"),
                            severity_score=float(severity) if severity is not None else 0.0,
                            exploitable=bool(vuln.get("exploitable", False)),
                            patched=bool(vuln.get("patched", False)),
                            notes=vuln.get("notes", "")
                        ))
                    
                    # Parse service users
                    svc_users = []
                    for user_data in svc_data.get("users", []):
                        svc_users.append(User(
                            username=user_data.get("username", "Unknown"),
                            permission_level=user_data.get("permission_level", "Unknown"),
                            source=user_data.get("source", svc_data.get("name", "Unknown"))
                        ))
                    
                    port_services.append(Service(
                        name=svc_data.get("name", "Unknown"),
                        version=svc_data.get("version", ""),
                        notes=svc_data.get("notes", ""),
                        vulnerabilities=svc_vulns,
                        users=svc_users
                    ))
                
                ports.append(Port(
                    number=int(port_data.get("number", 0)),
                    protocol=port_data.get("protocol", "TCP"),
                    services=port_services
                ))
            
            # Parse direct host services
            host_services = []
            for svc_data in host_data.get("services", []):
                # Parse service vulnerabilities
                svc_vulns = []
                for vuln in svc_data.get("vulnerabilities", []):
                    severity = vuln.get("severity_score")
                    svc_vulns.append(Vulnerability(
                        cve_id=vuln.get("cve_id", "Unknown"),
                        severity_score=float(severity) if severity is not None else 0.0,
                        exploitable=bool(vuln.get("exploitable", False)),
                        patched=bool(vuln.get("patched", False)),
                        notes=vuln.get("notes", "")
                    ))
                
                # Parse service users
                svc_users = []
                for user_data in svc_data.get("users", []):
                    svc_users.append(User(
                        username=user_data.get("username", "Unknown"),
                        permission_level=user_data.get("permission_level", "Unknown"),
                        source=user_data.get("source", svc_data.get("name", "Unknown"))
                    ))
                
                host_services.append(Service(
                    name=svc_data.get("name", "Unknown"),
                    version=svc_data.get("version", ""),
                    notes=svc_data.get("notes", ""),
                    vulnerabilities=svc_vulns,
                    users=svc_users
                ))
            
            # Parse host users
            host_users = []
            for user_data in host_data.get("users", []):
                host_users.append(User(
                    username=user_data.get("username", "Unknown"),
                    permission_level=user_data.get("permission_level", "Unknown"),
                    source=user_data.get("source", host_name),
                    has_access_to=user_data.get("has_access_to", [])
                ))
            
            # Parse NICs
            nics = []
            for nic in host_data.get("nics", []):
                nics.append(NIC(
                    mac=nic.get("mac", "Unknown"),
                    ip=nic.get("ip", "Unknown"),
                    connects_to=nic.get("connects_to", [])
                ))
            
            # Create host
            host = Host(
                name=host_name,
                os=host_data.get("os", "Unknown"),
                notes=host_data.get("notes", ""),
                vulnerabilities=host_vulns,
                ports=ports,
                services=host_services,
                users=host_users,
                nics=nics
            )
            
            structured_hosts.append(asdict(host))
        
        return {"hosts": structured_hosts}


def parse_file(file_path: str, model: str = None) -> Dict:
    """
    Convenience function to parse a markdown file.
    
    Args:
        file_path: Path to the markdown file
        model: Ollama model to use (default: from .env)
        
    Returns:
        Dictionary containing extracted hosts and their relationships
    """
    parser = LLMParser(model=model)
    return parser.parse_markdown_file(file_path)
