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
class Application:
    name: str
    cves: List[str] = None
    
    def __post_init__(self):
        if self.cves is None:
            self.cves = []


@dataclass
class User:
    username: str
    permission_level: str = "Unknown"


@dataclass
class Port:
    number: int
    service: str = "Unknown"


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
    cves: List[str] = None
    applications: List[Application] = None
    users: List[User] = None
    ports: List[Port] = None
    nics: List[NIC] = None
    
    def __post_init__(self):
        if self.cves is None:
            self.cves = []
        if self.applications is None:
            self.applications = []
        if self.users is None:
            self.users = []
        if self.ports is None:
            self.ports = []
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
- CVEs (Common Vulnerabilities and Exposures)
- Applications running on each host (with their CVEs if mentioned)
- Users on each host (with their permission levels)
- Open ports (with their services)
- Network Interface Cards (with MAC addresses, IP addresses, and connections to other IPs)

CRITICAL: Only extract information that is explicitly mentioned in the notes. Do not infer or make up any data.

Return ONLY a valid JSON object in this exact format:
{{
  "hosts": [
    {{
      "name": "hostname",
      "os": "operating system",
      "cves": ["CVE-XXXX-YYYY"],
      "applications": [
        {{
          "name": "app name",
          "cves": ["CVE-XXXX-YYYY"]
        }}
      ],
      "users": [
        {{
          "username": "username",
          "permission_level": "admin/user/guest"
        }}
      ],
      "ports": [
        {{
          "number": 80,
          "service": "http"
        }}
      ],
      "nics": [
        {{
          "mac": "00:00:00:00:00:00",
          "ip": "192.168.1.1",
          "connects_to": ["192.168.1.2", "192.168.1.3"]
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
            # Parse applications
            apps = []
            for app in host_data.get("applications", []):
                apps.append(Application(
                    name=app.get("name", "Unknown"),
                    cves=app.get("cves", [])
                ))
            
            # Parse users
            users = []
            for user in host_data.get("users", []):
                users.append(User(
                    username=user.get("username", "Unknown"),
                    permission_level=user.get("permission_level", "Unknown")
                ))
            
            # Parse ports
            ports = []
            for port in host_data.get("ports", []):
                ports.append(Port(
                    number=int(port.get("number", 0)),
                    service=port.get("service", "Unknown")
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
                name=host_data.get("name", "Unknown"),
                os=host_data.get("os", "Unknown"),
                cves=host_data.get("cves", []),
                applications=apps,
                users=users,
                ports=ports,
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
