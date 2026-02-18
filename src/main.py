# Author: Kaleb Austgen
# Date: 2/16/2026
# Description : Parses a MD file template, generates Neo4J nodes from this template, and pushes that to the graph database

import sys
from pathlib import Path
from llm_parser import parse_file, LLMParser
from neo4j_connector import create_connector_from_env

def main():
    """
    Main entry point for the application.
    Parse markdown file and extract Neo4j node structure.
    """
    if len(sys.argv) < 2:
        print("Usage: python main.py <path_to_markdown_file>")
        print("\nExample:")
        print("  python main.py notes/pentest.md")
        sys.exit(1)
    
    markdown_file = sys.argv[1]
    
    # Verify file exists
    if not Path(markdown_file).exists():
        print(f"Error: File not found: {markdown_file}")
        sys.exit(1)
    
    # Pre-flight service checks
    print("Checking service availability...")
    print("=" * 60)
    
    # Check Ollama connection
    parser = LLMParser()
    ollama_ok, ollama_msg = parser.test_connection()
    print(f"Ollama: {ollama_msg}")
    
    if not ollama_ok:
        print("\nCannot proceed without Ollama connection.")
        print("Please fix the issue above and try again.")
        sys.exit(1)
    
    # Check Neo4j connection
    try:
        neo4j = create_connector_from_env()
        neo4j_ok, neo4j_msg = neo4j.test_connection()
        print(f"Neo4j: {neo4j_msg}")
        
        if not neo4j_ok:
            print("\nCannot proceed without Neo4j connection.")
            print("Please fix the issue above and try again.")
            neo4j.close()
            sys.exit(1)
        
        neo4j.close()
    except Exception as e:
        print(f"Neo4j: Failed to initialize: {e}")
        print("\nCheck your .env file configuration.")
        sys.exit(1)
    
    print("\nAll services available. Starting parse...")
    print(f"\nParsing markdown file: {markdown_file}")
    print("=" * 60)
    
    # Parse the markdown file using local LLM
    result = parse_file(markdown_file)
    
    # Display results
    print(f"\nExtracted {len(result['hosts'])} host(s):\n")
    
    for i, host in enumerate(result['hosts'], 1):
        print(f"\n{'=' * 60}")
        print(f"Host #{i}: {host['name']}")
        print(f"{'=' * 60}")
        print(f"  OS: {host['os']}")
        if host.get('notes'):
            print(f"  Notes: {host['notes']}")
        
        if host['vulnerabilities']:
            print(f"\n  Host Vulnerabilities ({len(host['vulnerabilities'])}):")
            for vuln in host['vulnerabilities']:
                exploit_status = "✓ Exploitable" if vuln['exploitable'] else "✗ Not Exploitable"
                patch_status = "✓ Patched" if vuln['patched'] else "✗ Unpatched"
                print(f"    - {vuln['cve_id']} | Score: {vuln['severity_score']} | {exploit_status} | {patch_status}")
                if vuln.get('notes'):
                    print(f"      Notes: {vuln['notes']}")
        
        if host['ports']:
            print(f"\n  Open Ports ({len(host['ports'])}):")
            for port in host['ports']:
                print(f"    - Port {port['number']}/{port['protocol']}")
                for svc in port.get('services', []):
                    version_str = f" {svc['version']}" if svc['version'] else ""
                    print(f"      └─ Service: {svc['name']}{version_str}")
                    if svc.get('notes'):
                        print(f"         Notes: {svc['notes']}")
                    if svc.get('vulnerabilities'):
                        for vuln in svc['vulnerabilities']:
                            print(f"         └─ {vuln['cve_id']} (Score: {vuln['severity_score']})")
                    if svc.get('users'):
                        for user in svc['users']:
                            password_display = f" | Password: {user.get('password')}" if user.get('password') else ""
                            print(f"         └─ User: {user['username']} ({user['permission_level']}){password_display}")
        
        if host['services']:
            print(f"\n  Direct Services ({len(host['services'])}):")
            for svc in host['services']:
                version_str = f" {svc['version']}" if svc['version'] else ""
                print(f"    - {svc['name']}{version_str}")
                if svc.get('notes'):
                    print(f"      Notes: {svc['notes']}")
                if svc.get('users'):
                    for user in svc['users']:
                        password_display = f" | Password: {user.get('password')}" if user.get('password') else ""
                        print(f"      └─ User: {user['username']} ({user['permission_level']}){password_display}")
        
        if host['users']:
            print(f"\n  Users ({len(host['users'])}):")
            for user in host['users']:
                password_display = f" | Password: {user.get('password')}" if user.get('password') else ""
                print(f"    - {user['username']} ({user['permission_level']}){password_display}")
                # DEPRECATED: HAS_ACCESS relationship removed
                # if user.get('has_access_to'):
                #     print(f"      Has Access: {', '.join(user['has_access_to'])}")
        
        if host['nics']:
            print(f"\n  Network Interfaces ({len(host['nics'])}):")
            for nic in host['nics']:
                print(f"    - IP: {nic['ip']} | MAC: {nic['mac']}")
                if nic.get('connects_to'):
                    print(f"      Connects To: {', '.join(nic['connects_to'])}")
                print(f"      Connects to: {', '.join(nic['connects_to']) if nic['connects_to'] else 'None'}")
    
    print(f"\n{'=' * 60}")
    print("Parsing complete!")
    
    # Push to Neo4j
    print(f"\n{'=' * 60}")
    print("Pushing to Neo4j database...")
    print(f"{'=' * 60}")
    
    try:
        with create_connector_from_env() as neo4j:
            stats = neo4j.import_parsed_data(result)
            
            print(f"\nSuccessfully imported to Neo4j:")
            print(f"  - {stats['hosts']} Host(s)")
            print(f"  - {stats['vulnerabilities']} Vulnerability/Vulnerabilities")
            print(f"  - {stats['services']} Service(s)")
            print(f"  - {stats['users']} User(s)")
            print(f"  - {stats['ports']} Port(s)")
            print(f"  - {stats['nics']} NIC(s)")
            print(f"\n{'=' * 60}")
            print("Neo4j import complete!")
            print("View your graph at: http://localhost:7474")
    
    except Exception as e:
        print(f"\nError connecting to Neo4j: {e}")
        print("\nMake sure:")
        print("  1. Neo4j is running (bolt://localhost:7687)")
        print("  2. Credentials in .env file are correct")
        print("  3. Neo4j Python driver is installed: pip install neo4j")
        sys.exit(1)
    
    #print(result)
    return result


if __name__ == "__main__":
    main()
