# Author: Kaleb Austgen
# Date: 2/16/2026
# Description : Parses a MD file template, generates Neo4J nodes from this template, and pushes that to the graph database

import sys
from pathlib import Path
from llm_parser import parse_file
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
    
    print(f"Parsing markdown file: {markdown_file}")
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
        print(f"  CVEs: {', '.join(host['cves']) if host['cves'] else 'None'}")
        
        if host['applications']:
            print(f"\n  Applications ({len(host['applications'])}):")
            for app in host['applications']:
                cves = ', '.join(app['cves']) if app['cves'] else 'None'
                print(f"    - {app['name']} | CVEs: {cves}")
        
        if host['users']:
            print(f"\n  Users ({len(host['users'])}):")
            for user in host['users']:
                print(f"    - {user['username']} ({user['permission_level']})")
        
        if host['ports']:
            print(f"\n  Ports ({len(host['ports'])}):")
            for port in host['ports']:
                print(f"    - {port['number']}/{port['service']}")
        
        if host['nics']:
            print(f"\n  Network Interfaces ({len(host['nics'])}):")
            for nic in host['nics']:
                print(f"    - IP: {nic['ip']} | MAC: {nic['mac']}")
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
            
            print(f"\n✓ Successfully imported to Neo4j:")
            print(f"  - {stats['hosts']} Host(s)")
            print(f"  - {stats['applications']} Application(s)")
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
    
    return result


if __name__ == "__main__":
    main()
