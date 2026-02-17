# Cyber Visualization Assistance - AI Agent Instructions

## Project Purpose
A local Neo4j-powered penetration testing note visualization system. Ingests markdown files from Obsidian, uses LLM to parse pentesting notes, and automatically generates Neo4j graph nodes. **Critical**: Never invent data - only structure what the user provides. Enable precise node editing without cascading changes.

## Architecture Overview

### Data Flow
1. Obsidian plugin → Markdown template → Python application
2. Python ingests `.md` → LLM parses structure → Neo4j graph generation
3. User queries Neo4j for pentesting reconnaissance visualization

### Tech Stack
- **Database**: Neo4j Community Edition
- **LLM**: Local Model
- **Testing**: pytest
- **environment**: Python 3 with env

### Neo4j Graph Schema
Use proper Neo4j relationship syntax with `HAS_*`, `RUNS_SERVICE`, and connection patterns:

**Node Hierarchy:**
```cypher
(Host {name: string, os: string, notes: string})
  -[:HAS_VULNERABILITY]-> (Vulnerability {cve_id: string, severity_score: float, exploitable: bool, patched: bool, notes: string})
  -[:HAS_PORT]-> (Port {number: int, protocol: string})
    -[:RUNS_SERVICE]-> (Service {name: string, version: string, notes: string})
      -[:HAS_VULNERABILITY]-> (Vulnerability)
      -[:HAS_USER]-> (User {username: string, permission_level: string, source: string})
  -[:RUNS_SERVICE]-> (Service)  // Direct host services (no port)
  -[:HAS_USER]-> (User {username: string, permission_level: string, source: string})
    -[:HAS_ACCESS]-> (Service)
  -[:HAS_NIC]-> (NIC {ip: string, mac: string})
    -[:CONNECTS_TO]-> (NIC)
```

**Key Constraints:**
- Host nodes are top-level entities (machines/devices on network)
- Vulnerabilities are shared nodes - multiple hosts/services can link to same CVE
- Services can run on Ports or directly on Hosts
- Users are uniquely identified by username + source (e.g., "web-server-01" or "MySQL")
- User source attribute prevents duplication across hosts and services
- Relationships: `HAS_VULNERABILITY`, `HAS_USER`, `HAS_PORT`, `HAS_NIC`, `RUNS_SERVICE`, `HAS_ACCESS`, `CONNECTS_TO`
- **NEVER infer relationships** - only create what is explicitly in markdown

## Development Workflows

### Python Virtual Environment (Windows)
```bash
# Setup (one-time)
python3 -m venv venv/

# Activate (every session)
.\venv\Scripts\activate

# End of session - ALWAYS update requirements
pip freeze > requirements.txt
```
### Testing with pytest
```bash
# Activate venv first!
.\venv\Scripts\activate

# Run all tests
pytest

# Run specific test file
pytest tests/test_parser.py

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=src tests/
```

### Neo4j Local Setup
- Community Edition running locally
- Connection details in `.env` file
- Use `neo4j` Python driver for all database operations
- Example `.env` format:
  ```
  NEO4J_URL=bolt://localhost:7687
  NEO4J_USERNAME=neo4j
  NEO4J_PASSWORD=your_password 

#### Services, Users, Ports, NICs, and Vulnerabilities Clarifications:
- Extract attributes without inference (OS, CVEs, permission levels, service versions, MAC/IP)
- Parse nested structures: Services under Ports, Users under Services, Vulnerabilities under multiple levels
- Service naming: "Port 443 - HTTPS (Apache 2.4.41)" → Service name="Apache", version="2.4.41", notes="Running over HTTPS"
- User source tracking: Host-level users get source="hostname", Service-level users get source="ServiceName"
- Vulnerability attributes: Parse severity_score from markdown if present, default 0.0
  LLM_MODEL=llama3
  LLM_OLLAMA_URL=http://localhost:11434

## Code Patterns

### Local LLM Integration
- Parse markdown to identify: Hosts, Applications, Users, Ports, NICs
- Extract attributes without inference (OS, CVEs, permission levels, services, MAC/IP)
- Output structured format matching Neo4j schema above

### Neo4j Operations (Cypher)
```python
# Pattern: Use MERGE for idempotent operations
session.run("""
    MERGE (m:Machine {name: $name})
    SET m.os = $os, m.cves = $cves
    RETURN m
""", name=machine_name, os=os_value, cves=cve_list)

# Pattern: Create relationships with MERGE on both ends
session.run("""
    MATCH (m:Machine {name: $machine_name})
    MERGE (a:Application {name: $app_name})
    SET a.cves = $cves
    MERGE (m)-[:HAS_APPLICATION]->(a)
    RETURN m, a
""", machine_name=machine_name, app_name=app_name, cves=cve_list)
```

### Testing Patterns
```python
# Use pytest fixtures for Neo4j test database
@pytest.fixture
def neo4j_session():
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "test"))
    session = driver.session()
    yield session
    # Cleanup after test
    session.run("MATCH (n) DETACH DELETE n")
    session.close()

# Test LLM parsing output structure
def test_parse_markdown_returns_valid_schema(sample_markdown):
    result = parse_markdown(sample_markdown)
    assert "machines" in result
    assert isinstance(result["machines"], list)
```

**Always:**
- Use parameterized queries (never string concatenation)
- Return created/modified nodes for verification
- Use `MERGE` instead of `CREATE` to avoid duplicates
- Match existing nodes before creating relationships

## Critical Development Principles

### Data Integrity First
When modifying Neo4j operations, ensure:
- No hallucinated nodes or relationships
- Edit operations are atomic (one node/relationship at a time)
- Delete operations don't cascade unintentionally
- User data is preserved exactly as provided in markdown

### Local-First Architecture
- Never assume internet connectivity
- All processing happens locally (LLM, database, parsing)
- No telemetry or external API calls
- Configuration files for local paths/ports only

## Project Structure
```
/src          - Main application code
/tests        - pytest test suite
/venv         - Virtual environment (never commit)
requirements.txt - Python dependencies (update every session!)
AGENTS.md - Key agent instructions

**NEVER infer relationships or data** - only extract what is explicitly in markdown
- Don't create duplicate User nodes - use source attribute to differentiate
- Don't create duplicate Vulnerability nodes - CVEs are shared across hosts/services
- Don't assume Service-User relationships - only create if nested in markdown
- Don't use generic relationship names - use schema patterns: `HAS_*`, `RUNS_SERVICE`, `HAS_ACCESS`, `CONNECTS_TO`

## Common Pitfalls to Avoid
- Don't create relationships between Application, User, Port nodes directly
- Don't infer missing data from context - flag it for user input
- Don't use generic relationship names - stick to `HAS_*` convention
- Don't forget to activate venv before running Python code or tests
- Don't hardcode Neo4j credentials - use `.env` file
- Don't call external APIs - everything must work offline
- Don't commit `venv/` or `.env` files to git

## Key Files
- `AGENTS.md` - Complete project specification (reference for schema updates)
- `requirements.txt` - Python dependencies (update end of every session)
- `venv/` - Virtual environment (never commit)