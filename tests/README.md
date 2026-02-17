# Test Suite Documentation

## Overview
Comprehensive test suite for the Cyber Visualization Assistance project. Tests ensure markdown parsing robustness and Neo4j graph creation correctness.

## Running Tests

### Run All Tests
```bash
pytest tests/ -v
```

### Run with Coverage
```bash
pytest tests/ --cov=src --cov-report=term-missing --cov-report=html
```

### Run Specific Test Classes
```bash
# Only markdown variations
pytest tests/test_llm_parser.py::TestMarkdownVariations -v

# Only Neo4j integration tests (requires Neo4j running)
pytest tests/ -m neo4j -v

# Only LLM integration test (requires Ollama running)
pytest tests/ -m integration -v

# Coverage with report
pytest tests/ --cov=src --cov-report=html
```

### Skip Slow Tests
```bash
pytest tests/ -v -m "not integration"
```

## Test Coverage

Current coverage: **61%**

- `llm_parser.py`: 85% (24 lines uncovered - mostly error handling)
- `neo4j_connector.py`: 76% (36 lines uncovered - mostly error handling)
- `main.py`: 0% (CLI not tested - manual testing required)

## Test Structure

### test_llm_parser.py
Tests for markdown parsing variations and LLM integration.

**TestMarkdownVariations** (6 tests)
- Different heading styles (##, ###, ####)
- Case-insensitive labels
- Optional vulnerability fields (missing scores, exploitable, patched)
- Services with/without version numbers
- Multiple users on one line
- Nested notes

**TestEdgeCases** (4 tests)
- Empty sections handling
- Duplicate host names
- Special characters in names
- Missing required fields

**TestNeo4jSchema** (3 tests)
- User source attribute uniqueness
- Vulnerability shared node format
- Port RUNS_SERVICE relationship

**Integration Test** (1 test, marked `@pytest.mark.integration`)
- Full pipeline with real Ollama LLM parsing

### test_neo4j_connector.py
Tests for Neo4j database operations with mock data.

**TestNeo4jConnector** (9 tests, all marked `@pytest.mark.neo4j`)
- `test_create_host`: Basic host creation
- `test_create_vulnerability_shared_node`: Vulnerabilities as shared nodes
- `test_import_full_structure`: Complete import pipeline
- `test_user_uniqueness_by_source`: User source attribute prevents duplication
- `test_has_access_relationship`: User HAS_ACCESS to Service
- `test_port_runs_service_relationship`: Port RUNS_SERVICE relationship
- `test_host_runs_service_directly`: Host RUNS_SERVICE (no port)
- `test_nic_connects_to_relationship`: NIC CONNECTS_TO NIC by IP
- `test_vulnerability_links_to_host_and_service`: Vulnerability shared across hosts/services

## Test Data

### tests/test_data/minimal_host.md
Basic host with minimal information for simple test cases.

### tests/test_data/complex_network.md
Complex multi-host network with:
- Multiple hosts with full vulnerability data
- Nested services on ports
- Direct host services
- User access relationships
- NIC connections between hosts

## Markers

Custom pytest markers defined in `pytest.ini`:

- `@pytest.mark.integration`: Tests requiring real LLM (Ollama). Slow (~30s each).
- `@pytest.mark.neo4j`: Tests requiring Neo4j database connection.

## Fixtures

Defined in `conftest.py`:

- `parser`: LLMParser instance for unit tests
- `test_data_dir`: Path to test data directory
- `setup_test_env`: Environment variable setup fixture
- `mock_parsed_data`: Complete mock parsed data structure
- `neo4j_connector`: Neo4j connector with database cleanup

## CI/CD Considerations

For CI pipelines:
1. Skip integration tests: `pytest tests/ -m "not integration"`
2. Mock Neo4j for neo4j-marked tests or run with test Neo4j instance
3. Coverage threshold: Currently 61%, aim for >70%

## Known Limitations

1. **LLM Variability**: Integration tests may have slight variations in LLM output
2. **No main.py Coverage**: CLI requires manual testing
3. **Error Path Coverage**: Some error handling paths untested (would require mocking failures)

## Future Improvements

- [ ] Add tests for error handling (connection failures, invalid JSON from LLM)
- [ ] Mock Ollama responses for faster integration tests
- [ ] Add CLI integration tests for main.py
- [ ] Increase coverage to >75%
- [ ] Add performance/benchmark tests for large markdown files
