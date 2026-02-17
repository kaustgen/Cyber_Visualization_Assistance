# Author: Kaleb Austgen
# Date: 2/16/2026
# Description: Pytest configuration and shared fixtures

import pytest
import os
from pathlib import Path

# Add project root to Python path
import sys
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "src"))


def pytest_configure(config):
    """Register custom markers"""
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests (slow, requires LLM/Neo4j)"
    )
    config.addinivalue_line(
        "markers", "neo4j: marks tests that require Neo4j connection"
    )


@pytest.fixture(scope="session")
def test_data_dir():
    """Get test data directory"""
    return Path(__file__).parent / "test_data"


@pytest.fixture(autouse=True)
def setup_test_env(monkeypatch):
    """Set up test environment variables"""
    # Use test Neo4j database if available
    monkeypatch.setenv("NEO4J_DATABASE", "neo4j")
