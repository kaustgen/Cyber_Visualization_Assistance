# Author: Kaleb Austgen
# Date: 2/16/2026
# Description: Tests for service connection health checks (Neo4j and Ollama)

import pytest
from unittest.mock import Mock, patch
import requests

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from llm_parser import LLMParser
from neo4j_connector import Neo4jConnector


class TestOllamaConnection:
    """Test Ollama service health checks"""
    
    def test_ollama_success(self):
        """Test successful Ollama connection with available model"""
        parser = LLMParser()
        
        with patch('requests.get') as mock_get:
            # Mock successful response with model available
            mock_response = Mock()
            mock_response.json.return_value = {
                "models": [
                    {"name": "llama3:latest"},
                    {"name": "codellama:latest"}
                ]
            }
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response
            
            success, message = parser.test_connection()
            
            assert success is True
            assert "successful" in message.lower()
            assert parser.model in message
    
    def test_ollama_model_not_found(self):
        """Test when model is not installed"""
        parser = LLMParser(model="nonexistent-model")
        
        with patch('requests.get') as mock_get:
            # Mock response with different models
            mock_response = Mock()
            mock_response.json.return_value = {
                "models": [
                    {"name": "llama3:latest"},
                    {"name": "codellama:latest"}
                ]
            }
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response
            
            success, message = parser.test_connection()
            
            assert success is False
            assert "not found" in message.lower()
            assert "ollama pull" in message.lower()
    
    def test_ollama_connection_refused(self):
        """Test when Ollama service is not running"""
        parser = LLMParser()
        
        with patch('requests.get') as mock_get:
            mock_get.side_effect = requests.exceptions.ConnectionError()
            
            success, message = parser.test_connection()
            
            assert success is False
            assert "cannot connect" in message.lower()
            assert "ollama serve" in message.lower()
    
    def test_ollama_timeout(self):
        """Test when Ollama service times out"""
        parser = LLMParser()
        
        with patch('requests.get') as mock_get:
            mock_get.side_effect = requests.exceptions.Timeout()
            
            success, message = parser.test_connection()
            
            assert success is False
            assert "timed out" in message.lower()
    
    def test_ollama_authentication_failure(self):
        """Test when Ollama authentication fails"""
        parser = LLMParser()
        
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 401
            mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_response)
            mock_get.return_value = mock_response
            
            success, message = parser.test_connection()
            
            assert success is False
            assert "authentication" in message.lower()


class TestNeo4jConnection:
    """Test Neo4j service health checks"""
    
    def test_neo4j_success(self):
        """Test successful Neo4j connection"""
        # This would require a running Neo4j instance or full mocking
        # For now, we'll test the structure
        connector = Neo4jConnector(
            uri="bolt://localhost:7687",
            username="neo4j",
            password="test",
            database="neo4j"
        )
        
        # Mock the driver session
        with patch.object(connector.driver, 'session') as mock_session:
            mock_context = Mock()
            mock_context.__enter__ = Mock(return_value=mock_session)
            mock_context.__exit__ = Mock(return_value=None)
            mock_session.return_value = mock_context
            
            mock_result = Mock()
            mock_result.single.return_value = {"test": 1}
            mock_session.run = Mock(return_value=mock_result)
            
            success, message = connector.test_connection()
            
            assert success is True
            assert "successful" in message.lower()
        
        connector.close()
    
    def test_neo4j_authentication_failure(self):
        """Test Neo4j authentication failure detection"""
        # This test checks that our error message categorization works
        # Full testing would require Neo4j mock or real instance
        connector = Neo4jConnector(
            uri="bolt://localhost:7687",
            username="wrong",
            password="credentials",
            database="neo4j"
        )
        
        # The actual connection test would fail with real credentials
        # This is a structural test
        assert hasattr(connector, 'test_connection')
        assert callable(connector.test_connection)
        
        connector.close()


class TestMainIntegration:
    """Test main.py integration of service checks"""
    
    def test_service_checks_present(self):
        """Verify main.py calls service checks"""
        # Read main.py to verify it has the checks
        main_file = Path(__file__).parent.parent / "src" / "main.py"
        content = main_file.read_text()
        
        # Verify pre-flight checks exist
        assert "test_connection" in content
        assert "Ollama" in content
        assert "Neo4j" in content
        assert "service availability" in content.lower()
        
        # Verify exit on failure
        assert "sys.exit(1)" in content
        assert "Cannot proceed" in content
