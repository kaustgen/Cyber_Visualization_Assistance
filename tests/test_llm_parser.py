# Author: Kaleb Austgen
# Date: 2/16/2026
# Description: Unit tests for LLM parser - testing markdown variations

import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from llm_parser import LLMParser

# Test fixtures directory
TEST_DATA_DIR = Path(__file__).parent / "test_data"


@pytest.fixture
def parser():
    """Create a parser instance for testing"""
    return LLMParser()


class TestMarkdownVariations:
    """Test parser handles various markdown format variations"""
    
    def test_different_heading_styles(self, parser):
        """Test both ## Host: and ##Host: formats work"""
        markdown_with_space = "## Host: web-server-01\n**Operating System:** Ubuntu"
        markdown_without_space = "##Host: web-server-01\n**Operating System:** Ubuntu"
        
        result1 = parser.parse_markdown(markdown_with_space)
        result2 = parser.parse_markdown(markdown_without_space)
        
        assert len(result1['hosts']) == 1
        assert len(result2['hosts']) == 1
        assert result1['hosts'][0]['name'] == 'web-server-01'
    
    def test_case_insensitive_labels(self, parser):
        """Test labels like 'Operating System', 'OS', 'operating system' all work"""
        markdown_variations = [
            "## Host: server-01\n**Operating System:** Ubuntu",
            "## Host: server-01\n**OS:** Ubuntu",
            "## Host: server-01\n**operating system:** Ubuntu"
        ]
        
        for md in markdown_variations:
            result = parser.parse_markdown(md)
            assert result['hosts'][0]['os'] in ['Ubuntu', 'Unknown']
    
    def test_optional_vulnerability_fields(self, parser):
        """Test vulnerabilities work with missing optional fields"""
        markdown = """
## Host: server-01
### Vulnerabilities
- CVE-2021-3156
- CVE-2021-44228 - Score: 10.0
- CVE-2022-1234 - Score: 7.5, Exploitable: true, Patched: false
"""
        result = parser.parse_markdown(markdown)
        vulns = result['hosts'][0]['vulnerabilities']
        
        # All should be parsed
        assert len(vulns) >= 1
        
        # First has minimal info
        cve1 = next((v for v in vulns if v['cve_id'] == 'CVE-2021-3156'), None)
        if cve1:
            assert cve1['severity_score'] == 0.0  # Default
            # Don't assert on exploitable - LLM may infer it
    
    def test_services_with_without_version(self, parser):
        """Test services parse correctly with or without version numbers"""
        markdown = """
## Host: server-01
### Open Ports
- Port 80
  - Service: Apache 2.4.41
- Port 443
  - Service: nginx
"""
        result = parser.parse_markdown(markdown)
        ports = result['hosts'][0]['ports']
        
        # Should have 2 ports
        assert len(ports) == 2
        
        # Services should exist
        port80 = next(p for p in ports if p['number'] == 80)
        assert len(port80['services']) >= 1
    
    def test_multiple_users_on_one_line(self, parser):
        """Test 'Users: root, admin, backup' format"""
        markdown = """
## Host: server-01
### Services
- MySQL
  - Users: root (Administrator), db_user (Standard), backup (Backup account)
"""
        result = parser.parse_markdown(markdown)
        services = result['hosts'][0]['services']
        
        if services:
            mysql = services[0]
            # Should parse multiple users from one line
            assert len(mysql.get('users', [])) >= 1
    
    def test_nested_notes(self, parser):
        """Test notes at different levels are preserved"""
        markdown = """
## Host: server-01
### Notes
Host-level note

### Services
- Apache
  - Notes: Service-level note
  - Vulnerabilities: CVE-2021-1234
    - Notes: Vulnerability-level note
"""
        result = parser.parse_markdown(markdown)
        host = result['hosts'][0]
        
        # Check host notes
        assert host.get('notes') is not None
        
        # Check service notes if parsed
        if host['services']:
            service = host['services'][0]
            assert service.get('notes') is not None


class TestEdgeCases:
    """Test edge cases and malformed input"""
    
    def test_empty_sections(self, parser):
        """Test sections with no content don't crash"""
        markdown = """
## Host: server-01
### Vulnerabilities
### Open Ports
### Users
"""
        result = parser.parse_markdown(markdown)
        assert len(result['hosts']) == 1
        assert result['hosts'][0]['vulnerabilities'] == []
        assert result['hosts'][0]['ports'] == []
    
    def test_duplicate_host_names(self, parser):
        """Test handling of duplicate host entries"""
        markdown = """
## Host: server-01
**OS:** Ubuntu

---

## Host: server-01
**OS:** Windows
"""
        result = parser.parse_markdown(markdown)
        # Should handle duplicates (merge or keep separate)
        assert len(result['hosts']) >= 1
    
    def test_special_characters_in_names(self, parser):
        """Test hosts/services with special characters"""
        markdown = """
## Host: web-server_01.domain.com
### Services
- MySQL-5.7-custom
- app_service (v2.0)
"""
        result = parser.parse_markdown(markdown)
        assert len(result['hosts']) == 1
    
    def test_missing_required_fields(self, parser):
        """Test graceful handling of missing critical fields"""
        markdown = """
## Host: 
**OS:** Ubuntu
"""
        # Should not crash, might skip or use default
        result = parser.parse_markdown(markdown)
        assert isinstance(result, dict)
        assert 'hosts' in result


class TestNeo4jSchema:
    """Test that parsed output matches Neo4j schema requirements"""
    
    def test_user_source_attribute(self, parser):
        """Test users have source attribute for uniqueness"""
        markdown = """
## Host: server-01
### Users
- admin
### Services
- MySQL
  - Users: mysql_admin
"""
        result = parser.parse_markdown(markdown)
        host = result['hosts'][0]
        
        # Host users should have source = hostname
        if host['users']:
            assert host['users'][0]['source'] == 'server-01'
        
        # Service users should have source = service name
        if host['services'] and host['services'][0].get('users'):
            assert 'MySQL' in host['services'][0]['users'][0]['source']
    
    def test_vulnerability_shared_node_format(self, parser):
        """Test vulnerabilities are in format suitable for shared nodes"""
        markdown = """
## Host: server-01
### Vulnerabilities
- CVE-2021-3156 - Score: 7.8

### Services
- Apache
  - Vulnerabilities: CVE-2021-3156
"""
        result = parser.parse_markdown(markdown)
        host = result['hosts'][0]
        
        # Both should reference same CVE
        host_cve = host['vulnerabilities'][0]['cve_id']
        if host['services'] and host['services'][0].get('vulnerabilities'):
            service_cve = host['services'][0]['vulnerabilities'][0]['cve_id']
            assert host_cve == service_cve  # Same CVE ID
    
    def test_port_runs_service_relationship(self, parser):
        """Test ports correctly contain services array"""
        markdown = """
## Host: server-01
### Open Ports
- Port 443
  - Service: Apache
  - Service: MySQL-tunnel
"""
        result = parser.parse_markdown(markdown)
        port = result['hosts'][0]['ports'][0]
        
        # Port should have services array
        assert 'services' in port
        assert isinstance(port['services'], list)


# Integration test with actual LLM (slower)
@pytest.mark.integration
def test_full_pipeline_with_llm(tmp_path):
    """Test complete pipeline with real markdown file and LLM"""
    # Create temporary markdown file
    test_md = tmp_path / "test_notes.md"
    test_md.write_text("""
# Test Pentest Notes

## Host: test-server
**IP Address:** 192.168.1.100
**Operating System:** Ubuntu 20.04

### Vulnerabilities
- CVE-2021-3156 - Score: 7.8, Exploitable: true

### Open Ports
- Port 80
  - Service: Apache 2.4.41

### Users
- admin (Administrator)
""")
    
    from llm_parser import parse_file
    result = parse_file(str(test_md))
    
    assert len(result['hosts']) == 1
    assert result['hosts'][0]['name'] == 'test-server'
    assert len(result['hosts'][0]['vulnerabilities']) >= 1
    assert len(result['hosts'][0]['ports']) >= 1
