# Author: Kaleb Austgen
# Date: 2/16/2026
# Description: Tests for Neo4j connector with mock data

import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from neo4j_connector import Neo4jConnector, create_connector_from_env


@pytest.fixture
def mock_parsed_data():
    """Fixture with sample parsed data matching schema"""
    return {
        'hosts': [
            {
                'name': 'test-server',
                'os': 'Ubuntu 20.04',
                'notes': 'Test host',
                'vulnerabilities': [
                    {
                        'cve_id': 'CVE-2021-3156',
                        'severity_score': 7.8,
                        'exploitable': True,
                        'patched': False,
                        'notes': 'Sudo vulnerability'
                    }
                ],
                'ports': [
                    {
                        'number': 80,
                        'protocol': 'TCP',
                        'services': [
                            {
                                'name': 'Apache',
                                'version': '2.4.41',
                                'notes': 'Web server',
                                'vulnerabilities': [],
                                'users': []
                            }
                        ]
                    }
                ],
                'services': [],
                'users': [
                    {
                        'username': 'admin',
                        'permission_level': 'Administrator',
                        'source': 'test-server',
                        'has_access_to': ['Apache']
                    }
                ],
                'nics': [
                    {
                        'ip': '192.168.1.100',
                        'mac': '00:0a:95:9d:68:16',
                        'connects_to': []
                    }
                ]
            }
        ]
    }


@pytest.fixture
def neo4j_connector():
    """Create Neo4j connector for testing"""
    try:
        connector = create_connector_from_env()
        # Clear test database before each test
        connector.clear_database()
        yield connector
        # Cleanup after test
        connector.clear_database()
        connector.close()
    except Exception as e:
        pytest.skip(f"Neo4j not available: {e}")


@pytest.mark.neo4j
class TestNeo4jConnector:
    """Test Neo4j connector operations"""
    
    def test_create_host(self, neo4j_connector):
        """Test host creation"""
        result = neo4j_connector.create_host(
            name='test-host',
            os='Ubuntu',
            notes='Test notes'
        )
        assert result['name'] == 'test-host'
        assert result['os'] == 'Ubuntu'
    
    def test_create_vulnerability_shared_node(self, neo4j_connector):
        """Test vulnerabilities are created as shared nodes"""
        # Create same CVE twice
        vuln1 = neo4j_connector.create_vulnerability('CVE-2021-3156', 7.8)
        vuln2 = neo4j_connector.create_vulnerability('CVE-2021-3156', 7.8)
        
        # Should return same node (MERGE behavior)
        assert vuln1['cve_id'] == vuln2['cve_id']
    
    def test_import_full_structure(self, neo4j_connector, mock_parsed_data):
        """Test importing complete parsed data structure"""
        stats = neo4j_connector.import_parsed_data(mock_parsed_data)
        
        assert stats['hosts'] == 1
        assert stats['vulnerabilities'] >= 1
        assert stats['services'] >= 1
        assert stats['users'] >= 1
        assert stats['ports'] >= 1
        assert stats['nics'] >= 1
    
    def test_user_uniqueness_by_source(self, neo4j_connector):
        """Test users are unique by username + source"""
        # Create same username but different sources
        user1 = neo4j_connector.create_user('admin', 'server-01', 'Administrator')
        user2 = neo4j_connector.create_user('admin', 'server-02', 'Administrator')
        
        # Should create two different user nodes
        assert user1['source'] != user2['source']
    
    def test_has_access_relationship(self, neo4j_connector, mock_parsed_data):
        """Test HAS_ACCESS relationship is created"""
        neo4j_connector.import_parsed_data(mock_parsed_data)
        
        # Query to verify relationship exists
        with neo4j_connector.driver.session(database=neo4j_connector.database) as session:
            result = session.run("""
                MATCH (u:User {username: 'admin'})-[:HAS_ACCESS]->(s:Service {name: 'Apache'})
                RETURN u, s
            """)
            records = list(result)
            assert len(records) > 0
    
    def test_port_runs_service_relationship(self, neo4j_connector):
        """Test RUNS_SERVICE relationship between Port and Service"""
        # Create host, port, and service
        neo4j_connector.create_host('test-host')
        neo4j_connector.create_port('test-host', 80, 'TCP')
        neo4j_connector.create_service('test-host', 'Apache', '2.4.41', '', port_number=80)
        
        # Query to verify relationship
        with neo4j_connector.driver.session(database=neo4j_connector.database) as session:
            result = session.run("""
                MATCH (p:Port {number: 80})-[:RUNS_SERVICE]->(s:Service {name: 'Apache'})
                RETURN p, s
            """)
            records = list(result)
            assert len(records) > 0
    
    def test_host_runs_service_directly(self, neo4j_connector):
        """Test direct Host -> Service relationship (no port)"""
        neo4j_connector.create_host('test-host')
        neo4j_connector.create_service('test-host', 'cron', '', 'Background service', port_number=None)
        
        # Query to verify relationship
        with neo4j_connector.driver.session(database=neo4j_connector.database) as session:
            result = session.run("""
                MATCH (h:Host {name: 'test-host'})-[:RUNS_SERVICE]->(s:Service {name: 'cron'})
                RETURN h, s
            """)
            records = list(result)
            assert len(records) > 0
    
    def test_nic_connects_to_relationship(self, neo4j_connector):
        """Test CONNECTS_TO relationship between NICs"""
        # Create two hosts with NICs
        neo4j_connector.create_host('host-01')
        neo4j_connector.create_host('host-02')
        neo4j_connector.create_nic('host-01', '00:00:00:00:00:01', '192.168.1.100')
        neo4j_connector.create_nic('host-02', '00:00:00:00:00:02', '192.168.1.101')
        
        # Create connection
        result = neo4j_connector.create_nic_connection('192.168.1.100', '192.168.1.101')
        assert result == True
        
        # Query to verify
        with neo4j_connector.driver.session(database=neo4j_connector.database) as session:
            result = session.run("""
                MATCH (n1:NIC {ip: '192.168.1.100'})-[:CONNECTS_TO]->(n2:NIC {ip: '192.168.1.101'})
                RETURN n1, n2
            """)
            records = list(result)
            assert len(records) > 0
    
    def test_vulnerability_links_to_host_and_service(self, neo4j_connector):
        """Test same vulnerability can link to both host and service"""
        # Create host and service
        neo4j_connector.create_host('test-host')
        neo4j_connector.create_service('test-host', 'Apache', '2.4.41', '')
        
        # Create vulnerability and link to both
        neo4j_connector.create_vulnerability('CVE-2021-3156', 7.8)
        neo4j_connector.link_vulnerability_to_host('test-host', 'CVE-2021-3156')
        neo4j_connector.link_vulnerability_to_service('Apache', 'test-host', 'CVE-2021-3156')
        
        # Verify both relationships exist
        with neo4j_connector.driver.session(database=neo4j_connector.database) as session:
            host_result = session.run("""
                MATCH (h:Host)-[:HAS_VULNERABILITY]->(v:Vulnerability {cve_id: 'CVE-2021-3156'})
                RETURN h, v
            """)
            service_result = session.run("""
                MATCH (s:Service)-[:HAS_VULNERABILITY]->(v:Vulnerability {cve_id: 'CVE-2021-3156'})
                RETURN s, v
            """)
            assert len(list(host_result)) > 0
            assert len(list(service_result)) > 0
