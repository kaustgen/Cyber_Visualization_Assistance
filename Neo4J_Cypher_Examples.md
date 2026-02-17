# Neo4j Browser Queries for Visualization

## View All Hosts with Their NICs
```cypher
MATCH (h:Host)-[:HAS_NIC]->(n:NIC)
RETURN h, n
```

## View Complete Network Topology
```cypher
MATCH (h:Host)-[:HAS_NIC]->(n:NIC)
OPTIONAL MATCH (n)-[:CONNECTS_TO]->(n2:NIC)
RETURN h, n, n2
```

## View NIC Connections Only
```cypher
MATCH (n1:NIC)-[:CONNECTS_TO]->(n2:NIC)
RETURN n1, n2
```

## View Everything in the Database
```cypher
MATCH (n)
OPTIONAL MATCH (n)-[r]->(m)
RETURN n, r, m
```

## Check if database-server-01 has a NIC
```cypher
MATCH (h:Host {name: 'database-server-01'})-[:HAS_NIC]->(n:NIC)
RETURN h, n
```

## Count NICs per Host
```cypher
MATCH (h:Host)
OPTIONAL MATCH (h)-[:HAS_NIC]->(n:NIC)
RETURN h.name AS Host, count(n) AS NIC_Count, collect(n.ip) AS IPs
ORDER BY h.name
```
