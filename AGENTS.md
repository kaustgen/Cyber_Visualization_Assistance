# Project Overview
This is a localized neo4j instance that utilizes an Obsidian plugin alongside a markdown template to send notes from your Obsidian instance to this application. This application will run a local, community-edition Neo4J instance, recieve the .md file from Obsidian, parse it using an LLM, and automatically generate the nodes within Neo4J. 

It is designed for penetration testers who may use Obsidian as a note taking system, and it will help them with organizing their penetration testing notes.

It is critical that we do not create any extra information or links, and simply provide a place for the user to store their notes in a visual way that can be queried. It is imperative we provide a way for the user to add, edit, or remove information from nodes without changing any other items. 

# Neo4J
Within Neo4J there will be a heirarchy of nodes. The top-level nodes will be actual machines and devices on the network, and from there will stem other nodes. The basic heirarchy we will start with is this where '-' represents a new node, '+' represent one or several attributes of that node, and '*' represents connections
- Host
    + Attributes: OS, CVEs
    - Connected Nodes:
        - Applications
            + Attributes: CVEs
            * Connections: Host
        - Users
            + Attributes: Permission Level
            * Connections: Host
        - Ports
            + Attributes: Service
            * Connections: Host
        - Network Interface Cards
            + Attributes: MAC, IP
            * Connections: Network Interface Cards belong to other Host

The above is what we will start with for now. 

# Python

## Virtual Environment
Created with `python3 -m venv venv/`
Activated with `.\venv\Scripts\activate`
- Ensure that your virtual environment is properly activated before running code or tests

At the end of every sessions we must update our requirements file, so make sure you run this command from the project's root directory: `pip freeze > requirements.txt`

## Overview
After setting up the python virtual environment then we will move onto our actual python code.

This will ingest a MD from our Obsidian plugin, parse it using an LLM, embed the LLMs parsed information into Neo4J nodes, and then push those Neo4J nodes. The nodes will be structured as they were above within the Neo4J section so a user can query the neo4j database with useful information. While keeping 