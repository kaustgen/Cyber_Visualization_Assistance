# What am I?
The Cyber Visualization Tools is a local, Neo4J backed visualization tool utilizing Neo4j community edition. It is meant to assist penetration testers in visualizing and organizing their notes, network maps, and other important items.

It is supposed to be a one-stop shop for enumeration, and will allow you to utilize Neo4Js powerful querying system to show potential attack vectors that may have been hidden before. 

## Local
The instance in entirely local so you can deploy this application alongside a fresh database to your machine. This keep your client's data safe so you can maintain ethical practices. 

## Technologies
Neo4j acts as our primary interface. It comes with a built-in webapplication which we can interact with, so all we have to do is parse notes and import it into Neo4J, and provide some pre-built queries for users to utilize. They can also use their own queries if they understand how Neo4J works!

We will use Python as our primary worker to parse data due to its extensive support with LLM libraries. When the user writes notes within Obsidian and have our plugin included, they can choose specific notes to send to Neo4J. If they are formatted correctly with a template included then the LLM will parse the data and import it directly into Neo4J for us!