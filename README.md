**SOAR Workbook Exporter**

**Integration**
The app does not integrate with any external service, it merely provides actions to generate and store files containing information about SOAR tasks associated with a container.

**About**
The app provides actions to create .json, .yaml, and .pdf files containing workbook information in the following format:
```
<h2> Phase
<h3> Task
<standard> Description
<bold> Actions ... <standard> Action Name
<Bold> Playbook ... <standard> Playbook Name
```
PDF and YAML files are stored in the vault associated with the container. The cleaned json file is added to the SOAR action result. 
The user needs to provide a container ID, and can leave an additional comment.

