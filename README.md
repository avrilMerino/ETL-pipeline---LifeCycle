# ETL-pipeline---LifeCycle

ETL pipeline built in Python that processes weekly security scan exports from Sonar, Fortify, and Trivy, consolidating the results into a single dated audit report per execution.
Practice exercise based on a real DevSecOps workflow.

Project Structure
Ejercicio_LifeCycle_Avril/
│
├── csv/                                  # Weekly raw CSV inputs
│   ├── 2024-09-06.csv
│   ├── 2024-09-13.csv
│   ├── 2024-09-20.csv
│   └── 2024-09-27.csv
│
├── logs/
│   └── etl_lifecycle.log
│
├── Auditoria_Lifecycle_YYYY-MM-DD.csv    # Output (generated at runtime)
├── LifeCycle.pdf                         # Exercise specification
└── etl_lifecycle.py

How It Works
The script reads all CSVs from the csv/ folder and processes them in four stages:
Extraction — All weekly files are loaded and concatenated into a single DataFrame. The filename is used as the audit date for each record.
Per-tool cleaning — The data is split into three separate tables (Sonar, Fortify, Trivy), each deduplicated by application name and enriched with derived columns:

Sonar adds a ToPassSonar flag and a SonarTest result, defaulting to KO when the analysis result is missing.
Fortify and Trivy follow the same logic: null vulnerability counts are filled with 0, and each app receives a classification based on the severity of its findings.

Merge — The three tables are joined on appName using an outer join, so no application is lost even if it only appears in one of the tools.
Export — The final DataFrame is saved as Auditoria_Lifecycle_YYYY-MM-DD.csv in the project root.

Vulnerability Classification
Applied to both Fortify and Trivy:
ResultConditionOKNo high or critical findingsHighOnly high-severity findingsCriticalOnly critical-severity findingsHigh&CriticalBoth high and critical findings present

Requirements

Python 3.x
pandas
numpy

bashpip install pandas numpy

Usage
Place the weekly CSV files in the csv/ folder and run:
bashpython etl_lifecycle.py
The output file will be created in the project root. Execution details are written to logs/etl_lifecycle.log.

Author
Avril Merino Moreno 
