"""AI Agent Browser Forensics (AABF).

A modular forensic toolkit for AI agent browsers, implementing the framework
described in "I Know What You Prompted Last Session: Forensic Analysis of AI
Agent Browsers".

Modules
-------
identification : identify the AI agent browser from local traces and classify
                 its service type (local-centric / cloud-centric / hybrid).
collection     : local artifact collection + API-reconstruction remote
                 collection (later module).
parsing        : parse LevelDB / IndexedDB / SQLite / logs into structured
                 agent artifacts (later module).
analysis       : correlate local + server data into a behavior timeline
                 (later module).
"""

# Versioning scheme: MAJOR.MINOR.YYMMDD (the third field is the build date).
__version__ = "1.0.260611"

# Four agent-artifact categories defined by the paper (Section 3.1).
ARTIFACT_CATEGORIES = ("Account", "Prompt", "Workflow", "Output")

# Three service types from the classification stage (Section 5.2).
SERVICE_TYPE_LOCAL = "local-centric"
SERVICE_TYPE_CLOUD = "cloud-centric"
SERVICE_TYPE_HYBRID = "hybrid"
