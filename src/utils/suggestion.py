from .vulnerability_database import VulnerabilityDatabase

class Suggestion:
    def __init__(self):
        self.db = VulnerabilityDatabase()

    def suggest(self, open_ports, services):
        matched_vulnerabilities = self.db.match_vulnerabilities(open_ports, services)
        priorities = self.db.prioritize_vulnerabilities(matched_vulnerabilities)
        potential_vulnerabilities = self.db.generate_potential_vulnerabilities(matched_vulnerabilities, priorities)
        return potential_vulnerabilities
