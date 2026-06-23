from typing import List, Dict, Tuple, Optional
from rules import BehavioralRule

class DetectionEngine:
    """
    Evaluates process ancestry chains against a set of behavioral rules
    to detect suspicious activity and assign threat scores.
    """
    def __init__(self, rules: List[BehavioralRule]):
        self.rules = rules

    def evaluate_chain(self, chain: List[Dict]) -> List[Tuple[BehavioralRule, Dict, Dict]]:
        """
        Evaluates a process chain against the behavioral rules.
        Returns a list of matches: (matched_rule, parent_node, child_node).
        """
        matches = []
        if len(chain) < 2:
            return matches

        child = chain[-1]
        parent = chain[-2]

        for rule in self.rules:
            # 1. Direct Parent-Child Match
            parent_match = False
            child_match = False

            if rule.parent_names:
                if parent["name"] in rule.parent_names:
                    parent_match = True
            else:
                parent_match = True

            if rule.child_names:
                if child["name"] in rule.child_names:
                    child_match = True
            else:
                child_match = True

            if parent_match and child_match and (rule.parent_names or rule.child_names):
                matches.append((rule, parent, child))
                continue

            # 2. Ancestor-Descendant Match (if specified)
            ancestor_match = False
            descendant_match = False

            if rule.ancestor_names:
                # Check if any process in the chain before the child matches
                for ancestor in chain[:-1]:
                    if ancestor["name"] in rule.ancestor_names:
                        ancestor_match = True
                        parent = ancestor # Treat matched ancestor as parent context for the alert
                        break
            
            if rule.descendant_names:
                if child["name"] in rule.descendant_names:
                    descendant_match = True

            if ancestor_match and descendant_match:
                matches.append((rule, parent, child))

        return matches
