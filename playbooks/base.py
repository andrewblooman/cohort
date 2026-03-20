"""
playbooks/base.py

Base playbook definition.

Every incident-response playbook is represented as a dataclass that carries
scenario-specific metadata, investigation guidance, and recommended actions.
The AI analysis Lambda selects a playbook at runtime based on the GuardDuty
finding type and injects the playbook's instructions into the analysis prompt
so that the LLM receives targeted guidance for the incident category.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Playbook:
    """Immutable playbook definition.

    Attributes:
        name:                   Human-readable playbook name.
        description:            Short description of the scenario this playbook covers.
        finding_type_patterns:  GuardDuty finding-type substrings that trigger this
                                playbook (matched case-insensitively).
        investigation_steps:    Ordered list of scenario-specific investigation steps
                                injected into the AI prompt.
        key_indicators:         Indicators the analyst / LLM should look for.
        response_actions:       Recommended response actions for the scenario.
        mitre_techniques:       Relevant MITRE ATT&CK technique IDs.
    """

    name: str
    description: str
    finding_type_patterns: list[str] = field(default_factory=list)
    investigation_steps: list[str] = field(default_factory=list)
    key_indicators: list[str] = field(default_factory=list)
    response_actions: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Prompt-fragment helpers
    # ------------------------------------------------------------------

    def format_prompt_section(self) -> str:
        """Return a markdown section suitable for injection into an AI prompt."""
        lines: list[str] = []
        lines.append(f"## PLAYBOOK: {self.name}\n")
        lines.append(f"{self.description}\n")

        if self.investigation_steps:
            lines.append("### Investigation Steps\n")
            for i, step in enumerate(self.investigation_steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        if self.key_indicators:
            lines.append("### Key Indicators to Evaluate\n")
            for indicator in self.key_indicators:
                lines.append(f"- {indicator}")
            lines.append("")

        if self.response_actions:
            lines.append("### Recommended Response Actions\n")
            for action in self.response_actions:
                lines.append(f"- {action}")
            lines.append("")

        if self.mitre_techniques:
            lines.append(
                "### Relevant MITRE ATT&CK Techniques\n"
            )
            lines.append(", ".join(self.mitre_techniques))
            lines.append("")

        return "\n".join(lines)
