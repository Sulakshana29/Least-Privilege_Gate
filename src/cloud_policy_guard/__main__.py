"""
Enables running Cloud Policy Guard as a module:
    python -m cloud_policy_guard scan --terraform-plan plan.json
"""

from cloud_policy_guard.cli import main

if __name__ == "__main__":
    main()
