#!/usr/bin/env python3
"""Preflight information for the local ReverseLens Phase 1 environment."""
import shutil

def main() -> int:
    print("ReverseLens Phase 1 preflight")
    for command in ("docker", "java", "mvn", "node", "npm", "python"):
        print(f"{command}: {shutil.which(command) or 'not found'}")
    print("Engine binaries run inside the worker container.")
    print("Start stack: docker compose up --build")
    print("Dashboard: http://localhost:3000")
    print("API health: http://localhost:8080/actuator/health")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
