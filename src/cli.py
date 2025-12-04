"""Veritas CLI - Command line interface"""

import argparse
import sys
import os

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    parser = argparse.ArgumentParser(
        prog="veritas",
        description="Veritas - Automated Red Teaming Suite for AI Agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  veritas scan                          Run full scan with default target
  veritas scan --attacks jailbreak      Run specific attack only
  veritas scan --output report.pdf      Export PDF report
  veritas scan --ci --fail-on critical  CI mode with failure threshold
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # SCAN command
    scan_parser = subparsers.add_parser("scan", help="Run security scan against target agent")
    scan_parser.add_argument(
        "--target", "-t",
        default="default",
        help="Target agent config (default: built-in vulnerable agent)"
    )
    scan_parser.add_argument(
        "--attacks", "-a",
        nargs="+",
        choices=[
            "all", "jailbreak", "injection", "tool_abuse", "memory_poison",
            "goal_hijack", "context_override", "data_exfil", "dos",
            "privilege_escalation", "multi_turn"
        ],
        default=["all"],
        help="Attacks to run (default: all)"
    )
    scan_parser.add_argument(
        "--output", "-o",
        help="Output report file (supports .pdf, .json)"
    )
    scan_parser.add_argument(
        "--ci",
        action="store_true",
        help="CI mode (minimal output, exit codes)"
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "never"],
        default="critical",
        help="Fail threshold for CI (default: critical)"
    )
    scan_parser.add_argument(
        "--no-sandbox",
        action="store_true",
        help="Disable Docker sandbox"
    )
    
    # BENCHMARK command
    bench_parser = subparsers.add_parser("benchmark", help="Run standard benchmark suite")
    bench_parser.add_argument(
        "--suite",
        choices=["jailbreak", "injection", "full"],
        default="full",
        help="Benchmark suite to run"
    )
    
    # VERSION command
    subparsers.add_parser("version", help="Show version info")
    
    args = parser.parse_args()
    
    if args.command == "version":
        print("Veritas v1.0.0 - Automated Red Teaming Suite")
        print("https://github.com/ARYAN2302/veritas")
        return 0
    
    if args.command == "scan":
        return run_scan(args)
    
    if args.command == "benchmark":
        print("Benchmark mode coming soon...")
        return 0
    
    parser.print_help()
    return 1


def run_scan(args):
    """Execute the scan command."""
    from src.core.target import AgentTarget
    from src.core.scoring import RiskScorer, RiskLevel
    from src.sandbox.sandbox import AgentSandbox
    from src.attacks import ALL_ATTACKS
    from src.defense import PolicyEngine, DEFAULT_RULES, VeritasNanoClassifier
    
    if not args.ci:
        print("VERITAS Security Scanner v1.0")
        print("=" * 50)
    
    # Initialize components
    target = AgentTarget()
    scorer = RiskScorer()
    classifier = VeritasNanoClassifier()
    policy = PolicyEngine(DEFAULT_RULES)
    
    sandbox = None
    if not args.no_sandbox:
        sandbox = AgentSandbox()
    
    # Select attacks
    if "all" in args.attacks:
        attacks = [cls() for cls in ALL_ATTACKS]
    else:
        attack_map = {
            "jailbreak": "JailbreakAttack",
            "injection": "PromptInjectionAttack",
            "tool_abuse": "ToolAbuseAttack",
            "memory_poison": "MemoryPoisonAttack",
            "goal_hijack": "GoalHijackAttack",
            "context_override": "ContextOverrideAttack",
            "data_exfil": "DataExfilAttack",
            "dos": "DenialOfServiceAttack",
            "privilege_escalation": "PrivilegeEscalationAttack",
            "multi_turn": "MultiTurnAttack",
        }
        attacks = []
        for a in args.attacks:
            cls_name = attack_map.get(a)
            for cls in ALL_ATTACKS:
                if cls.__name__ == cls_name:
                    attacks.append(cls())
                    break
    
    if not args.ci:
        print(f"\nTarget: {target.name if hasattr(target, 'name') else 'Agent'}")
        print(f"Attacks: {len(attacks)}")
        print("-" * 50)
    
    # Run attacks
    for attack in attacks:
        if not args.ci:
            print(f"\n[{attack.name}]")
        
        result = attack.run(target)
        severity = getattr(attack, "severity", "medium")
        
        scorer.add_result(
            attack_name=attack.name,
            severity=severity,
            success=result.success,
            prompt=result.prompt,
            response=result.response,
            score=result.score
        )
        
        if not args.ci:
            status = "VULNERABLE" if result.success else "SAFE"
            print(f"   {status}")
    
    # Generate report
    report = scorer.generate_report(target.name if hasattr(target, 'name') else 'Agent')
    
    if not args.ci:
        scorer.print_summary()
        print("\nRecommendations:")
        for rec in report.recommendations:
            print(f"   • {rec}")
    
    # Export if requested
    if args.output:
        if args.output.endswith(".pdf"):
            from src.reporter import PDFReporter
            reporter = PDFReporter(args.output)
            reporter.generate_report(report.target_name, report.vulnerabilities)
            if not args.ci:
                print(f"\nReport saved: {args.output}")
        elif args.output.endswith(".json"):
            import json
            with open(args.output, "w") as f:
                json.dump(report.to_dict(), f, indent=2)
            if not args.ci:
                print(f"\nReport saved: {args.output}")
    
    # CI exit codes
    if args.ci:
        print(f"VERITAS: {report.overall_risk.value.upper()} ({report.overall_score:.1f})")
        
        threshold_map = {
            "critical": RiskLevel.CRITICAL,
            "high": RiskLevel.HIGH,
            "medium": RiskLevel.MEDIUM,
            "low": RiskLevel.LOW,
        }
        
        if args.fail_on != "never":
            threshold = threshold_map.get(args.fail_on, RiskLevel.CRITICAL)
            risk_order = [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
            if risk_order.index(report.overall_risk) >= risk_order.index(threshold):
                return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
