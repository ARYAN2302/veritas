"""
VERITAS - Automated Red Teaming Suite for AI Agents
"Burp Suite for AI Agents"

Usage:
    python veritas.py                         # Run full scan with defaults
    python veritas.py --config config.yaml    # Run with YAML config
    python veritas.py --attacks jailbreak injection
    python veritas.py --output report.pdf
"""

import sys
import os
import argparse

# Ensure src is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.core.target import AgentTarget
from src.core.scoring import RiskScorer
from src.core.config import VeritasConfig, load_config
from src.core.adapters import create_adapter, AgentConfig as AdapterConfig
from src.sandbox.sandbox import AgentSandbox
from src.attacks import ALL_ATTACKS
from src.defense import PolicyEngine, DEFAULT_RULES, VeritasNanoClassifier
from src.reporter import PDFReporter


def get_classifier(args):
    """Get the appropriate classifier based on args."""
    if args.classifier == "regex":
        return VeritasNanoClassifier()
    
    if args.classifier == "ml":
        try:
            from src.classifier import VeritasNanoInference
            if not os.path.exists(args.model_path):
                print(f"   [WARN] ML model not found at {args.model_path}, using regex fallback")
                return VeritasNanoClassifier()
            return VeritasNanoInference(args.model_path, use_fallback=False)
        except ImportError:
            print("   [WARN] ML classifier requires transformers package, using regex fallback")
            return VeritasNanoClassifier()
    
    # auto mode: try ML, fallback to regex
    try:
        from src.classifier import VeritasNanoInference
        return VeritasNanoInference(args.model_path, use_fallback=True)
    except ImportError:
        return VeritasNanoClassifier()


BANNER = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   ██╗   ██╗███████╗██████╗ ██╗████████╗ █████╗ ███████╗       ║
    ║   ██║   ██║██╔════╝██╔══██╗██║╚══██╔══╝██╔══██╗██╔════╝       ║
    ║   ██║   ██║█████╗  ██████╔╝██║   ██║   ███████║███████╗       ║
    ║   ╚██╗ ██╔╝██╔══╝  ██╔══██╗██║   ██║   ██╔══██║╚════██║       ║
    ║    ╚████╔╝ ███████╗██║  ██║██║   ██║   ██║  ██║███████║       ║
    ║     ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝       ║
    ║                                                               ║
    ║   Automated Red Teaming Suite for AI Agents v1.0              ║
    ║   "Burp Suite for AI Agents"                                  ║
    ╚═══════════════════════════════════════════════════════════════╝
"""


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="VERITAS - Automated Red Teaming Suite for AI Agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python veritas.py                             # Run full scan
    python veritas.py --config examples/config_basic.yaml
    python veritas.py --attacks injection jailbreak --verbose
    python veritas.py --provider openai --model gpt-4o-mini
        """
    )
    parser.add_argument(
        "--config", "-c",
        help="Path to YAML configuration file"
    )
    parser.add_argument(
        "--attacks", "-a",
        nargs="+",
        help="Specific attacks to run (e.g., injection jailbreak)"
    )
    parser.add_argument(
        "--provider", "-p",
        choices=["groq", "openai", "anthropic", "ollama", "custom"],
        default="groq",
        help="LLM provider (default: groq)"
    )
    parser.add_argument(
        "--model", "-m",
        help="Model name (default: provider-specific)"
    )
    parser.add_argument(
        "--output", "-o",
        default="veritas_report",
        help="Output report filename (without extension)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["pdf", "json", "both"],
        default="both",
        help="Output format (default: both)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--no-sandbox",
        action="store_true",
        help="Disable sandbox escalation tests"
    )
    parser.add_argument(
        "--classifier",
        choices=["regex", "ml", "auto"],
        default="auto",
        help="Classifier to use (regex=fast heuristic, ml=trained model, auto=ml if available)"
    )
    parser.add_argument(
        "--model-path",
        default="models/veritas-nano",
        help="Path to trained ML classifier model"
    )
    return parser.parse_args()


def get_enabled_attacks(attack_names=None):
    """Get attack classes based on names or return all."""
    attack_map = {cls().name.lower().replace(" ", "_").replace("-", "_"): cls for cls in ALL_ATTACKS}
    # Also map short names
    attack_map["injection"] = attack_map.get("prompt_injection", ALL_ATTACKS[0])
    attack_map["jailbreak"] = attack_map.get("jailbreak", ALL_ATTACKS[1])
    attack_map["data_exfil"] = attack_map.get("data_exfiltration", ALL_ATTACKS[6])
    attack_map["dos"] = attack_map.get("denial_of_service", ALL_ATTACKS[7])
    attack_map["multi_turn"] = attack_map.get("multi_turn_manipulation", ALL_ATTACKS[9])
    
    if attack_names is None:
        return ALL_ATTACKS
    
    enabled = []
    for name in attack_names:
        key = name.lower().replace("-", "_")
        if key in attack_map:
            enabled.append(attack_map[key])
        else:
            print(f"[WARN] Unknown attack: {name}, skipping...")
    
    return enabled if enabled else ALL_ATTACKS


def create_target_from_config(args):
    """Create target agent from args or config file."""
    if args.config:
        try:
            config = load_config(args.config)
            print(f"   Loaded config: {args.config}")
            
            # Resolve API key
            api_key = config.resolve_api_key()
            
            # Create adapter config
            adapter_config = AdapterConfig(
                name=f"{config.target.provider}/{config.target.model}",
                provider=config.target.provider,
                model=config.target.model,
                api_key=api_key,
                system_prompt=config.target.system_prompt,
                temperature=config.target.temperature,
                max_tokens=config.target.max_tokens,
            )
            
            # Create adapter from config
            adapter = create_adapter(adapter_config)
            
            # Wrap adapter as target
            class ConfiguredTarget:
                def __init__(self, adapter, config):
                    self.adapter = adapter
                    self.name = f"{config.target.provider}/{config.target.model}"
                    
                def invoke(self, prompt):
                    return self.adapter.invoke(prompt)
            
            return ConfiguredTarget(adapter, config), config
        except Exception as e:
            print(f"   [WARN] Config error: {e}, using defaults...")
    
    # Default: use AgentTarget (Groq)
    return AgentTarget(), None


def main():
    args = parse_args()
    print(BANNER)
    
    # Phase 1: Infrastructure Initialization
    print("[Phase 1] Initializing Infrastructure...")
    print("-" * 60)
    
    # Initialize sandbox
    sandbox = None
    if not args.no_sandbox:
        sandbox = AgentSandbox()
    
    # Initialize target agent
    target, config = create_target_from_config(args)
    target_name = target.name if hasattr(target, 'name') else "Unknown Agent"
    print(f"   Target: {target_name}")
    
    # Initialize defense systems
    classifier = get_classifier(args)
    classifier_type = "ML" if hasattr(classifier, '_load_model') else "Regex"
    print(f"   Classifier: {classifier_type}")
    policy = PolicyEngine(DEFAULT_RULES)
    
    # Initialize scoring
    scorer = RiskScorer()
    
    # Get attacks
    attack_names = args.attacks
    if config and hasattr(config, 'attacks') and config.attacks.enabled:
        attack_names = config.attacks.enabled
    attack_classes = get_enabled_attacks(attack_names)
    
    # Phase 2: Attack Execution
    print("\n[Phase 2] Executing Attack Suite...")
    print("-" * 60)
    
    # Instantiate all attacks
    attacks = [cls() for cls in attack_classes]
    print(f"   Loaded {len(attacks)} attack modules\n")
    
    for i, attack in enumerate(attacks, 1):
        severity = getattr(attack, "severity", "medium")
        print(f"[{i:02d}/{len(attacks)}] {attack.name} (Severity: {severity.upper()})")
        
        try:
            # Execute attack
            result = attack.run(target)
            
            # Post-scan with policy engine
            if result.success:
                decision = policy.evaluate_response(result.prompt, result.response)
                print(f"       Policy: {decision.action.value.upper()} - {decision.reason}")
            
            # Record result
            scorer.add_result(
                attack_name=attack.name,
                severity=severity,
                success=result.success,
                prompt=result.prompt,
                response=result.response,
                score=result.score
            )
            
            status = "VULNERABLE" if result.success else "SAFE"
            print(f"       Result: {status}")
            
            # If vulnerable, attempt sandbox escalation
            if result.success and sandbox and sandbox.client:
                print("       Running sandbox escalation test...")
                sandbox_result = sandbox.execute_isolated("print('Escalation test passed')")
                print(f"       Sandbox: {sandbox_result[:50]}...")
                
        except Exception as e:
            print(f"       [ERROR] {str(e)[:50]}...")
            scorer.add_result(
                attack_name=attack.name,
                severity=severity,
                success=False,
                prompt="ERROR",
                response=str(e),
                score=0.0
            )
        
        print()
    
    # Phase 3: Report Generation
    print("\n[Phase 3] Generating Risk Report...")
    print("-" * 60)
    
    report = scorer.generate_report(target_name)
    scorer.print_summary()
    
    print("\nRecommendations:")
    for rec in report.recommendations:
        print(f"   • {rec}")
    
    # Phase 4: Export
    print("\n[Phase 4] Exporting Report...")
    print("-" * 60)
    
    output_base = args.output
    output_format = args.format
    
    # PDF Report
    if output_format in ["pdf", "both"]:
        pdf_file = f"{output_base}.pdf"
        pdf_reporter = PDFReporter(pdf_file)
        pdf_reporter.generate_report(target_name, report.vulnerabilities)
        print(f"   PDF saved: {pdf_file}")
    
    # JSON Report
    if output_format in ["json", "both"]:
        import json
        json_file = f"{output_base}.json"
        with open(json_file, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"   JSON saved: {json_file}")
    
    # Done
    print("\n" + "=" * 60)
    print("VERITAS scan complete.")
    print(f"   Risk Level: {report.overall_risk.value.upper()}")
    print(f"   Score: {report.overall_score}/100")
    print("=" * 60)
    
    return 0 if report.overall_score < 50 else 1


if __name__ == "__main__":
    sys.exit(main())