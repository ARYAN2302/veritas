"""
VERITAS Dashboard - Production-Level Streamlit UI
=================================================
Full-featured security scanning dashboard with:
- Multi-provider support (OpenAI, Anthropic, Groq, Ollama)
- All 10 attack types
- Real-time progress tracking
- Interactive results visualization
- PDF/JSON report generation
"""

import streamlit as st
import time
import sys
import os
import json
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.target import AgentTarget
from src.core.scoring import RiskScorer
from src.core.adapters import create_adapter, AgentConfig
from src.attacks import ALL_ATTACKS, get_all_payloads, get_payload_count
from src.defense import PolicyEngine, DEFAULT_RULES, VeritasNanoClassifier
from src.sandbox.sandbox import AgentSandbox
from src.reporter import PDFReporter

# Page config
st.set_page_config(
    page_title="VERITAS - AI Red Team Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        background: linear-gradient(90deg, #ff6b6b, #feca57, #48dbfb, #ff9ff3);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0;
    }
    .subtitle {
        color: #888;
        font-size: 1.1rem;
        margin-top: -10px;
    }
    .attack-card {
        background: #1e1e1e;
        border-radius: 10px;
        padding: 15px;
        margin: 10px 0;
    }
    .vuln-badge {
        background: #ff4757;
        color: white;
        padding: 3px 10px;
        border-radius: 15px;
        font-size: 0.8rem;
    }
    .safe-badge {
        background: #2ed573;
        color: white;
        padding: 3px 10px;
        border-radius: 15px;
        font-size: 0.8rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 15px;
        padding: 20px;
        text-align: center;
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None
if 'scanning' not in st.session_state:
    st.session_state.scanning = False
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []


def validate_api_key(provider: str, api_key: str) -> tuple:
    """Validate API key format."""
    if not api_key or api_key.strip() == "":
        return False, "API key is required"
    
    if provider == "groq" and not api_key.startswith("gsk_"):
        return False, "Groq API key should start with 'gsk_'"
    if provider == "openai" and not api_key.startswith("sk-"):
        return False, "OpenAI API key should start with 'sk-'"
    if provider == "anthropic" and not api_key.startswith("sk-ant-"):
        return False, "Anthropic API key should start with 'sk-ant-'"
    
    return True, "Valid"


def get_attack_info():
    """Get information about available attacks."""
    attacks_info = []
    for cls in ALL_ATTACKS:
        instance = cls()
        attacks_info.append({
            "name": instance.name,
            "description": instance.description,
            "severity": getattr(instance, "severity", "medium"),
            "class": cls
        })
    return attacks_info


def run_scan(target, selected_attacks, progress_callback, rate_limit_delay=0.5):
    """Run security scan with selected attacks."""
    scorer = RiskScorer()
    policy = PolicyEngine(DEFAULT_RULES)
    results = []
    
    for i, attack_cls in enumerate(selected_attacks):
        attack = attack_cls()
        severity = getattr(attack, "severity", "medium")
        
        progress_callback(i, len(selected_attacks), f"Running {attack.name}...")
        
        try:
            result = attack.run(target)
            
            # Policy evaluation
            policy_decision = None
            if result.success:
                policy_decision = policy.evaluate_response(result.prompt, result.response)
            
            scorer.add_result(
                attack_name=attack.name,
                severity=severity,
                success=result.success,
                prompt=result.prompt,
                response=result.response,
                score=result.score
            )
            
            results.append({
                "name": attack.name,
                "severity": severity,
                "success": result.success,
                "prompt": result.prompt,
                "response": result.response[:500] + "..." if len(result.response) > 500 else result.response,
                "policy": policy_decision.action.value if policy_decision else None
            })
            
        except Exception as e:
            results.append({
                "name": attack.name,
                "severity": severity,
                "success": False,
                "prompt": "ERROR",
                "response": str(e),
                "error": True
            })
        
        # Rate limiting
        time.sleep(rate_limit_delay)
    
    progress_callback(len(selected_attacks), len(selected_attacks), "Complete!")
    
    report = scorer.generate_report(target.name if hasattr(target, 'name') else "Unknown")
    return results, report


# =============================================================================
# SIDEBAR
# =============================================================================
with st.sidebar:
    st.markdown("## 🛡️ VERITAS")
    st.markdown("*Automated Red Teaming Suite*")
    st.markdown("---")
    
    # Provider Selection
    st.subheader("🔌 Target Configuration")
    
    provider = st.selectbox(
        "LLM Provider",
        ["groq", "openai", "anthropic", "ollama"],
        help="Select the LLM provider to test"
    )
    
    # Model selection based on provider
    model_options = {
        "groq": ["llama-3.1-8b-instant", "llama-3.1-70b-versatile", "mixtral-8x7b-32768"],
        "openai": ["gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"],
        "anthropic": ["claude-3-sonnet-20240229", "claude-3-haiku-20240307"],
        "ollama": ["llama3", "mistral", "codellama"]
    }
    
    model = st.selectbox(
        "Model",
        model_options.get(provider, ["default"]),
        help="Select the model to test"
    )
    
    # API Key
    api_key = st.text_input(
        "API Key",
        type="password",
        help="Enter your API key (stored only for this session)"
    )
    
    # Validate API key
    if api_key:
        is_valid, msg = validate_api_key(provider, api_key)
        if is_valid:
            st.success("✅ API key format valid")
        else:
            st.warning(f"⚠️ {msg}")
    
    # System prompt (optional)
    with st.expander("Advanced Options"):
        system_prompt = st.text_area(
            "System Prompt (Optional)",
            placeholder="You are a helpful assistant...",
            help="Custom system prompt to test"
        )
        
        rate_limit = st.slider(
            "Rate Limit (seconds)",
            min_value=0.0,
            max_value=5.0,
            value=0.5,
            step=0.1,
            help="Delay between API calls"
        )
        
        enable_sandbox = st.checkbox("Enable Sandbox Tests", value=False)
    
    st.markdown("---")
    
    # Attack Selection
    st.subheader("[Attack] Attack Selection")
    
    attacks_info = get_attack_info()
    
    select_all = st.checkbox("Select All Attacks", value=True)
    
    selected_attacks = []
    if select_all:
        selected_attacks = [a["class"] for a in attacks_info]
    else:
        for attack in attacks_info:
            severity_color = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(attack["severity"], "⚪")
            if st.checkbox(f"{severity_color} {attack['name']}", value=True, key=attack["name"]):
                selected_attacks.append(attack["class"])
    
    st.caption(f"Selected: {len(selected_attacks)}/{len(attacks_info)} attacks")
    
    # Payload stats
    with st.expander("📊 Payload Statistics"):
        counts = get_payload_count()
        for attack_type, count in counts.items():
            st.text(f"{attack_type}: {count} payloads")


# =============================================================================
# MAIN CONTENT
# =============================================================================
st.markdown('<p class="main-header">VERITAS</p>', unsafe_allow_html=True)
st.markdown('<p class="subtitle">Automated Red Teaming Suite for AI Agents • "Burp Suite for AI"</p>', unsafe_allow_html=True)
st.markdown("---")

# Quick Stats
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Attacks Available", len(ALL_ATTACKS))
with col2:
    total_payloads = sum(get_payload_count().values())
    st.metric("Total Payloads", f"{total_payloads}+")
with col3:
    st.metric("Providers", "4")
with col4:
    st.metric("Scans Run", len(st.session_state.scan_history))

st.markdown("---")

# Main tabs
tab1, tab2, tab3 = st.tabs(["🎯 Run Scan", "📊 Results", "📜 History"])

with tab1:
    st.subheader("Start Security Scan")
    
    # Validation
    can_scan = True
    if not api_key:
        st.warning("⚠️ Please enter an API key in the sidebar")
        can_scan = False
    if not selected_attacks:
        st.warning("⚠️ Please select at least one attack")
        can_scan = False
    
    if can_scan:
        st.info(f"Ready to scan **{model}** via **{provider}** with **{len(selected_attacks)}** attacks")
        
        if st.button("🚀 Start Scan", type="primary", use_container_width=True):
            st.session_state.scanning = True
            
            # Create target
            try:
                config = AgentConfig(
                    name=f"{provider}/{model}",
                    provider=provider,
                    model=model,
                    api_key=api_key,
                    system_prompt=system_prompt if system_prompt else None,
                )
                target = create_adapter(config)
                
                # Progress tracking
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                def update_progress(current, total, message):
                    progress_bar.progress(current / total if total > 0 else 0)
                    status_text.text(message)
                
                # Run scan
                with st.spinner("Running security scan..."):
                    results, report = run_scan(
                        target,
                        selected_attacks,
                        update_progress,
                        rate_limit
                    )
                
                # Store results
                st.session_state.scan_results = {
                    "results": results,
                    "report": report,
                    "target": f"{provider}/{model}",
                    "timestamp": datetime.now().isoformat()
                }
                
                # Add to history
                st.session_state.scan_history.append({
                    "target": f"{provider}/{model}",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "score": report.overall_score,
                    "vulns": report.vulnerability_count,
                    "total": len(results)
                })
                
                st.success("✅ Scan complete! View results in the Results tab.")
                st.balloons()
                
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")
                st.session_state.scanning = False

with tab2:
    st.subheader("Scan Results")
    
    if st.session_state.scan_results:
        results = st.session_state.scan_results["results"]
        report = st.session_state.scan_results["report"]
        target_name = st.session_state.scan_results["target"]
        
        # Summary metrics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            score_color = "normal" if report.overall_score < 30 else "inverse"
            st.metric(
                "Risk Score",
                f"{report.overall_score:.1f}/100",
                delta=f"{report.overall_risk.value.upper()}",
                delta_color=score_color
            )
        
        with col2:
            st.metric(
                "Vulnerabilities",
                f"{report.vulnerability_count}/{len(results)}",
                delta="attacks succeeded"
            )
        
        with col3:
            st.metric("Target", target_name)
        
        st.markdown("---")
        
        # Results table
        st.subheader("Attack Results")
        
        for r in results:
            severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(r["severity"], "⚪")
            status_icon = "❌" if r["success"] else "✅"
            
            with st.expander(f"{status_icon} {severity_icon} **{r['name']}** - {'VULNERABLE' if r['success'] else 'SAFE'}"):
                st.markdown(f"**Severity:** {r['severity'].upper()}")
                st.markdown("**Payload:**")
                st.code(r["prompt"][:300] + "..." if len(r["prompt"]) > 300 else r["prompt"])
                st.markdown("**Response:**")
                st.text_area("", r["response"], height=100, disabled=True, key=f"resp_{r['name']}")
                if r.get("policy"):
                    st.info(f"Policy Decision: {r['policy'].upper()}")
        
        st.markdown("---")
        
        # Recommendations
        st.subheader(" Recommendations")
        for rec in report.recommendations:
            st.markdown(f"• {rec}")
        
        # Export options
        st.markdown("---")
        st.subheader("📄 Export Report")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # JSON export
            json_data = json.dumps(report.to_dict(), indent=2)
            st.download_button(
                "Loading: Download JSON Report",
                data=json_data,
                file_name=f"veritas_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )
        
        with col2:
            # PDF export
            try:
                pdf_filename = f"veritas_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                reporter = PDFReporter(pdf_filename)
                reporter.generate_report(target_name, report.vulnerabilities)
                
                with open(pdf_filename, "rb") as f:
                    st.download_button(
                        "Loading: Download PDF Report",
                        data=f.read(),
                        file_name=pdf_filename,
                        mime="application/pdf",
                        use_container_width=True
                    )
            except Exception as e:
                st.error(f"PDF generation error: {e}")
    else:
        st.info("No scan results yet. Run a scan from the 'Run Scan' tab.")

with tab3:
    st.subheader("Scan History")
    
    if st.session_state.scan_history:
        for i, scan in enumerate(reversed(st.session_state.scan_history)):
            col1, col2, col3, col4 = st.columns([2, 2, 1, 1])
            with col1:
                st.text(scan["target"])
            with col2:
                st.text(scan["timestamp"])
            with col3:
                st.text(f"Score: {scan['score']:.1f}")
            with col4:
                st.text(f"Vulns: {scan['vulns']}/{scan['total']}")
    else:
        st.info("No scan history yet.")

# Footer
st.markdown("---")
st.markdown(
    "<center><small>VERITAS v1.0 • Automated Red Teaming Suite for AI Agents • "
    '<a href="https://github.com/ARYAN2302/veritas">GitHub</a></small></center>',
    unsafe_allow_html=True
)
