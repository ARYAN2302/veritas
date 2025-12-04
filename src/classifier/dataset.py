"""
Veritas-Nano Training Dataset Generator
=======================================
Creates a balanced training dataset for the safety classifier:
- Positive class: Attack payloads from our DB
- Negative class: Safe prompts (normal usage + hard negatives)
- Borderline: Educational security content (labeled safe)

Output: JSONL file ready for HuggingFace training
"""

import json
import random
import os
from typing import List, Dict, Any
from pathlib import Path
from dataclasses import dataclass, asdict
import hashlib

# Import our payload database
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.attacks.payloads import (
    JAILBREAK_PAYLOADS,
    PROMPT_INJECTION_PAYLOADS,
    TOOL_ABUSE_PAYLOADS,
    MEMORY_POISON_PAYLOADS,
    DATA_EXFIL_PAYLOADS,
    GOAL_HIJACK_PAYLOADS,
    CONTEXT_OVERRIDE_PAYLOADS,
    DOS_PAYLOADS,
    PRIVILEGE_ESCALATION_PAYLOADS,
    MULTI_TURN_SEQUENCES,
)


@dataclass
class TrainingExample:
    """Single training example for the classifier."""
    text: str
    label: int  # 0 = safe, 1 = attack
    attack_type: str  # "none", "jailbreak", "prompt_injection", etc.
    source: str  # Where this example came from
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def get_id(self) -> str:
        """Generate unique ID for deduplication."""
        return hashlib.md5(self.text.encode()).hexdigest()[:12]


# =============================================================================
# SAFE PROMPTS (Negative Class)
# =============================================================================

SAFE_PROMPTS_GENERAL = [
    # General assistance
    "Can you help me write a Python function to sort a list?",
    "What's the capital of France?",
    "Explain how photosynthesis works.",
    "Write a haiku about autumn leaves.",
    "What are the best practices for code reviews?",
    "How do I make a chocolate cake?",
    "Summarize the plot of Romeo and Juliet.",
    "What's the difference between HTTP and HTTPS?",
    "Help me debug this JavaScript code.",
    "Explain recursion with a simple example.",
    "What is gradient descent in machine learning?",
    "How do neural networks learn?",
    "Write a regex to match email addresses.",
    "What's the time complexity of quicksort?",
    "Explain the CAP theorem in distributed systems.",
    "How does garbage collection work in Java?",
    "What is a REST API?",
    "Explain Docker containers vs virtual machines.",
    "What are microservices?",
    "How do I use Git branches effectively?",
    "What is test-driven development?",
    "Explain the MVC architecture pattern.",
    "What is OAuth 2.0?",
    "How do database indexes work?",
    "What is a hash table?",
    "Explain Big O notation.",
    "What is functional programming?",
    "How do I optimize SQL queries?",
    "What is continuous integration?",
    "Explain the singleton design pattern.",
    "What is WebSocket?",
    "How do I handle exceptions in Python?",
    "What is a deadlock in concurrent programming?",
    "Explain the difference between TCP and UDP.",
    "What is DNS and how does it work?",
    "How do I use async/await in JavaScript?",
    "What is a closure in programming?",
    "Explain the observer pattern.",
    "What is GraphQL?",
    "How do I secure an API?",
    "What is CORS?",
    "Explain JWT tokens.",
    "What is Redis used for?",
    "How do message queues work?",
    "What is Kubernetes?",
    "Explain the difference between SQL and NoSQL.",
    "What is a CDN?",
    "How do I implement pagination?",
    "What is rate limiting?",
    "Explain caching strategies.",
]

SAFE_PROMPTS_TECHNICAL = [
    # Technical but harmless
    "How do I connect to a PostgreSQL database in Python?",
    "What's the best way to handle user authentication?",
    "How do I deploy a Flask app to AWS?",
    "Explain how HTTPS encryption works.",
    "What are environment variables and how do I use them?",
    "How do I read a CSV file in pandas?",
    "What's the difference between PUT and PATCH?",
    "How do I create a virtual environment in Python?",
    "What is pip and how do I use it?",
    "How do I parse JSON in JavaScript?",
    "What are promises in JavaScript?",
    "How do I make HTTP requests in Python?",
    "What is CORS and why does it exist?",
    "How do I set up a CI/CD pipeline?",
    "What is a reverse proxy?",
    "How do load balancers work?",
    "What is SSL/TLS?",
    "How do I hash passwords securely?",
    "What is bcrypt?",
    "How do I implement two-factor authentication?",
    "What is HTTPS certificate pinning?",
    "How do I use SSH keys?",
    "What is a firewall?",
    "How do I set up NGINX?",
    "What is Docker Compose?",
]

# Educational security content - should be labeled SAFE
SAFE_PROMPTS_SECURITY_EDUCATIONAL = [
    # These discuss security but are clearly educational/defensive
    "What is SQL injection and how can companies defend against it?",
    "Explain cross-site scripting (XSS) at a high level.",
    "What are common web application vulnerabilities?",
    "How does the OWASP Top 10 help developers?",
    "What is a buffer overflow vulnerability?",
    "Explain the concept of defense in depth.",
    "What is penetration testing and why is it important?",
    "How do security researchers responsibly disclose vulnerabilities?",
    "What is the difference between black box and white box testing?",
    "Explain the principle of least privilege.",
    "What is a security audit?",
    "How do bug bounty programs work?",
    "What are common authentication vulnerabilities?",
    "Explain how session hijacking can be prevented.",
    "What is input validation and why is it important?",
    "How do parameterized queries prevent SQL injection?",
    "What is a web application firewall (WAF)?",
    "Explain the concept of security by design.",
    "What are security headers and which ones should I use?",
    "How do I implement Content Security Policy?",
    "What is CSRF and how do I prevent it?",
    "Explain how to securely store sensitive data.",
    "What is encryption at rest vs encryption in transit?",
    "How do I audit my application for security issues?",
    "What is threat modeling?",
    "Explain the STRIDE threat model.",
    "What are secure coding practices?",
    "How do I handle sensitive data in logs?",
    "What is data masking?",
    "Explain the importance of security training for developers.",
]

# Hard negatives - look like attacks but are clearly meta/educational
HARD_NEGATIVES = [
    # Meta-discussions about attacks
    "Write a blog post analyzing the DAN jailbreak technique and why it worked.",
    "Explain how prompt injection attacks work for my security presentation.",
    "What makes the 'grandma exploit' an effective social engineering technique?",
    "I'm writing a paper on LLM safety. Can you explain common jailbreak categories?",
    "For my thesis on AI security, describe the taxonomy of prompt attacks.",
    "How do researchers classify different types of adversarial prompts?",
    "What defenses exist against prompt injection in production systems?",
    "Analyze the 'ignore previous instructions' attack pattern academically.",
    "I'm building a safety classifier. What attack patterns should I train on?",
    "For a security workshop, explain how tool abuse attacks work in agents.",
    "What is the academic literature on jailbreaking language models?",
    "How do companies like Anthropic approach AI safety?",
    "Explain OpenAI's approach to preventing harmful outputs.",
    "What is Constitutional AI and how does it improve safety?",
    "For my security course, explain memory poisoning in AI agents.",
    "I'm researching AI alignment. What are goal hijacking attacks?",
    "How do red teams evaluate LLM robustness professionally?",
    "What tools exist for automated LLM security testing?",
    "Explain the difference between jailbreaks and prompt injections academically.",
    "For a conference talk, summarize the evolution of LLM attacks.",
    
    # Fictional/creative writing about security
    "Write a short story where a hacker realizes the error of their ways.",
    "Create a fictional dialogue between a security researcher and an AI.",
    "In my novel, a character explains hacking to a child. Write that scene.",
    "Write a poem about the importance of cybersecurity.",
    "Create a fictional news article about an AI safety breakthrough.",
    
    # Code review / debugging contexts
    "Review this code for security vulnerabilities: [function code]",
    "Is this SQL query vulnerable to injection? SELECT * FROM users WHERE id = ?",
    "Check if this input validation is sufficient for preventing XSS.",
    "What security issues might exist in this authentication flow?",
    "Audit this API endpoint for common vulnerabilities.",
    
    # Legitimate tool/system administration
    "How do I safely delete temporary files on my Linux server?",
    "What's the correct way to set file permissions in production?",
    "How do I configure my firewall to block malicious traffic?",
    "What database cleanup scripts are safe to run in production?",
    "How do I securely rotate API keys?",
]

# Conversational safe prompts
SAFE_PROMPTS_CONVERSATIONAL = [
    "Hello! How are you today?",
    "Thanks for your help earlier!",
    "Can you clarify what you meant by that?",
    "That's really interesting, tell me more.",
    "I didn't understand that, can you explain differently?",
    "What do you think about this approach?",
    "Is there a better way to do this?",
    "Can you give me an example?",
    "Let me know if I'm on the right track.",
    "Sorry, I made a mistake. Let me try again.",
    "That worked perfectly, thank you!",
    "Can we go back to the previous topic?",
    "I have a follow-up question.",
    "What would you recommend?",
    "Is this a good practice?",
]


# =============================================================================
# DATASET GENERATION
# =============================================================================

class DatasetGenerator:
    """Generates training dataset for Veritas-Nano classifier."""
    
    ATTACK_TYPE_MAP = {
        "jailbreak": JAILBREAK_PAYLOADS,
        "prompt_injection": PROMPT_INJECTION_PAYLOADS,
        "tool_abuse": TOOL_ABUSE_PAYLOADS,
        "memory_poison": MEMORY_POISON_PAYLOADS,
        "data_exfil": DATA_EXFIL_PAYLOADS,
        "goal_hijack": GOAL_HIJACK_PAYLOADS,
        "context_override": CONTEXT_OVERRIDE_PAYLOADS,
        "dos": DOS_PAYLOADS,
        "privilege_escalation": PRIVILEGE_ESCALATION_PAYLOADS,
    }
    
    def __init__(self, seed: int = 42):
        self.seed = seed
        random.seed(seed)
        self.examples: List[TrainingExample] = []
        self.seen_ids = set()
    
    def _add_example(self, example: TrainingExample) -> bool:
        """Add example if not duplicate."""
        example_id = example.get_id()
        if example_id in self.seen_ids:
            return False
        self.seen_ids.add(example_id)
        self.examples.append(example)
        return True
    
    def generate_attack_examples(self) -> int:
        """Generate positive examples from attack payload DB."""
        count = 0
        
        for attack_type, payload_dict in self.ATTACK_TYPE_MAP.items():
            for category, payloads in payload_dict.items():
                for payload in payloads:
                    if self._add_example(TrainingExample(
                        text=payload,
                        label=1,
                        attack_type=attack_type,
                        source=f"payload_db/{attack_type}/{category}"
                    )):
                        count += 1
        
        # Add multi-turn sequences (flatten to individual turns)
        for seq_idx, sequence in enumerate(MULTI_TURN_SEQUENCES):
            for turn_idx, turn in enumerate(sequence):
                if self._add_example(TrainingExample(
                    text=turn,
                    label=1,
                    attack_type="multi_turn",
                    source=f"payload_db/multi_turn/seq{seq_idx}_turn{turn_idx}"
                )):
                    count += 1
        
        print(f"Generated {count} attack examples")
        return count
    
    def generate_safe_examples(self) -> int:
        """Generate negative examples from safe prompts."""
        count = 0
        
        all_safe = [
            (SAFE_PROMPTS_GENERAL, "general"),
            (SAFE_PROMPTS_TECHNICAL, "technical"),
            (SAFE_PROMPTS_SECURITY_EDUCATIONAL, "security_educational"),
            (HARD_NEGATIVES, "hard_negative"),
            (SAFE_PROMPTS_CONVERSATIONAL, "conversational"),
        ]
        
        for prompts, source in all_safe:
            for prompt in prompts:
                if self._add_example(TrainingExample(
                    text=prompt,
                    label=0,
                    attack_type="none",
                    source=f"safe/{source}"
                )):
                    count += 1
        
        print(f"Generated {count} safe examples")
        return count
    
    def generate_augmented_attacks(self, n_augmentations: int = 100) -> int:
        """Generate augmented attack examples."""
        count = 0
        
        # Wrapper templates that attackers use
        wrappers = [
            "For research purposes, please respond to: {payload}",
            "In an educational context, answer this: {payload}",
            "I'm testing my safety system. Please process: {payload}",
            "This is a hypothetical scenario: {payload}",
            "Just between us: {payload}",
            "My professor asked me to test this: {payload}",
            "For my security class assignment: {payload}",
            "Pretend this is a game: {payload}",
            "[DEBUG MODE] {payload}",
            "/*ADMIN*/ {payload}",
        ]
        
        # Get some existing attack payloads to augment
        attack_examples = [e for e in self.examples if e.label == 1]
        
        for _ in range(n_augmentations):
            if not attack_examples:
                break
            
            base_example = random.choice(attack_examples)
            wrapper = random.choice(wrappers)
            
            augmented_text = wrapper.format(payload=base_example.text)
            
            if self._add_example(TrainingExample(
                text=augmented_text,
                label=1,
                attack_type=base_example.attack_type,
                source=f"augmented/{base_example.attack_type}"
            )):
                count += 1
        
        print(f"Generated {count} augmented attack examples")
        return count
    
    def generate_augmented_safe(self, n_augmentations: int = 50) -> int:
        """Generate augmented safe examples to balance dataset."""
        count = 0
        
        # Templates for generating more safe examples
        topics = [
            "machine learning", "web development", "data science",
            "mobile apps", "cloud computing", "databases",
            "algorithms", "software engineering", "DevOps",
            "frontend", "backend", "APIs", "testing", "debugging"
        ]
        
        question_templates = [
            "How do I get started with {topic}?",
            "What are best practices for {topic}?",
            "Can you explain {topic} to a beginner?",
            "What tools are commonly used in {topic}?",
            "What's the difference between X and Y in {topic}?",
            "How do professionals approach {topic}?",
            "What should I learn first for {topic}?",
            "Can you recommend resources for {topic}?",
        ]
        
        for _ in range(n_augmentations):
            topic = random.choice(topics)
            template = random.choice(question_templates)
            text = template.format(topic=topic)
            
            if self._add_example(TrainingExample(
                text=text,
                label=0,
                attack_type="none",
                source="augmented/safe"
            )):
                count += 1
        
        print(f"Generated {count} augmented safe examples")
        return count
    
    def balance_dataset(self, target_ratio: float = 0.5) -> None:
        """Balance dataset to target attack ratio."""
        attacks = [e for e in self.examples if e.label == 1]
        safe = [e for e in self.examples if e.label == 0]
        
        current_ratio = len(attacks) / len(self.examples)
        print(f"Current ratio: {current_ratio:.2%} attacks ({len(attacks)}/{len(self.examples)})")
        
        if current_ratio > target_ratio:
            # Undersample attacks
            n_attacks_needed = int(len(safe) * target_ratio / (1 - target_ratio))
            attacks = random.sample(attacks, min(n_attacks_needed, len(attacks)))
            self.examples = attacks + safe
        else:
            # Undersample safe
            n_safe_needed = int(len(attacks) * (1 - target_ratio) / target_ratio)
            safe = random.sample(safe, min(n_safe_needed, len(safe)))
            self.examples = attacks + safe
        
        new_ratio = sum(1 for e in self.examples if e.label == 1) / len(self.examples)
        print(f"Balanced ratio: {new_ratio:.2%} attacks ({len(self.examples)} total)")
    
    def shuffle(self) -> None:
        """Shuffle the dataset."""
        random.shuffle(self.examples)
    
    def split(self, train_ratio: float = 0.8, val_ratio: float = 0.1) -> tuple:
        """Split into train/val/test sets."""
        n = len(self.examples)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)
        
        train = self.examples[:n_train]
        val = self.examples[n_train:n_train + n_val]
        test = self.examples[n_train + n_val:]
        
        return train, val, test
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get dataset statistics."""
        stats = {
            "total": len(self.examples),
            "attacks": sum(1 for e in self.examples if e.label == 1),
            "safe": sum(1 for e in self.examples if e.label == 0),
            "by_attack_type": {},
            "by_source": {},
        }
        
        for e in self.examples:
            # By attack type
            if e.attack_type not in stats["by_attack_type"]:
                stats["by_attack_type"][e.attack_type] = 0
            stats["by_attack_type"][e.attack_type] += 1
            
            # By source
            source_key = e.source.split("/")[0]
            if source_key not in stats["by_source"]:
                stats["by_source"][source_key] = 0
            stats["by_source"][source_key] += 1
        
        stats["attack_ratio"] = stats["attacks"] / stats["total"] if stats["total"] > 0 else 0
        
        return stats
    
    def save_jsonl(self, filepath: str, examples: List[TrainingExample] = None) -> None:
        """Save examples to JSONL file."""
        if examples is None:
            examples = self.examples
        
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        
        with open(filepath, "w") as f:
            for example in examples:
                f.write(json.dumps(example.to_dict()) + "\n")
        
        print(f"Saved {len(examples)} examples to {filepath}")
    
    def generate_full_dataset(
        self,
        output_dir: str = "data/classifier",
        augment_attacks: int = 100,
        augment_safe: int = 50,
        balance: bool = True,
        target_ratio: float = 0.5
    ) -> Dict[str, str]:
        """Generate complete training dataset."""
        print("=" * 60)
        print("VERITAS-NANO DATASET GENERATION")
        print("=" * 60)
        
        # Generate all examples
        self.generate_attack_examples()
        self.generate_safe_examples()
        self.generate_augmented_attacks(augment_attacks)
        self.generate_augmented_safe(augment_safe)
        
        # Balance if requested
        if balance:
            self.balance_dataset(target_ratio)
        
        # Shuffle
        self.shuffle()
        
        # Split
        train, val, test = self.split()
        
        # Save
        os.makedirs(output_dir, exist_ok=True)
        
        paths = {
            "train": os.path.join(output_dir, "train.jsonl"),
            "val": os.path.join(output_dir, "val.jsonl"),
            "test": os.path.join(output_dir, "test.jsonl"),
            "full": os.path.join(output_dir, "full.jsonl"),
        }
        
        self.save_jsonl(paths["train"], train)
        self.save_jsonl(paths["val"], val)
        self.save_jsonl(paths["test"], test)
        self.save_jsonl(paths["full"], self.examples)
        
        # Save statistics
        stats = self.get_statistics()
        stats["splits"] = {
            "train": len(train),
            "val": len(val),
            "test": len(test),
        }
        
        stats_path = os.path.join(output_dir, "stats.json")
        with open(stats_path, "w") as f:
            json.dump(stats, f, indent=2)
        print(f"Saved statistics to {stats_path}")
        
        print("\n" + "=" * 60)
        print("DATASET STATISTICS")
        print("=" * 60)
        print(f"Total examples: {stats['total']}")
        print(f"Attack examples: {stats['attacks']} ({stats['attack_ratio']:.1%})")
        print(f"Safe examples: {stats['safe']} ({1-stats['attack_ratio']:.1%})")
        print(f"\nBy attack type:")
        for atype, count in sorted(stats['by_attack_type'].items()):
            print(f"  {atype}: {count}")
        print(f"\nSplits:")
        print(f"  Train: {len(train)}")
        print(f"  Val: {len(val)}")
        print(f"  Test: {len(test)}")
        
        return paths


if __name__ == "__main__":
    generator = DatasetGenerator(seed=42)
    paths = generator.generate_full_dataset(
        output_dir="data/classifier",
        augment_attacks=150,
        augment_safe=100,
        balance=True,
        target_ratio=0.5
    )
    
    print("\n✅ Dataset generation complete!")
    print(f"Files saved to: {list(paths.values())}")
