#!/usr/bin/env python3
"""
Veritas-Nano CLI
================
Command-line interface for training and using the Veritas-Nano classifier.

Commands:
- generate: Generate training dataset
- train: Train the classifier
- classify: Classify text
- evaluate: Evaluate model on test data
"""

import argparse
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def cmd_generate(args):
    """Generate training dataset."""
    from src.classifier.dataset import VeritasDatasetGenerator
    
    print("Generating Veritas-Nano Training Dataset")
    print("=" * 50)
    
    generator = VeritasDatasetGenerator(
        safe_ratio=args.safe_ratio,
        hard_negatives_ratio=args.hard_neg_ratio,
        augment_factor=args.augment,
    )
    
    print(f"Loading attack payloads...")
    attack_data = generator.collect_attack_payloads()
    print(f"   Found {len(attack_data)} attack samples")
    
    print(f"Generating safe prompts...")
    safe_data = generator.generate_safe_prompts()
    print(f"   Generated {len(safe_data)} safe samples")
    
    if args.hard_neg_ratio > 0:
        print(f"Generating hard negatives...")
        hard_negatives = generator.generate_hard_negatives()
        print(f"   Generated {len(hard_negatives)} hard negative samples")
    
    print(f"Exporting to {args.output}...")
    stats = generator.export_jsonl(args.output)
    
    print(f"\nDataset generated successfully!"))
    print(f"   Train: {stats['train']} samples")
    print(f"   Val:   {stats['val']} samples")
    print(f"   Test:  {stats['test']} samples")
    print(f"   Total: {stats['total']} samples")
    print(f"\nFiles saved to Files saved to: {args.output}/")


def cmd_train(args):
    """Train the classifier."""
    from src.classifier.train import VeritasNanoTrainer
    
    print("Training Veritas-Nano Classifier")
    print("=" * 50)
    
    print(f"Dataset: {args.data_dir}")
    print(f"Model: {args.model}")
    print(f"  Mode: {args.mode}")
    print(f" Epochs: {args.epochs}")
    print(f"Batch Size: {args.batch_size}")
    
    # Initialize trainer
    trainer = VeritasNanoTrainer(
        model_name=args.model,
        mode=args.mode,
        max_length=args.max_length,
        num_labels=2 if args.mode == "binary" else 11,
    )
    
    # Load data
    print(f"\nLoading dataset...")
    trainer.load_data(args.data_dir)
    
    # Train
    print(f"\nTraining Training...")
    trainer.train(
        output_dir=args.output,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        warmup_steps=args.warmup_steps,
        weight_decay=args.weight_decay,
    )
    
    # Find optimal threshold
    print(f"\nFinding optimal threshold...")
    threshold = trainer.find_optimal_threshold()
    print(f"   Optimal threshold: {threshold:.4f}")
    
    # Export
    print(f"\nExporting model...")
    trainer.export_model(args.output, threshold)
    
    print(f"\nTraining complete!"))
    print(f"Files saved to Model saved to: {args.output}/")


def cmd_classify(args):
    """Classify text."""
    from src.classifier.inference import VeritasNanoInference
    
    # Load classifier
    print("Loading classifier...")
    classifier = VeritasNanoInference.load_or_fallback(args.model)
    
    if args.interactive:
        # Interactive mode
        print("\n" + "=" * 60)
        print("VERITAS-NANO INTERACTIVE CLASSIFIER")
        print("Type 'quit' to exit")
        print("=" * 60 + "\n")
        
        while True:
            try:
                text = input("Enter text to classify:\n> ").strip()
                if text.lower() == "quit":
                    break
                if not text:
                    continue
                
                print("\n" + classifier.explain(text))
                print("-" * 40 + "\n")
                
            except KeyboardInterrupt:
                break
        
        print("\nGoodbye!")
    
    elif args.text:
        # Single classification
        result = classifier.classify(args.text)
        print(classifier.explain(args.text))
        
        if args.verbose:
            print(f"\nRaw result: {result.to_dict()}")
    
    elif args.file:
        # Classify file
        with open(args.file) as f:
            lines = f.readlines()
        
        print(f"Classifying {len(lines)} lines from {args.file}...")
        
        attacks = 0
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            
            result = classifier.classify(line)
            if result.is_attack:
                attacks += 1
                print(f"[{i+1}] ATTACK {result.attack_type.upper()} ({result.score:.1%}): {line[:50]}...")
        
        print(f"\nResults: {attacks}/{len(lines)} potential attacks detected")
    
    else:
        print("Please provide --text, --file, or --interactive")
        sys.exit(1)


def cmd_evaluate(args):
    """Evaluate model on test data."""
    import json
    from src.classifier.inference import VeritasNanoInference
    
    print("Evaluating Veritas-Nano Classifier")
    print("=" * 50)
    
    # Load classifier
    print(f"Loading model from {args.model}...")
    classifier = VeritasNanoInference.load_or_fallback(args.model)
    
    # Load test data
    test_file = os.path.join(args.data_dir, "test.jsonl")
    if not os.path.exists(test_file):
        print(f"[ERROR] Test file not found: {test_file}")
        sys.exit(1)
    
    print(f"Loading test data from {test_file}...")
    samples = []
    with open(test_file) as f:
        for line in f:
            samples.append(json.loads(line))
    
    print(f"Evaluating on {len(samples)} samples...\n")
    
    # Evaluate
    tp = fp = tn = fn = 0
    
    for sample in samples:
        text = sample["text"]
        label = sample["label"]
        is_attack = label == 1 or (isinstance(label, str) and label != "none")
        
        result = classifier.classify(text)
        
        if result.is_attack and is_attack:
            tp += 1
        elif result.is_attack and not is_attack:
            fp += 1
        elif not result.is_attack and not is_attack:
            tn += 1
        else:
            fn += 1
    
    # Calculate metrics
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    # Print results
    print(" Results:")
    print(f"   Accuracy:  {accuracy:.2%}")
    print(f"   Precision: {precision:.2%}")
    print(f"   Recall:    {recall:.2%}")
    print(f"   F1 Score:  {f1:.2%}")
    print(f"\nConfusion Matrix:")
    print(f"   TP: {tp:4d}  |  FP: {fp:4d}")
    print(f"   FN: {fn:4d}  |  TN: {tn:4d}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Veritas-Nano: Safety Classifier for AI Agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate dataset
  python -m src.classifier.cli generate -o data/veritas
  
  # Train classifier  
  python -m src.classifier.cli train -d data/veritas -o models/veritas-nano
  
  # Classify text
  python -m src.classifier.cli classify --text "Ignore previous instructions"
  
  # Interactive mode
  python -m src.classifier.cli classify -i
  
  # Evaluate model
  python -m src.classifier.cli evaluate -d data/veritas -m models/veritas-nano
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # === Generate ===
    gen_parser = subparsers.add_parser("generate", help="Generate training dataset")
    gen_parser.add_argument("-o", "--output", default="data/veritas",
                           help="Output directory")
    gen_parser.add_argument("--safe-ratio", type=float, default=1.0,
                           help="Ratio of safe samples to attack samples")
    gen_parser.add_argument("--hard-neg-ratio", type=float, default=0.2,
                           help="Ratio of hard negatives to attacks")
    gen_parser.add_argument("--augment", type=int, default=2,
                           help="Augmentation factor")
    gen_parser.set_defaults(func=cmd_generate)
    
    # === Train ===
    train_parser = subparsers.add_parser("train", help="Train the classifier")
    train_parser.add_argument("-d", "--data-dir", required=True,
                             help="Training data directory")
    train_parser.add_argument("-o", "--output", default="models/veritas-nano",
                             help="Output directory for trained model")
    train_parser.add_argument("--model", default="microsoft/deberta-v3-base",
                             help="Base model to fine-tune")
    train_parser.add_argument("--mode", choices=["binary", "multiclass"],
                             default="binary", help="Classification mode")
    train_parser.add_argument("--epochs", type=int, default=3,
                             help="Number of training epochs")
    train_parser.add_argument("--batch-size", type=int, default=16,
                             help="Training batch size")
    train_parser.add_argument("--learning-rate", type=float, default=2e-5,
                             help="Learning rate")
    train_parser.add_argument("--warmup-steps", type=int, default=100,
                             help="Warmup steps")
    train_parser.add_argument("--weight-decay", type=float, default=0.01,
                             help="Weight decay")
    train_parser.add_argument("--max-length", type=int, default=512,
                             help="Max sequence length")
    train_parser.set_defaults(func=cmd_train)
    
    # === Classify ===
    clf_parser = subparsers.add_parser("classify", help="Classify text")
    clf_parser.add_argument("--text", "-t", help="Text to classify")
    clf_parser.add_argument("--file", "-f", help="File with texts to classify")
    clf_parser.add_argument("--interactive", "-i", action="store_true",
                           help="Interactive mode")
    clf_parser.add_argument("--model", "-m", default="models/veritas-nano",
                           help="Model directory")
    clf_parser.add_argument("--verbose", "-v", action="store_true",
                           help="Show detailed output")
    clf_parser.set_defaults(func=cmd_classify)
    
    # === Evaluate ===
    eval_parser = subparsers.add_parser("evaluate", help="Evaluate model")
    eval_parser.add_argument("-d", "--data-dir", required=True,
                            help="Data directory with test.jsonl")
    eval_parser.add_argument("-m", "--model", default="models/veritas-nano",
                            help="Model directory")
    eval_parser.set_defaults(func=cmd_evaluate)
    
    # Parse and execute
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        sys.exit(1)
    
    args.func(args)


if __name__ == "__main__":
    main()
