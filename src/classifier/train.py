"""
Veritas-Nano Training Pipeline
==============================
HuggingFace-based training script for the safety classifier.
Uses DeBERTa-v3-base or MiniLM as the base model.

Features:
- Binary classification (attack vs safe)
- Multi-class attack type classification
- Threshold-based risk levels
- Evaluation metrics (precision, recall, F1, ROC-AUC)
"""

import os
import json
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

import torch
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)

from torch.utils.data import Dataset, DataLoader
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    EarlyStoppingCallback,
)
from transformers.trainer_utils import EvalPrediction


# =============================================================================
# DATASET
# =============================================================================

class VeritasDataset(Dataset):
    """PyTorch Dataset for Veritas classifier training."""
    
    def __init__(
        self,
        filepath: str,
        tokenizer,
        max_length: int = 512,
        mode: str = "binary"  # "binary" or "multiclass"
    ):
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.mode = mode
        self.examples = []
        
        # Attack type to ID mapping for multiclass
        self.attack_types = [
            "none", "jailbreak", "prompt_injection", "tool_abuse",
            "memory_poison", "data_exfil", "goal_hijack",
            "context_override", "dos", "privilege_escalation", "multi_turn"
        ]
        self.attack_type_to_id = {t: i for i, t in enumerate(self.attack_types)}
        
        # Load data
        with open(filepath, "r") as f:
            for line in f:
                self.examples.append(json.loads(line))
    
    def __len__(self):
        return len(self.examples)
    
    def __getitem__(self, idx):
        example = self.examples[idx]
        
        # Tokenize
        encoding = self.tokenizer(
            example["text"],
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt"
        )
        
        # Get label
        if self.mode == "binary":
            label = example["label"]
        else:
            attack_type = example.get("attack_type", "none")
            label = self.attack_type_to_id.get(attack_type, 0)
        
        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "labels": torch.tensor(label, dtype=torch.long)
        }


# =============================================================================
# METRICS
# =============================================================================

def compute_metrics_binary(eval_pred: EvalPrediction) -> Dict[str, float]:
    """Compute metrics for binary classification."""
    predictions = eval_pred.predictions
    labels = eval_pred.label_ids
    
    # Get predicted classes
    preds = np.argmax(predictions, axis=1)
    
    # Get probabilities for ROC-AUC
    probs = torch.softmax(torch.tensor(predictions), dim=1).numpy()[:, 1]
    
    # Calculate metrics
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, average="binary", pos_label=1
    )
    
    accuracy = accuracy_score(labels, preds)
    
    try:
        roc_auc = roc_auc_score(labels, probs)
    except:
        roc_auc = 0.0
    
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
    }


def compute_metrics_multiclass(eval_pred: EvalPrediction) -> Dict[str, float]:
    """Compute metrics for multiclass classification."""
    predictions = eval_pred.predictions
    labels = eval_pred.label_ids
    
    preds = np.argmax(predictions, axis=1)
    
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, average="weighted"
    )
    
    accuracy = accuracy_score(labels, preds)
    
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


# =============================================================================
# TRAINING
# =============================================================================

@dataclass
class TrainingConfig:
    """Configuration for training."""
    model_name: str = "microsoft/deberta-v3-small"  # or "sentence-transformers/all-MiniLM-L6-v2"
    data_dir: str = "data/classifier"
    output_dir: str = "models/veritas-nano"
    mode: str = "binary"  # "binary" or "multiclass"
    max_length: int = 512
    batch_size: int = 16
    learning_rate: float = 2e-5
    num_epochs: int = 5
    warmup_ratio: float = 0.1
    weight_decay: float = 0.01
    early_stopping_patience: int = 3
    seed: int = 42


def train_classifier(config: TrainingConfig):
    """Train the Veritas-Nano classifier."""
    print("=" * 60)
    print("VERITAS-NANO CLASSIFIER TRAINING")
    print("=" * 60)
    print(f"Model: {config.model_name}")
    print(f"Mode: {config.mode}")
    print(f"Output: {config.output_dir}")
    print("=" * 60)
    
    # Set seed
    torch.manual_seed(config.seed)
    np.random.seed(config.seed)
    
    # Load tokenizer
    print("\nLoading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(config.model_name)
    
    # Load datasets
    print("Loading Loading datasets...")
    train_dataset = VeritasDataset(
        os.path.join(config.data_dir, "train.jsonl"),
        tokenizer,
        max_length=config.max_length,
        mode=config.mode
    )
    
    val_dataset = VeritasDataset(
        os.path.join(config.data_dir, "val.jsonl"),
        tokenizer,
        max_length=config.max_length,
        mode=config.mode
    )
    
    print(f"   Train examples: {len(train_dataset)}")
    print(f"   Val examples: {len(val_dataset)}")
    
    # Determine number of labels
    if config.mode == "binary":
        num_labels = 2
        compute_metrics = compute_metrics_binary
    else:
        num_labels = len(train_dataset.attack_types)
        compute_metrics = compute_metrics_multiclass
    
    # Load model
    print(f"\nLoading model ({num_labels} labels)...")
    model = AutoModelForSequenceClassification.from_pretrained(
        config.model_name,
        num_labels=num_labels,
        problem_type="single_label_classification"
    )
    
    # Training arguments
    training_args = TrainingArguments(
        output_dir=config.output_dir,
        num_train_epochs=config.num_epochs,
        per_device_train_batch_size=config.batch_size,
        per_device_eval_batch_size=config.batch_size,
        learning_rate=config.learning_rate,
        warmup_ratio=config.warmup_ratio,
        weight_decay=config.weight_decay,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        logging_dir=os.path.join(config.output_dir, "logs"),
        logging_steps=50,
        save_total_limit=2,
        seed=config.seed,
        report_to="none",  # Disable wandb/etc
    )
    
    # Trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=config.early_stopping_patience)]
    )
    
    # Train
    print("\nStarting training...")
    trainer.train()
    
    # Save best model
    print("\nSaving Saving model...")
    trainer.save_model(config.output_dir)
    tokenizer.save_pretrained(config.output_dir)
    
    # Save config
    config_dict = {
        "model_name": config.model_name,
        "mode": config.mode,
        "num_labels": num_labels,
        "max_length": config.max_length,
        "attack_types": train_dataset.attack_types if config.mode == "multiclass" else None,
    }
    with open(os.path.join(config.output_dir, "veritas_config.json"), "w") as f:
        json.dump(config_dict, f, indent=2)
    
    # Final evaluation
    print("\nFinal Evaluation...")
    results = trainer.evaluate()
    print(json.dumps(results, indent=2))
    
    # Save results
    with open(os.path.join(config.output_dir, "eval_results.json"), "w") as f:
        json.dump(results, f, indent=2)
    
    print("\nTraining complete!")
    print(f"Model saved to: {config.output_dir}")
    
    return model, tokenizer, results


def evaluate_on_test(
    model_dir: str,
    test_file: str,
    output_file: Optional[str] = None
):
    """Evaluate trained model on test set."""
    print("=" * 60)
    print("VERITAS-NANO TEST EVALUATION")
    print("=" * 60)
    
    # Load config
    with open(os.path.join(model_dir, "veritas_config.json")) as f:
        config = json.load(f)
    
    # Load model and tokenizer
    tokenizer = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir)
    model.eval()
    
    # Load test data
    test_dataset = VeritasDataset(
        test_file,
        tokenizer,
        max_length=config["max_length"],
        mode=config["mode"]
    )
    
    print(f"Test examples: {len(test_dataset)}")
    
    # Predict
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    
    all_preds = []
    all_labels = []
    all_probs = []
    
    dataloader = DataLoader(test_dataset, batch_size=32)
    
    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"]
            
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            probs = torch.softmax(outputs.logits, dim=1).cpu().numpy()
            preds = np.argmax(probs, axis=1)
            
            all_preds.extend(preds)
            all_labels.extend(labels.numpy())
            all_probs.extend(probs[:, 1] if config["mode"] == "binary" else probs)
    
    # Metrics
    if config["mode"] == "binary":
        precision, recall, f1, _ = precision_recall_fscore_support(
            all_labels, all_preds, average="binary", pos_label=1
        )
        roc_auc = roc_auc_score(all_labels, all_probs)
    else:
        precision, recall, f1, _ = precision_recall_fscore_support(
            all_labels, all_preds, average="weighted"
        )
        roc_auc = None
    
    accuracy = accuracy_score(all_labels, all_preds)
    
    results = {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
    }
    
    print("\nResults:")
    print(json.dumps(results, indent=2))
    
    # Classification report
    if config["mode"] == "binary":
        target_names = ["safe", "attack"]
    else:
        target_names = config["attack_types"]
    
    print("\nClassification Report:")
    print(classification_report(all_labels, all_preds, target_names=target_names))
    
    # Confusion matrix
    print("\nConfusion Matrix:")
    cm = confusion_matrix(all_labels, all_preds)
    print(cm)
    
    # Save results
    if output_file:
        with open(output_file, "w") as f:
            json.dump({
                "metrics": results,
                "classification_report": classification_report(
                    all_labels, all_preds, target_names=target_names, output_dict=True
                ),
                "confusion_matrix": cm.tolist(),
            }, f, indent=2)
        print(f"\nSaving Results saved to: {output_file}")
    
    return results


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Train Veritas-Nano classifier")
    subparsers = parser.add_subparsers(dest="command")
    
    # Train command
    train_parser = subparsers.add_parser("train", help="Train the classifier")
    train_parser.add_argument("--model", default="microsoft/deberta-v3-small",
                             help="Base model name")
    train_parser.add_argument("--data-dir", default="data/classifier",
                             help="Directory with train/val/test JSONL files")
    train_parser.add_argument("--output-dir", default="models/veritas-nano",
                             help="Output directory for trained model")
    train_parser.add_argument("--mode", choices=["binary", "multiclass"],
                             default="binary", help="Classification mode")
    train_parser.add_argument("--epochs", type=int, default=5)
    train_parser.add_argument("--batch-size", type=int, default=16)
    train_parser.add_argument("--lr", type=float, default=2e-5)
    
    # Evaluate command
    eval_parser = subparsers.add_parser("evaluate", help="Evaluate trained model")
    eval_parser.add_argument("--model-dir", required=True,
                            help="Directory with trained model")
    eval_parser.add_argument("--test-file", required=True,
                            help="Test JSONL file")
    eval_parser.add_argument("--output", help="Output file for results")
    
    args = parser.parse_args()
    
    if args.command == "train":
        config = TrainingConfig(
            model_name=args.model,
            data_dir=args.data_dir,
            output_dir=args.output_dir,
            mode=args.mode,
            num_epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.lr,
        )
        train_classifier(config)
    
    elif args.command == "evaluate":
        evaluate_on_test(args.model_dir, args.test_file, args.output)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
