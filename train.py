"""
Model Training Script for Attack Forecasting Prototype
Trains the Plain BiLSTM with dual heads:
- Head 1: Current Stage Classification
- Head 2: Next Stage Forecasting
Saves trained weights, feature scaler, and reference background samples.
"""

import os
import pickle
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

from pipeline.dataset import build_temporal_dataset, STAGE_NAMES, NUM_STAGES
from models.attack_forecaster import AttackForecasterBiLSTM


def train_model():
    print("=" * 60)
    print("Step 1 & 2: Generating synthetic multi-stage attack flow sequences...")
    print("=" * 60)
    
    # Generate temporal dataset (T=10, 12 features)
    X, y_curr, y_next = build_temporal_dataset(num_timelines=300, sequence_length=10)
    print(f"Dataset generated: {X.shape[0]} sequences of shape {X.shape[1:]}")
    
    # Fit StandardScaler over all time steps
    N, T, D = X.shape
    X_flat = X.reshape(-1, D)
    scaler = StandardScaler()
    X_scaled_flat = scaler.fit_transform(X_flat)
    X_scaled = X_scaled_flat.reshape(N, T, D).astype(np.float32)
    
    # Train / validation split
    X_train, X_val, y_curr_tr, y_curr_val, y_next_tr, y_next_val = train_test_split(
        X_scaled, y_curr, y_next, test_size=0.2, random_state=42
    )
    
    train_dataset = TensorDataset(
        torch.tensor(X_train),
        torch.tensor(y_curr_tr),
        torch.tensor(y_next_tr)
    )
    val_dataset = TensorDataset(
        torch.tensor(X_val),
        torch.tensor(y_curr_val),
        torch.tensor(y_next_val)
    )
    
    train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=64, shuffle=False)
    
    print("\n" + "=" * 60)
    print("Step 3 & 4: Initializing & Training Dual-Head BiLSTM...")
    print("=" * 60)
    
    model = AttackForecasterBiLSTM(
        input_dim=D,
        hidden_dim=64,
        num_layers=2,
        num_classes=NUM_STAGES,
        dropout=0.2
    )
    
    criterion_curr = nn.CrossEntropyLoss()
    criterion_next = nn.CrossEntropyLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.003, weight_decay=1e-4)
    
    epochs = 15
    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        curr_correct = 0
        next_correct = 0
        total_samples = 0
        
        for batch_x, batch_curr, batch_next in train_loader:
            optimizer.zero_grad()
            curr_logits, next_logits = model(batch_x)
            
            loss_c = criterion_curr(curr_logits, batch_curr)
            loss_n = criterion_next(next_logits, batch_next)
            loss = loss_c + loss_n
            
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item() * batch_x.size(0)
            curr_correct += (curr_logits.argmax(dim=1) == batch_curr).sum().item()
            next_correct += (next_logits.argmax(dim=1) == batch_next).sum().item()
            total_samples += batch_x.size(0)
            
        train_loss = total_loss / total_samples
        train_curr_acc = curr_correct / total_samples
        train_next_acc = next_correct / total_samples
        
        # Validation
        model.eval()
        val_curr_correct = 0
        val_next_correct = 0
        val_samples = 0
        with torch.no_grad():
            for batch_x, batch_curr, batch_next in val_loader:
                curr_logits, next_logits = model(batch_x)
                val_curr_correct += (curr_logits.argmax(dim=1) == batch_curr).sum().item()
                val_next_correct += (next_logits.argmax(dim=1) == batch_next).sum().item()
                val_samples += batch_x.size(0)
                
        val_curr_acc = val_curr_correct / val_samples
        val_next_acc = val_next_correct / val_samples
        
        if epoch % 3 == 0 or epoch == epochs:
            print(
                f"Epoch {epoch:2d}/{epochs:2d} | "
                f"Loss: {train_loss:.4f} | "
                f"Curr Acc: {train_curr_acc*100:.1f}% (Val: {val_curr_acc*100:.1f}%) | "
                f"Next Acc: {train_next_acc*100:.1f}% (Val: {val_next_acc*100:.1f}%)"
            )

    # Save artifacts
    os.makedirs("models", exist_ok=True)
    os.makedirs("pipeline", exist_ok=True)
    
    weights_path = os.path.join("models", "bilstm_weights.pt")
    torch.save(model.state_dict(), weights_path)
    print(f"\nModel weights saved to: {weights_path}")
    
    scaler_path = os.path.join("pipeline", "scaler.pkl")
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)
    print(f"Scaler saved to: {scaler_path}")
    
    # Save baseline background flows for SHAP GradientExplainer
    bg_samples_path = os.path.join("pipeline", "background_samples.npy")
    np.save(bg_samples_path, X_scaled[:50])
    print(f"Background sample sequences saved to: {bg_samples_path}")
    
    print("\nTraining completed successfully!")


if __name__ == "__main__":
    train_model()
