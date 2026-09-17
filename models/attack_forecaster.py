"""
Pipeline Step 3 & 4: Dual-Head BiLSTM for Attack Stage Classification & Forecasting
- Temporal Sequence Learning: 2-layer Bidirectional LSTM
- Output Head 1: Current Stage Classifier (Softmax over 5 stages)
- Output Head 2: Probabilistic Next-Stage Forecaster (Softmax transition distribution over candidate next stages)
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple, Dict, Any


class AttackForecasterBiLSTM(nn.Module):
    """
    Plain Bidirectional LSTM with dual heads:
    1. Current Stage Classifier Head
    2. Next-Stage Forecaster Head
    """
    def __init__(
        self,
        input_dim: int = 12,
        hidden_dim: int = 64,
        num_layers: int = 2,
        num_classes: int = 5,
        dropout: float = 0.2
    ):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.num_classes = num_classes

        # Bidirectional LSTM encoder
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0.0
        )
        
        # Combined representation size: hidden_dim * 2 (forward + backward)
        encoder_out_dim = hidden_dim * 2
        
        self.dropout = nn.Dropout(dropout)
        
        # Head 1: Current Attack Stage Classifier
        self.current_stage_head = nn.Sequential(
            nn.Linear(encoder_out_dim, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_classes)
        )
        
        # Head 2: Next Attack Stage Forecaster
        self.next_stage_head = nn.Sequential(
            nn.Linear(encoder_out_dim, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_classes)
        )

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Input:
          x: [batch_size, sequence_length, input_dim]
        Output:
          current_logits: [batch_size, num_classes]
          next_logits: [batch_size, num_classes]
        """
        # lstm_out shape: [batch_size, seq_len, hidden_dim * 2]
        lstm_out, _ = self.lstm(x)
        
        # Pool the sequence representation from the final time-step
        seq_repr = lstm_out[:, -1, :]  # [batch_size, hidden_dim * 2]
        seq_repr = self.dropout(seq_repr)
        
        current_logits = self.current_stage_head(seq_repr)
        next_logits = self.next_stage_head(seq_repr)
        
        return current_logits, next_logits

    def predict_probabilities(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """Returns softmax probabilities for current stage and next stage."""
        self.eval()
        with torch.no_grad():
            curr_logits, next_logits = self.forward(x)
            curr_probs = F.softmax(curr_logits, dim=-1)
            next_probs = F.softmax(next_logits, dim=-1)
        return curr_probs, next_probs


class NextStageForecasterWrapper(nn.Module):
    """
    Wrapper exposing only next_stage_head output for GradientExplainer.
    Input: [batch_size, seq_len, input_dim]
    Output: next_logits [batch_size, num_classes]
    """
    def __init__(self, base_model: AttackForecasterBiLSTM):
        super().__init__()
        self.base_model = base_model

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        _, next_logits = self.base_model(x)
        return next_logits
