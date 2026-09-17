"""
Launcher script for AI-Based Network Attack Forecasting System (SIH26153)
Starts the FastAPI application with Uvicorn.
"""

import uvicorn
import os
import sys

if __name__ == "__main__":
    print("=" * 65)
    print(" AI-BASED NETWORK ATTACK FORECASTING SYSTEM (SIH26153)")
    print(" Ingestion -> Temporal BiLSTM -> Probabilistic Forecasting -> SHAP")
    print("=" * 65)
    print(" Dashboard URL: http://localhost:8000")
    print(" API Documentation: http://localhost:8000/docs")
    print("=" * 65)
    
    # Run uvicorn server
    uvicorn.run("dashboard.server:app", host="0.0.0.0", port=8000, reload=False)
