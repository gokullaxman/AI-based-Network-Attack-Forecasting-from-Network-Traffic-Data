"""
Launcher script for AI-Based Network Attack Forecasting System (SIH26153)
Starts the FastAPI application with Uvicorn.
"""

import argparse
import os
import sys
import uvicorn

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-Based Network Attack Forecasting System Launcher")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"), help="Host address to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8000)), help="Port to bind (default: 8000)")
    args = parser.parse_args()

    print("=" * 65)
    print(" AI-BASED NETWORK ATTACK FORECASTING SYSTEM (SIH26153)")
    print(" Ingestion -> Temporal BiLSTM -> Probabilistic Forecasting -> SHAP")
    print("=" * 65)
    print(f" Dashboard URL: http://{args.host}:{args.port}")
    print(f" API Documentation: http://{args.host}:{args.port}/docs")
    print("=" * 65)
    
    # Run uvicorn server
    uvicorn.run("dashboard.server:app", host=args.host, port=args.port, reload=False)
