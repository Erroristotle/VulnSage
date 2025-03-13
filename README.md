# VulnSage

A comprehensive benchmarking platform for evaluating LLM-based vulnerability detection capabilities across different prompting strategies and models.

## Project Structure
```
project/
├── generate/              # Generated files directory
├── requirements.txt       # Project dependencies
├── scripts/               # Execution scripts
│   ├── run_analysis.py    # Main script for running vulnerability analysis
│   └── monitor_progress.py # Script for monitoring analysis progress
├── src/                   # Source code
│   ├── config.py          # Configuration settings
│   ├── database.py        # Database operations
│   ├── llm_interaction.py # LLM API interaction
│   ├── models.py          # Data models
│   ├── prompts/           # Prompt templates for different strategies
│   └── utils/             # Utility functions
├── tests/                 # Test files
└── vulnerability_dataset/ # Dataset processing and management
```

## Setup

1. Clone the repository:
```bash
git clone [repository-url]
cd project
```

2. Set up a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # For Linux/Unix
# or
.\venv\Scripts\activate  # For Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Ensure Ollama is installed and running:
```bash
# Check if Ollama is running
curl http://localhost:11434/api/generate
```

## Running the Code

1. **Normal Execution**:
```bash
python scripts/run_analysis.py
```

2. **Background Execution** (Linux/Unix):
```bash
# Using nohup
nohup python scripts/run_analysis.py > output.log 2>&1 &

# Check logs
tail -f output.log
```

3. **Monitoring Progress**:
```bash
python scripts/monitor_progress.py
```

## Database Structure

The system creates a new table for each model with the following structure:
- `COMMIT_HASH`: Unique identifier for each commit
- Results for each strategy (BASELINE, COT, THINK, THINK_VERIFY)
- Both vulnerable and patched code analysis results
- Reasoning columns for strategies that provide explanations

## Prompting Strategies

VulnSage implements four different prompting strategies:

1. **Baseline**: Simple YES/NO vulnerability detection
2. **Chain of Thought (CoT)**: Structured reasoning before making a decision
3. **Think**: In-depth analysis with step-by-step reasoning
4. **Think & Verify**: Two-stage reasoning with verification step

## Features

- **Multiple Prompting Strategies**: Compare effectiveness of different prompting approaches
- **Batch Processing**: Efficient processing of multiple code samples
- **Automatic Model Management**: Handles model installation and verification
- **Progress Tracking**: Resume capability for interrupted runs
- **Multi-threaded Processing**: Parallel processing for improved performance
- **Graceful Shutdown**: Properly saves state when interrupted
- **Comprehensive Logging**: Detailed logs for debugging and analysis

## Requirements

- Python 3.8+
- Ollama
- SQLite3
- Required Python packages:
  - pandas, numpy, matplotlib, seaborn
  - requests, aiohttp, websockets
  - python-dotenv, tqdm, colorlog
  - tenacity (for retry logic)
  - pytest (for testing)

## Performance Considerations

- The system uses batch processing to optimize LLM API calls
- Database operations use WAL mode for better concurrency
- Memory usage should be monitored when running large models
- Graceful shutdown can be triggered with Ctrl+C