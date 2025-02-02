# VulnSage

## Project Structure
```
project/
├── generate/              # Generated files directory
├── requirements.txt       # Project dependencies
├── scripts/              # Execution scripts
├── src/                  # Source code
├── tests/                # Test files
└── vulnerability_dataset/ # Dataset files
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
- Check the generated log files
- Monitor the database in the output directory

## Database Structure

The system creates a new table for each model with the following structure:
- `COMMIT_HASH`: Unique identifier for each commit
- Results for each strategy (BASELINE, COT, THINK, THINK_VERIFY)
- Both vulnerable and patched code analysis results

## Features

- Multiple prompting strategies:
  - Baseline (YES/NO)
  - Chain of Thought (CoT)
  - Think
  - Think & Verify
- Automatic model management
- Progress tracking and resume capability
- Multi-threaded processing
- Graceful shutdown handling

## Requirements

- Python 3.8+
- Ollama
- SQLite3
- Required Python packages (see requirements.txt)

## Notes

- The system will create a copy of the database for each model
- Progress is saved automatically and can be resumed if interrupted
- Use Ctrl+C for graceful shutdown
- Monitor memory usage when running large models