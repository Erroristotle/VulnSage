import os
import shutil
import sqlite3
import requests
import time
import json
import re
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess

# API URL and database path
api_url = "http://localhost:11434/api/generate"
database_path = "database.sqlite"

# List of models and their commands
LLMs = {
    "deepseek-v2-16b": "ollama run deepseek-v2",
    "llama3.1-8b": "ollama run llama3.1",
    "llama3.1-70b": "ollama run llama3.1:70b",
    "gemma2-9b": "ollama run gemma2:9b",
    "gemma2-27b": "ollama run gemma2:27b",
    "deepseek-coder-16b": "ollama run deepseek-coder-v2",
    "qwen2.5-coder-7b": "ollama run qwen2.5-coder",
    "qwen2.5-coder-32b": "ollama run qwen2.5-coder:32b",
    "codellama-7b": "ollama run codellama:7b",
    "codellama-34b": "ollama run codellama:34b",
    "deepseek-r1-7b": "ollama run deepseek-r1",
    "deepseek-r1-32b": "ollama run deepseek-r1:32b"

}
# Add signal handler for graceful shutdown
def signal_handler(signum, frame):
    print("\nReceived shutdown signal. Cleaning up...")
    # Clean up code here (e.g., close database connections)
    cleanup_and_exit()

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def cleanup_and_exit():
    # Delete the installed model
    if 'payload_model_parameter' in globals():
        try:
            subprocess.run(['ollama', 'rm', payload_model_parameter])
            print(f"Model {payload_model_parameter} removed successfully")
        except Exception as e:
            print(f"Error removing model: {e}")
    sys.exit(0)
    
# Prompt the user to select the models to be used
def select_models():
    print("Please select the models you want to install and run. (Separate model numbers by commas)")
    for i, model in enumerate(LLMs.keys()):
        print(f"{i + 1}. {model}")

    selected = input("Enter the model numbers: ")
    selected_indices = selected.split(',')
    selected_models = []

    for index in selected_indices:
        try:
            model_index = int(index.strip()) - 1
            model_name = list(LLMs.keys())[model_index]
            selected_models.append(model_name)
        except (ValueError, IndexError):
            print(f"Invalid input: {index}. Skipping...")

    return selected_models

# Install the selected models and extract model_name and payload_model_parameter
def install_models(models):
    model_name, payload_model_parameter = None, None

    for model in models:
        command = LLMs[model]
        try:
            print(f"Installing {model}...")
            # Run the command to install the model, but don't block or enter interactive mode
            process = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for a few seconds to let the model initialize, then terminate it
            time.sleep(10)  # Adjust the time as needed based on how long it takes to initialize
            process.terminate()  # Terminate the process to prevent it from entering interactive mode
            
            print(f"{model} installed successfully.")
            model_name = model
            payload_model_parameter = command.split(" ")[2]  # Extract the model name from the command
        except subprocess.CalledProcessError as e:
            print(f"Failed to install {model}: {e}")

    return model_name, payload_model_parameter


# Main flow: Ask for user input and install selected models
selected_models = select_models()

# If multiple models are selected, choose the first one to proceed
if selected_models:
    model_name, payload_model_parameter = install_models([selected_models[0]])
else:
    print("No valid models selected, exiting.")
    exit(1)

# Output the chosen model and payload
print(f"Model selected: {model_name}")
print(f"Payload model parameter: {payload_model_parameter}")

# Proceed with the rest of the script using model_name and payload_model_parameter
# Output directory
output_dir = r"../output"
os.makedirs(output_dir, exist_ok=True)

# Create a copy of the database.sqlite file and assign a specific name to it
if not os.path.exists(os.path.join(output_dir, f"database_{model_name}.sqlite")):
    new_database = os.path.join(output_dir, f"database_{model_name}.sqlite")
    shutil.copy(database_path, new_database)
else:
    new_database = os.path.join(output_dir, f"database_{model_name}.sqlite")


class LLMInteraction:
    def __init__(self, db_file="database.sqlite", model_name=None):
        self.db_file = db_file
        self.model_name = model_name
        self.conn = sqlite3.connect(db_file)
        self.cursor = self.conn.cursor()
        self.create_table()
        
    def create_table(self):
            """Create a new table for the specific model if it doesn't exist."""
            table_name = f"vulnerabilities_{self.model_name}"
            self.cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_name} (
                    COMMIT_HASH TEXT PRIMARY KEY,
                    BASELINE_VULN INT,
                    BASELINE_PATCH INT,
                    COT_VULN INT,
                    COT_PATCH INT,
                    THINK_VULN INT,
                    THINK_PATCH INT,
                    THINK_VERIFY_VULN INT,
                    THINK_VERIFY_PATCH INT,
                    FOREIGN KEY (COMMIT_HASH) REFERENCES vulnerabilities(COMMIT_HASH)
                )
            """)
            self.conn.commit()

    def ensure_db_open(self):
        """Ensure the database connection is open."""
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_file)
            self.cursor = self.conn.cursor()

    def query_model(self, prompt, max_retries=3, retry_delay=2):
        """Sends a prompt to the model and retrieves the generated response."""
        payload = {
            "model": payload_model_parameter,
            "prompt": prompt
        }

        for attempt in range(max_retries):
            response = requests.post(api_url, json=payload)
            if response.status_code == 200:
                response_lines = response.content.decode('utf-8').splitlines()
                full_response = ''.join([json.loads(line)["response"] for line in response_lines if line])
                if full_response == "":
                    print("Empty response. Retrying...")
                    time.sleep(retry_delay)
                    continue
                return full_response
            elif response.status_code == 503:
                wait_time = retry_delay
                print(f"Model is loading, retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                print(f"HTTP Error {response.status_code}: {response.text}")
                if attempt < max_retries - 1:
                    print("Retrying...")
                else:
                    print("Reached maximum retry attempts.")
                time.sleep(retry_delay)

        return None

    def extract_vulnerability_names(self, text):
        """Extract CVE and CWE names from the LLM response."""
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cwe_pattern = r"CWE-\d{1,4}"
        cve_names = re.findall(cve_pattern, text)
        cwe_names = re.findall(cwe_pattern, text)
        return cve_names, cwe_names

    def detection(self, commit_hash, code_block, cwe_id=None, is_vulnerable=True, strategy="baseline"):
            """Check if the code block has vulnerabilities using different prompting strategies."""
            print(f"Processing {commit_hash} with strategy: {strategy} ({'vulnerable' if is_vulnerable else 'patched'} code)")
            table_name = f"vulnerabilities_{self.model_name}"
            
            strategies = {
                "baseline": self.create_baseline_prompt,
                "cot": self.create_cot_prompt,
                "think": self.create_think_prompt,
                "think_verify": self.create_think_verify_prompt
            }
            
            prompt = strategies[strategy](code_block, cwe_id)
            result = self.query_model(prompt)
            
            if result:
                status = self.parse_response(result, strategy)
                if status is not None:
                    # Create column name based on strategy and vulnerability type
                    column = f"{strategy.upper()}_{('VULN' if is_vulnerable else 'PATCH')}"
                    self.cursor.execute(f"""
                        INSERT OR REPLACE INTO {table_name} 
                        (COMMIT_HASH, {column})
                        VALUES (?, ?)
                    """, (commit_hash, status))
                    self.conn.commit()

    def create_baseline_prompt(self, code_block, cwe_id):
            """Create a baseline prompt for simple YES/NO vulnerability detection."""
            return f"""You are a security expert specializing in identifying software vulnerabilities in C code.

    Analyze the following code and determine **only** whether it contains a **{cwe_id}** vulnerability.

    **Code to analyze:**
    {code_block}

    Provide your response in **exactly** the following format:
    1. **Vulnerability Present?** (YES or NO)

    **Do not provide any explanation or additional details.**"""

    def create_cot_prompt(self, code_block, cwe_id):
        """Create a Chain of Thought prompt for vulnerability detection."""
        return f"""You are a security expert specializing in vulnerability detection, with a focus on **{cwe_id}**. Your task is to analyze the following C code using a structured approach to determine whether it contains this specific vulnerability.

Your analysis should **clearly explain whether {cwe_id} is present or not** by reasoning through the code step by step.

**Step-by-step analysis:**
1. **Code Structure Analysis:**
   * Identify key components (functions, loops, conditionals, memory operations).
   * Trace the data flow and control flow to locate relevant sections.
   * Determine areas where {cwe_id} might arise.

2. **{cwe_id} Pattern Matching & Risk Assessment:**
   * Identify coding patterns that match known causes of {cwe_id}.
   * Examine how data is processed, stored, and validated.
   * Determine whether unsafe functions or insecure coding practices contribute to this vulnerability.

3. **Exploitability & Security Impact:**
   * Assess whether an attacker could exploit {cwe_id} in this code.
   * Identify potential attack vectors and their impact.
   * Consider edge cases, user input handling, and memory management concerns.

4. **Final Decision ({cwe_id} Present or Not):**
   * **If {cwe_id} exists**, explain why and how it can be exploited. Provide an example scenario if possible.
   * **If the code is safe from {cwe_id}**, justify why no major security risks exist.

5. **Suggested Security Improvements:**
   * If applicable, suggest mitigations to eliminate {cwe_id}.
   * Provide best practices and alternative coding techniques.

**Code to analyze:**
{code_block}"""

    def create_think_prompt(self, code_block, cwe_id):
        """Create a Think prompt for vulnerability detection."""
        return f"""You are a security expert analyzing C code for vulnerabilities, with a focus on **{cwe_id}**. Use the following structured approach to determine whether this specific vulnerability is present in the code.

**<thinking>**
Explain your analysis process step by step:
* Identify potential instances of {cwe_id} as you read the code.
* Consider different attack scenarios relevant to {cwe_id}.
* Examine function interactions and data flows that may contribute to this vulnerability.
* Question assumptions about input validation, memory management, and user input handling.
* Verify initial findings and rule out false positives.
* Document confidence levels in each identified issue.

**<vulnerability_assessment>**
Summarize your conclusions, including:
* Presence of {cwe_id} (Yes/No)
* Explanation of how {cwe_id} manifests in this code (if applicable).
* Severity rating (Low, Medium, High, Critical).
* Relevant evidence from the code that supports the assessment.

**Code to analyze:**
{code_block}"""

    def create_think_verify_prompt(self, code_block, cwe_id):
        """Create a Think & Verify prompt for vulnerability detection."""
        return f"""You are a security expert conducting an **in-depth vulnerability assessment** focused on **{cwe_id}**. Follow these structured steps to determine whether this specific vulnerability is present in the given C code.

**1. Initial Analysis (Up to 3 Attempts)**
**<thinking>**
* Examine the code structure for potential {cwe_id} instances.
* Identify coding patterns that could introduce {cwe_id}.
* Consider attack vectors and real-world exploitation related to this vulnerability.
* Document any uncertainties or doubts regarding the presence of {cwe_id}.

**<findings>**
* List occurrences of {cwe_id} with supporting evidence from the code.

**<confidence>**
* Assign a confidence score (0–100%) for each {cwe_id} finding.
* If confidence is **≥90%**, proceed to verification.
* If confidence is **<90%**, reanalyze the code before verification.

**2. Verification (Required for High-Confidence Findings)**
**<verification>**
* Validate each identified instance of {cwe_id}.
* Check for false positives and confirm its exploitability.
* Ensure accurate vulnerability classification.
* Consider edge cases and uncommon attack scenarios.

**3. Final Assessment**
**<assessment>**
* Provide a final list of verified **{cwe_id}** vulnerabilities.
* Map each finding to {cwe_id} and justify its classification.
* Assign severity ratings (**Low, Medium, High, Critical**).
* Recommend security fixes or mitigations specifically for {cwe_id}.

**Code to analyze:**
{code_block}"""

    def parse_response(self, result, strategy="baseline"):
        """Parse the LLM response based on the prompting strategy used."""
        if strategy == "baseline":
            if 'YES' in result.upper():
                return 1
            elif 'NO' in result.upper():
                return 0
        elif strategy == "cot":
            # Look for final decision
            if re.search(r'Final Decision.*exists|present|found|detected|identified', result, re.IGNORECASE | re.DOTALL):
                return 1
            elif re.search(r'Final Decision.*safe|not present|no.*vulnerability', result, re.IGNORECASE | re.DOTALL):
                return 0
        elif strategy == "think":
            # Look for vulnerability assessment
            assessment = re.search(r'<vulnerability_assessment>.*?Presence of.*?(\bYES\b|\bNO\b)', result, re.IGNORECASE | re.DOTALL)
            if assessment:
                if 'YES' in assessment.group(1).upper():
                    return 1
                elif 'NO' in assessment.group(1).upper():
                    return 0
        elif strategy == "think_verify":
            # Look for final assessment and confidence score
            confidence_match = re.search(r'confidence score.*?(\d+)%', result, re.IGNORECASE | re.DOTALL)
            assessment_match = re.search(r'<assessment>.*?(verified.*?vulnerabilities).*?</assessment>', result, re.IGNORECASE | re.DOTALL)
            
            if confidence_match and assessment_match:
                confidence = int(confidence_match.group(1))
                assessment = assessment_match.group(1).lower()
                
                if confidence >= 90 and ('verified' in assessment and 'vulnerabilit' in assessment):
                    return 1
                elif confidence >= 90:
                    return 0
                
        return None
    
def process_detection(llm, commit_hash, code_block, cwe_id=None, is_vulnerable=True):
    """Process a single detection request with all prompting strategies."""
    strategies = ["baseline", "cot", "think", "think_verify"]
    for strategy in strategies:
        llm.detection(commit_hash, code_block, cwe_id, is_vulnerable, strategy)

# Fetch function IDs and commit hashes
llm = LLMInteraction(new_database, model_name)

# Fetch all vulnerability data
llm.cursor.execute("""
    SELECT COMMIT_HASH, vulnerable_code_block, patched_code_block, 
            VULNERABILITY_CWE 
    FROM vulnerabilities
""")
vulnerability_data = llm.cursor.fetchall()
llm.conn.close()

def worker_function(commit_hash, code_block, cwe_id, is_vulnerable, max_retries=3):
    """Worker function for processing individual commits."""
    llm = LLMInteraction(new_database, model_name)
    retries = 0
    while retries < max_retries:
        try:
            process_detection(llm, commit_hash, code_block, cwe_id, is_vulnerable)
            break
        except Exception as e:
            retries += 1
            print(f"Error processing commit {commit_hash}, retry {retries}/{max_retries}: {e}")
            if retries == max_retries:
                print(f"Failed to process commit {commit_hash} after {max_retries} retries.")
        finally:
            llm.conn.close()

# Process both vulnerable and patched code blocks
with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
    futures = []
    
    for data in vulnerability_data:
        commit_hash, vuln_block, patch_block, cwe_id = data
        
        # Submit vulnerable code block analysis
        if vuln_block:
            futures.append(
                executor.submit(
                    worker_function,
                    commit_hash,
                    vuln_block,
                    cwe_id,
                    True  # is_vulnerable
                )
            )
        
        # Submit patched code block analysis
        if patch_block:
            futures.append(
                executor.submit(
                    worker_function,
                    commit_hash,
                    patch_block,
                    cwe_id,
                    False  # is_vulnerable
                )
            )
    
    # Wait for all futures to complete
    for future in as_completed(futures):
        try:
            future.result()
        except Exception as e:
            print(f"Error in processing: {e}")

import sqlite3

def add_columns_and_update_line_counts(db_file):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    # Add the new columns if they don't exist
    columns = [
        'NUM_LINES_IN_PATCHED_BLOCK_LLM',
        'NUM_LINES_IN_PATCHED_BLOCK_LLM_F'
    ]
    for column in columns:
        try:
            cursor.execute(f"ALTER TABLE vulnerabilities ADD COLUMN {column} INTEGER")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                pass
            else:
                raise e
    conn.commit()

    # Update the columns with line counts
    update_llm_query = """
    UPDATE vulnerabilities 
    SET NUM_LINES_IN_PATCHED_BLOCK_LLM = (LENGTH(Patched_Block_LLM) - LENGTH(REPLACE(Patched_Block_LLM, '\n', '')) + 1)
    WHERE Patched_Block_LLM IS NOT NULL
    """
    cursor.execute(update_llm_query)

    update_llm_f_query = """
    UPDATE vulnerabilities 
    SET NUM_LINES_IN_PATCHED_BLOCK_LLM_F = (LENGTH(Patched_Block_LLM_F) - LENGTH(REPLACE(Patched_Block_LLM_F, '\n', '')) + 1)
    WHERE Patched_Block_LLM_F IS NOT NULL
    """
    cursor.execute(update_llm_f_query)

    conn.commit()
    conn.close()

# Main execution
db_file = new_database
add_columns_and_update_line_counts(db_file)