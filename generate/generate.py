import os
import shutil
import sqlite3
import requests
import time
import json
import re
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
    # def __init__(self, db_file=new_database):
    def __init__(self, db_file=new_database):

        self.db_file = db_file
        self.conn = sqlite3.connect(db_file)
        self.cursor = self.conn.cursor()
        self.create_columns()

    def create_columns(self):
        """Create necessary columns in the database if they do not exist."""
        columns = [
            "LLM_Ranked_CVE TEXT",
            "LLM_Ranked_CWE TEXT",
            "IS_VULNERABLE_Vuln INT",
            "IS_VULNERABLE_Patch INT",
            "IS_VULNERABLE_Vuln_CVE_CWE INT",
            "IS_VULNERABLE_Patch_CVE_CWE INT",
            "Patched_Block_LLM TEXT",
            "Patched_Block_LLM_F TEXT",
        ]

        for column in columns:
            try:
                self.cursor.execute(f"ALTER TABLE vulnerabilities ADD COLUMN {column}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e):
                    pass
                else:
                    raise e
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

    def rank_cve(self, commit_hash, vulnerable_code_block, VULNERABILITY_YEAR, description=None, few_shot=False):
        """Rank the top 5 most likely CVEs for the provided C code snippets by probability."""
        if few_shot:
            prompt_cve = (
                f"Identify the five most likely CVEs (Common Vulnerabilities and Exposures) "
                f"for the provided C code snippets from the year {VULNERABILITY_YEAR}. Description: {description}. "
                f"Provide the CVE names ordered by their likelihood, without any additional information or duplication. "
                f"CVE pattern: CVE-YYYY-XXXX."
            )
            column_name = 'LLM_Ranked_CVE_F'

        else:
            prompt_cve = (
                f"Identify the five most likely CVEs (Common Vulnerabilities and Exposures) "
                f"for the provided C code snippets from the year {VULNERABILITY_YEAR}. "
                f"Provide the CVE names ordered by their likelihood, without any additional information or duplication. "
                f"CVE pattern: CVE-YYYY-XXXX."
            )
            column_name = 'LLM_Ranked_CVE'

        prompt_cve += f"\n{vulnerable_code_block}"

        result_cve = self.query_model(prompt_cve)

        if result_cve:
            cve_list = self.extract_vulnerability_names(result_cve)[0]
            if not cve_list:
                cve_list = [result_cve]
            self.cursor.execute(f"""
                UPDATE vulnerabilities
                SET {column_name} = ?
                WHERE COMMIT_HASH = ?
            """, (json.dumps(cve_list), commit_hash))
            self.conn.commit()
            print(f"Ranked CVEs updated in database for commit_hash {commit_hash}.")
        else:
            print(f"Failed to rank CVEs for commit_hash {commit_hash}.")

    def rank_cwe(self, commit_hash, vulnerable_code_block, description=None, few_shot=False):
        """Rank the top 5 most likely CWEs for the provided C code snippets by probability."""
        if few_shot:
            prompt_cwe = (
                f"Identify the five most likely CWEs (Common Weakness Enumeration) "
                f"for the provided C code snippets. Description: {description}. "
                f"Provide the CWE names ordered by their likelihood, without any additional information or duplication. "
                f"CWE pattern: CWE-XXX."
            )
            column_name = 'LLM_Ranked_CWE_F'

        else:
            prompt_cwe = (
                f"Identify the five most likely CWEs (Common Weakness Enumeration) "
                f"for the provided C code snippets. "
                f"Provide the CWE names ordered by their likelihood, without any additional information or duplication. "
                f"CWE pattern: CWE-XXX."
            )
            column_name = 'LLM_Ranked_CWE'

        prompt_cwe += f"\n{vulnerable_code_block}"

        result_cwe = self.query_model(prompt_cwe)

        if result_cwe:
            cwe_list = self.extract_vulnerability_names(result_cwe)[1]
            if not cwe_list:
                cwe_list = [result_cwe]
            self.cursor.execute(f"""
                UPDATE vulnerabilities
                SET {column_name} = ?
                WHERE COMMIT_HASH = ?
            """, (json.dumps(cwe_list), commit_hash))
            self.conn.commit()
            print(f"Ranked CWEs updated in database for commit_hash {commit_hash}.")
        else:
            print(f"Failed to rank CWEs for commit_hash {commit_hash}.")

    def cve_vuln_patch(self, commit_hash, code_block, description=None, few_shot=False, is_vulnerable=True):
        """Check if the code block has a specific CVE and update the result in the database."""
        if few_shot:
            if is_vulnerable:
                prompt = (
                    f"Check if the following C code block has a specific CVE vulnerability."
                    f"Respond 1 if it has a vulnerability, otherwise respond 0.\n"
                    f"Description: {description}\n code block:{code_block}"
                )
                column_name = 'CVE_Vuln_F'
            else:
                prompt = (
                    f"Check if the following C code block has a specific CVE vulnerability."
                    f"Respond 1 if it has a vulnerability, otherwise respond 0.\n"
                    f"Description: {description}\n code block:{code_block}"
                )
                column_name = 'CVE_Patch_F'

        else:
            if is_vulnerable:
                prompt = (
                    f"Check if the following C code block has a specific CVE vulnerability."
                    f"Respond 1 if it has a vulnerability, otherwise respond 0.\n"
                    f"code block: {code_block}"
                )
                column_name = 'CVE_Vuln'
            else:
                prompt = (
                    f"Check if the following C code block has a specific CVE vulnerability."
                    f"Respond 1 if it has a vulnerability, otherwise respond 0.\n"
                    f"code block: {code_block}"
                )
                column_name = 'CVE_Patch'

        result = self.query_model(prompt)

        if result:
            if re.search(r'\b1\b',
                         result) or 'yes' in result.lower() or 'has a vulnerability' in result.lower() or 'is vulnerable' in result.lower() or 'contains a vulnerability' in result.lower() or ' has a security issue' in result.lower() or 'has a security vulnerability' in result.lower() or 'has a security flaw' in result.lower() or 'the code block has the' in result.lower() or 'the code block contains the' in result.lower() or 'the code block has a' in result.lower() or 'the code block has an' in result.lower() or 'the code block contains an' in result.lower() or 'the code block has the' in result.lower() or 'the code block contains' in result.lower() or 'found a vulnerability' in result.lower() or 'The code has vulnerabilities associated with' in result.lower() or 'vulnerability you are looking for is likely related to' in result.lower() or 'is vulnerable to' in result.lower() or 'vulnerability associated with CVE and CWE that I can identify is' in result.lower() or 'found a potential vulnerability associated with' in result.lower() or 'The code block has the' in result.lower() or 'it appears to be vulnerable to' in result.lower() or "The specific vulnerability you're asking about is" in result.lower() or 'code appears to be vulnerable to' in result.lower() or 'I can identify a potential vulnerability' in result.lower() or 'provided C code block has a specific CWE vulnerability' in result.lower() or 'code block has the following CWE vulnerability' in result.lower() or 'The CVE vulnerability is' in result.lower() or 'C code block has a specific CVE vulnerability' in result.lower() or 'can confirm that it corresponds to the CVE' in result.lower() or 'it has a specific CVE vulnerability' in result.lower() or 'code block appears to be vulnerable' in result.lower() or 'code block you provided has the' in result.lower() or 'code block appears to have a vulnerability that is related' in result.lower() or 'code block has a CVE vulnerability' in result.lower() or 'code block has the CVE vulnerability' in result.lower():
                status = 1
            elif re.search(r'\b0\b',
                           result) or 'no' in result.lower() or 'does not have a vulnerability' in result.lower() or 'does not contain' in result.lower() or 'is not vulnerable' in result.lower() or 'does not have a security issue' in result.lower() or 'does not have a security vulnerability' in result.lower() or 'does not have a security flaw' in result.lower() or 'the code block does not have the' in result.lower() or 'the code block does not contain the' in result.lower() or 'the code block does not have a' in result.lower() or 'the code block does not contain a' in result.lower() or 'the code block does not have an' in result.lower() or 'the code block does not contain an' in result.lower() or 'the code block does not have any' in result.lower() or 'the code block does not contain any' in result.lower() or 'the code block does not have' in result.lower() or 'the code block does not contain' in result.lower() or 'the code block does not' in result.lower() or 'the code block does not have any' in result.lower() or 'the code block does not contain any' in result.lower() or 'the code block does not have' in result.lower() or 'the code block does not contain' in result.lower() or "it doesn't appear to have a specific" in result.lower():
                status = 0
            else:
                status = None
        else:
            status = None

        if status is not None:
            self.cursor.execute(f"""
                UPDATE vulnerabilities
                SET {column_name} = ?
                WHERE COMMIT_HASH = ?
            """, (status, commit_hash))
            self.conn.commit()
            print(
                f"Specific CVE vulnerability check result ({status}) updated for commit_hash {commit_hash} in column {column_name}.")
        else:
            self.cursor.execute(f"""
                UPDATE vulnerabilities
                SET {column_name} = ?
                WHERE COMMIT_HASH = ?
            """, (result, commit_hash))
            self.conn.commit()
            print(
                f"Failed to get a clear specific CVE vulnerability check result for commit_hash {commit_hash}. Response stored in column {column_name}.")

    def cwe_vuln_patch(self, commit_hash, code_block, description=None, few_shot=False, is_vulnerable=True):
        """Check if the code block has a specific CWE and update the result in the database."""
        if few_shot:
            if is_vulnerable:
                prompt = (
                    f"Check if the following C code block has a specific CWE vulnerability."
                    f"Respond 1 if it has a vulnerability, otherwise respond 0.\n"
                    f"Description: {description}\n code block:{code_block}"
                )
                column_name = 'CWE_Vuln_F'
            else:
                prompt = (
                    f"Check if the following C code block has a specific CWE vulnerability."
                    f"Respond 1 if it has a vulnerability, otherwise respond 0.\n"
                    f"Description: {description}\n code block:{code_block}"
                )
                column_name = 'CWE_Patch_F'
        else:
            if is_vulnerable:
                prompt = (
                    f"Check if the following C code block has a specific CWE vulnerability."
                    f"Respond 1 if it has a vulnerability, otherwise respond 0.\n"
                    f"code block:{code_block}"
                )
                column_name = 'CWE_Vuln'
            else:
                prompt = (
                    f"Check if the following C code block has a specific CWE vulnerability."
                    f"Respond 1 if it has a vulnerability, otherwise respond 0.\n"
                    f"code block:{code_block}"
                )
                column_name = 'CWE_Patch'

        result = self.query_model(prompt)

        if result:
            if re.search(r'\b1\b',
                         result) or 'yes' in result.lower() or 'has a vulnerability' in result.lower() or 'is vulnerable' in result.lower() or 'contains a vulnerability' in result.lower() or ' has a security issue' in result.lower() or 'has a security vulnerability' in result.lower() or 'has a security flaw' in result.lower() or 'the code block has the' in result.lower() or 'the code block contains the' in result.lower() or 'the code block has a' in result.lower() or 'the code block has an' in result.lower() or 'the code block contains an' in result.lower() or 'the code block has the' in result.lower() or 'the code block contains' in result.lower() or 'found a vulnerability' in result.lower() or 'The code has vulnerabilities associated with' in result.lower() or 'vulnerability you are looking for is likely related to' in result.lower() or 'is vulnerable to' in result.lower() or 'vulnerability associated with CVE and CWE that I can identify is' in result.lower() or 'found a potential vulnerability associated with' in result.lower() or 'The code block contains the' in result.lower() or 'The code block has the' in result.lower() or 'it appears to be vulnerable to' in result.lower() or "The specific vulnerability you're asking about is" in result.lower() or 'code appears to be vulnerable to' in result.lower() or 'I can identify a potential vulnerability' in result.lower() or 'provided C code block has a specific CWE vulnerability' in result.lower() or 'code block has the following CWE vulnerability' in result.lower() or 'code block has the CWE vulnerability' in result.lower() or 'This C code block has a specific CWE vulnerability' in result.lower() or 'C code block has the vulnerability identified as' in result.lower() or 'it has a specific CVE vulnerability' in result.lower() or 'code block appears to be vulnerable' in result.lower() or 'code block you provided has the' in result.lower() or 'code block appears to have a vulnerability that is related' in result.lower():
                status = 1
            elif re.search(r'\b0\b',
                           result) or 'no' in result.lower() or 'does not have a vulnerability' in result.lower() or 'does not contain' in result.lower() or 'is not vulnerable' in result.lower() or 'does not have a security issue' in result.lower() or 'does not have a security vulnerability' in result.lower() or 'does not have a security flaw' in result.lower() or 'the code block does not have the' in result.lower() or 'the code block does not contain the' in result.lower() or 'the code block does not have a' in result.lower() or 'the code block does not contain a' in result.lower() or 'the code block does not have an' in result.lower() or 'the code block does not contain an' in result.lower() or 'the code block does not have any' in result.lower() or 'the code block does not contain any' in result.lower() or 'the code block does not have' in result.lower() or 'the code block does not contain' in result.lower() or 'the code block does not' in result.lower() or 'the code block does not have any' in result.lower() or 'the code block does not contain any' in result.lower() or 'the code block does not have' in result.lower() or 'the code block does not contain' in result.lower() or "it doesn't appear to have a specific" in result.lower():
                status = 0
            else:
                status = None
        else:
            status = None

        if status is not None:
            self.cursor.execute(f"""
                UPDATE vulnerabilities
                SET {column_name} = ?
                WHERE COMMIT_HASH = ?
            """, (status, commit_hash))
            self.conn.commit()
            print(
                f"Specific CWE vulnerability check result ({status}) updated for commit_hash {commit_hash} in column {column_name}.")
        else:
            self.cursor.execute(f"""
                UPDATE vulnerabilities
                SET {column_name} = ?
                WHERE COMMIT_HASH = ?
            """, (result, commit_hash))
            self.conn.commit()
            print(
                f"Failed to get a clear specific CWE vulnerability check result for commit_hash {commit_hash}. Response stored in column {column_name}.")

    def check_cve_cwe_vulnerability(self, commit_hash, code_block, cve=None, cwe=None, description=None, few_shot=False,
                                    is_vulnerable=True):
        """Check if the given code block has a vulnerability related to specific CVE and CWE, and update the result in the database."""
        cve_text = f"CVE: {cve}" if cve else "CVE"
        cwe_text = f"CWE: {cwe}" if cwe else "CWE"

        if few_shot:
            if is_vulnerable:
                prompt = (
                    f"Does the following C code have a vulnerability associated with {cve_text} and {cwe_text}? "
                    f"Description: {description}. Respond with '1' if it has a vulnerability, otherwise respond with '0'.\n"
                    f"Code block:\n{code_block}"
                )
                column_name = 'CVE_CWE_Vuln_F'
            else:
                prompt = (
                    f"Does the following C code have a vulnerability associated with {cve_text} and {cwe_text}? "
                    f"Description: {description}. Respond with '1' if it has a vulnerability, otherwise respond with '0'.\n"
                    f"Code block:\n{code_block}"
                )
                column_name = 'CVE_CWE_Patch_F'

        else:
            if is_vulnerable:
                prompt = (
                    f"Does the following C code have a vulnerability associated with {cve_text} and {cwe_text}? "
                    f"Respond with '1' if it has a vulnerability, otherwise respond with '0'.\n"
                    f"Code block:\n{code_block}"
                )
                column_name = 'CVE_CWE_Vuln'
            else:
                prompt = (
                    f"Does the following C code have a vulnerability associated with {cve_text} and {cwe_text}? "
                    f"Respond with '1' if it has a vulnerability, otherwise respond with '0'.\n"
                    f"Code block:\n{code_block}"
                )
                column_name = 'CVE_CWE_Patch'

        result = self.query_model(prompt)

        if result:
            if re.search(r'\b1\b',
                         result) or 'yes' in result.lower() or 'has a vulnerability' in result.lower() or 'is vulnerable' in result.lower() or 'contains a vulnerability' in result.lower() or ' has a security issue' in result.lower() or 'has a security vulnerability' in result.lower() or 'has a security flaw' in result.lower() or 'the code block has the' in result.lower() or 'found a vulnerability' in result.lower() or 'The code has vulnerabilities associated with' in result.lower() or 'vulnerability you are looking for is likely related to' in result.lower() or 'is vulnerable to' in result.lower() or 'vulnerability associated with CVE and CWE that I can identify is' in result.lower() or 'found a potential vulnerability associated with' in result.lower() or 'The code block contains the' in result.lower() or 'The code block has the' in result.lower() or 'it appears to be vulnerable to' in result.lower() or "The specific vulnerability you're asking about is" in result.lower() or 'code appears to be vulnerable to' in result.lower() or 'I can identify a potential vulnerability' in result.lower() or 'provided C code block has a specific CWE vulnerability' in result.lower() or 'code block has the following CWE vulnerability' in result.lower() or 'code is associated with the following CVE and CWE' in result.lower():
                status = 1
            elif re.search(r'\b0\b',
                           result) or 'no' in result.lower() or 'does not have a vulnerability' in result.lower() or 'does not contain' in result.lower() or 'is not vulnerable' in result.lower() or 'does not have a security issue' in result.lower() or 'does not have a security vulnerability' in result.lower() or 'does not have a security flaw' in result.lower() or 'the code block does not have the' in result.lower() or 'the code block does not contain the' in result.lower() or 'the code block does not have a' in result.lower() or 'the code block does not contain a' in result.lower() or 'the code block does not have an' in result.lower() or 'the code block does not contain an' in result.lower() or 'the code block does not have any' in result.lower() or 'the code block does not contain any' in result.lower() or 'the code block does not have' in result.lower() or 'the code block does not contain' in result.lower() or 'the code block does not' in result.lower() or 'the code block does not have any' in result.lower() or 'the code block does not contain any' in result.lower() or 'the code block does not have' in result.lower() or 'the code block does not contain' in result.lower():
                status = 0
            else:
                status = None
        else:
            status = None

        if status is not None:
            self.cursor.execute(f"""
                UPDATE vulnerabilities
                SET {column_name} = ?
                WHERE COMMIT_HASH = ?
            """, (status, commit_hash))
            self.conn.commit()
            print(
                f"Vulnerability check result ({status}) updated for commit_hash {commit_hash} in column {column_name}.")
        else:
            self.cursor.execute(f"""
                UPDATE vulnerabilities
                SET {column_name} = ?
                WHERE COMMIT_HASH = ?
            """, (result, commit_hash))
            self.conn.commit()
            print(
                f"Failed to get a clear vulnerability check result for commit_hash {commit_hash}. Response stored in column {column_name}.")

    def update_code_block_llm(self, commit_hash, code, few_shot=False):
        """Update the code block generated by LLM."""
        column_name = 'Patched_Block_LLM_F' if few_shot else 'Patched_Block_LLM'
        self.cursor.execute(f"""
            UPDATE vulnerabilities
            SET {column_name} = ?
            WHERE COMMIT_HASH = ?
        """, (code, commit_hash))
        self.conn.commit()

    def suggest_a_fix(self, commit_hash, vulnerable_code_block, cve, cwe, description=None, few_shot=False):
        """Generate a fix for the vulnerable code block."""
        if few_shot:
            prompt = (
                f"Please correct the following vulnerable C code to fix the security issue without changing its functionality. "
                f"Description of changes: {description}. "
                f"Provide the entire fixed code in the specified format, including all necessary parts. "
                f"Do not use ellipses or leave any parts of the code out.\n"
                f"Format example:\n"
                f"// File path: path/to/file1\nUpdated non-function element 1\n\n"
                f"// File path: path/to/file2\nUpdated Function 1(int param1, char *param2, ...)\n"
                f"{{\n    // Updated function body\n}}\n\n"
                f"// File path: path/to/file3\nUpdated non-function element 2\n\n"
                f"// File path: path/to/file4\nUpdated Function 2(double param1, int param2, ...)\n"
                f"{{\n    // Updated function body\n}}\n\n"
                f"This C code block is a vulnerability identified as {cve} and has the weaknesses of {cwe}.\n"
                f"Here is the vulnerable code:\n{vulnerable_code_block}"
            )
        else:
            prompt = (
                f"Please correct the following vulnerable C code to fix the security issue without changing its functionality. "
                f"Provide the entire fixed code in the specified format, including all necessary parts. "
                f"Do not use ellipses or leave any parts of the code out.\n"
                f"Format example:\n"
                f"// File path: path/to/file1\nUpdated non-function element 1\n\n"
                f"// File path: path/to/file2\nUpdated Function 1(int param1, char *param2, ...)\n"
                f"{{\n    // Updated function body\n}}\n\n"
                f"// File path: path/to/file3\nUpdated non-function element 2\n\n"
                f"// File path: path/to/file4\nUpdated Function 2(double param1, int param2, ...)\n"
                f"{{\n    // Updated function body\n}}\n\n"
                f"Here is the vulnerable code:\n{vulnerable_code_block}"
            )

        result = self.query_model(prompt)
        if result:
            code_block = re.findall(r'```(?:\w+)?\n(.*?)```', result, re.DOTALL)
            res = "\n\n".join(code_block)
            self.update_code_block_llm(commit_hash, res, few_shot)
            print(f"Fix suggested and updated in database for commit_hash {commit_hash}.")
        else:
            print(f"Failed to generate a fix for commit_hash {commit_hash}.")

    def is_vulnerable_func(self, commit_hash, code_block, is_vulnerable=True):
        """ check if the code block is vulnerable or not (Zero-shot, Few-shot for both vulnerable and patched code)"""
        if is_vulnerable:
            prompt = (
                f"Check if the following C code block is vulnerable. "
                f"Respond with '1' if it is vulnerable, otherwise respond with '0'.\n"
                f"code block:{code_block}"
            )
            column_name = 'IS_VULNERABLE_Vuln'
        else:
            prompt = (
                f"Check if the following C code block is vulnerable. "
                f"Respond with '1' if it is vulnerable, otherwise respond with '0'.\n"
                f"code block:{code_block}"
            )
            column_name = 'IS_VULNERABLE_Patch'
        result = self.query_model(prompt)
        if result:
            if re.search(r'\b1\b',
                         result) or 'yes' in result.lower() or 'is vulnerable' in result.lower() or 'contains a vulnerability' in result.lower() or ' has a security issue' in result.lower() or 'has a security vulnerability' in result.lower() or 'has a security flaw' in result.lower() or 'the code block has the' in result.lower() or 'the code block contains the' in result.lower() or 'the code block has a' in result.lower() or 'the code block has an' in result.lower() or 'the code block contains an' in result.lower() or 'the code block has the' in result.lower() or 'the code block contains' in result.lower() or 'found a vulnerability' in result.lower() or 'The code has vulnerabilities associated with' in result.lower() or 'vulnerability you are looking for is likely related to' in result.lower() or 'is vulnerable to' in result.lower() or 'vulnerability associated with CVE and CWE that I can identify is' in result.lower() or 'found a potential vulnerability associated with' in result.lower() or 'The code block contains the' in result.lower() or 'The code block has the' in result.lower() or 'it appears to be vulnerable to' in result.lower() or "The specific vulnerability you're asking about is" in result.lower() or 'code appears to be vulnerable to' in result.lower() or 'I can identify a potential vulnerability' in result.lower() or 'provided C code block has a specific CWE vulnerability' in result.lower() or 'code block has the following CWE vulnerability' in result.lower() or 'code block has the CWE vulnerability' in result.lower() or 'This C code block has a specific CWE vulnerability' in result.lower() or 'C code block has the vulnerability identified as' in result.lower() or 'it has a specific CVE vulnerability' in result.lower() or 'code block appears to be vulnerable' in result.lower() or 'code block you provided has the' in result.lower() or 'code block appears to have a vulnerability that is related' in result.lower():
                status = 1
            elif re.search(r'\b0\b',
                           result) or 'no' in result.lower() or 'does not have a vulnerability' in result.lower() or 'does not contain' in result.lower() or 'is not vulnerable' in result.lower() or 'does not have a security issue' in result.lower() or 'does not have a security vulnerability' in result.lower() or 'does not have a security flaw' in result.lower() or 'the code block does not have the' in result.lower() or 'the code block does not contain the' in result.lower() or 'the code block does not have a' in result.lower() or 'the code block does not contain a' in result.lower() or 'the code block does not have an' in result.lower() or 'the code block does not contain an' in result.lower() or 'the code block does not have any' in result.lower() or 'the code block does not contain any' in result.lower() or 'the code block does not have' in result.lower() or 'the code block does not contain' in result.lower() or 'the code block does not' in result.lower() or 'the code block does not have any' in result.lower() or 'the code block does not contain any' in result.lower() or 'the code block does not have' in result.lower() or 'the code block does not contain' in result.lower() or "it doesn't appear to have a specific" in result.lower():
                status = 0
            else:
                status = None
        else:
            status = None

        if status is not None:
            self.cursor.execute(f"""
                UPDATE vulnerabilities
                SET {column_name} = ?
                WHERE COMMIT_HASH = ?
            """, (status, commit_hash))
            self.conn.commit()
            print(
                f"Vulnerability check result ({status}) updated for commit_hash {commit_hash} in column {column_name}.")

    def is_vulnerable_to_CVE_CWE(self, commit_hash, code_block, CVE, CWE, is_vulnerable=True):
        """ check if the code block is vulnerable or not (Zero-shot, Few-shot for both vulnerable and patched code)"""
        if is_vulnerable:
            prompt = (
                f"Check if the following C code block is vulnerable to the specific CVE ({CVE}) and CWE ({CWE}). "
                f"Respond with '1' if it is vulnerable, otherwise respond with '0'.\n"
                f"code block:{code_block}"
            )
            column_name = 'IS_VULNERABLE_Vuln_CVE_CWE'
        else:
            prompt = (
                f"Check if the following C code block is vulnerable to the specific CVE ({CVE}) and CWE ({CWE}). "
                f"Respond with '1' if it is vulnerable, otherwise respond with '0'.\n"
                f"code block:{code_block}"
            )
            column_name = 'IS_VULNERABLE_Patch_CVE_CWE'
        result = self.query_model(prompt)
        if result:
            if re.search(r'\b1\b',
                         result) or 'yes' in result.lower() or 'is vulnerable' in result.lower() or 'contains a vulnerability' in result.lower() or ' has a security issue' in result.lower() or 'has a security vulnerability' in result.lower() or 'has a security flaw' in result.lower() or 'the code block has the' in result.lower() or 'the code block contains the' in result.lower() or 'the code block has a' in result.lower() or 'the code block has an' in result.lower() or 'the code block contains an' in result.lower() or 'the code block has the' in result.lower() or 'the code block contains' in result.lower() or 'found a vulnerability' in result.lower() or 'The code has vulnerabilities associated with' in result.lower() or 'vulnerability you are looking for is likely related to' in result.lower() or 'is vulnerable to' in result.lower() or 'vulnerability associated with CVE and CWE that I can identify is' in result.lower() or 'found a potential vulnerability associated with' in result.lower() or 'The code block contains the' in result.lower() or 'The code block has the' in result.lower() or 'it appears to be vulnerable to' in result.lower() or "The specific vulnerability you're asking about is" in result.lower() or 'code appears to be vulnerable to' in result.lower() or 'I can identify a potential vulnerability' in result.lower() or 'provided C code block has a specific CWE vulnerability' in result.lower() or 'code block has the following CWE vulnerability' in result.lower() or 'code block has the CWE vulnerability' in result.lower() or 'This C code block has a specific CWE vulnerability' in result.lower() or 'C code block has the vulnerability identified as' in result.lower() or 'it has a specific CVE vulnerability' in result.lower() or 'code block appears to be vulnerable' in result.lower() or 'code block you provided has the' in result.lower() or 'code block appears to have a vulnerability that is related' in result.lower():
                status = 1
            elif re.search(r'\b0\b',
                           result) or 'no' in result.lower() or 'does not have a vulnerability' in result.lower() or 'does not contain' in result.lower() or 'is not vulnerable' in result.lower() or 'does not have a security issue' in result.lower() or 'does not have a security vulnerability' in result.lower() or 'does not have a security flaw' in result.lower() or 'the code block does not have the' in result.lower() or 'the code block does not contain the' in result.lower() or 'the code block does not have a' in result.lower() or 'the code block does not contain a' in result.lower() or 'the code block does not have an' in result.lower() or 'the code block does not contain an' in result.lower() or 'the code block does not have any' in result.lower() or 'the code block does not contain any' in result.lower() or 'the code block does not have' in result.lower() or 'the code block does not contain' in result.lower() or 'the code block does not' in result.lower() or 'the code block does not have any' in result.lower() or 'the code block does not contain any' in result.lower() or 'the code block does not have' in result.lower() or 'the code block does not contain' in result.lower() or "it doesn't appear to have a specific" in result.lower():
                status = 0
            else:
                status = None
        else:
            status = None

        if status is not None:
            self.cursor.execute(f"""
                UPDATE vulnerabilities
                SET {column_name} = ?
                WHERE COMMIT_HASH = ?
            """, (status, commit_hash))
            self.conn.commit()
            print(
                f"Vulnerability check result ({status}) updated for commit_hash {commit_hash} in column {column_name}.")


# 1.1-1.4 Ranking CVEs and CWEs
def process_rank_cve(llm, commit_hash, code_block, VULNERABILITY_YEAR, description=None, few_shot=False):
    llm.rank_cve(commit_hash, code_block, VULNERABILITY_YEAR, description, few_shot)


def process_rank_cwe(llm, commit_hash, code_block, description=None, few_shot=False):
    llm.rank_cwe(commit_hash, code_block, description, few_shot)


#################################################
# 2.1-2.8
# check_cve|cwe_vulnerability
def process_cve_vuln_patch(llm, commit_hash, code_block, description=None, few_shot=False, is_vulnerable=True):
    llm.cve_vuln_patch(commit_hash, code_block, description, few_shot, is_vulnerable)


def process_cwe_vuln_patch(llm, commit_hash, code_block, description=None, few_shot=False, is_vulnerable=True):
    llm.cwe_vuln_patch(commit_hash, code_block, description, few_shot, is_vulnerable)


#################################################
# 3.1-3.4
# check_cve&cwe_vulnerability
def process_cve_cwe_vuln_patch(llm, commit_hash, code_block, description=None, few_shot=False, is_vulnerable=True):
    llm.check_cve_cwe_vulnerability(commit_hash, code_block, description=description, few_shot=few_shot,
                                    is_vulnerable=is_vulnerable)


#################################################
# 4.1-4.2
# suggest a fix
def process_suggest_a_fix(llm, commit_hash, code_block, cve, cwe, description=None, few_shot=False):
    llm.suggest_a_fix(commit_hash, code_block, cve, cwe, description, few_shot)


#################################################
def process_is_vulnerable(llm, commit_hash, code_block, is_vulnerable=True):
    llm.is_vulnerable_func(commit_hash, code_block, is_vulnerable)


#################################################
def process_is_vulnerable_to_CVE_CWE(llm, commit_hash, code_block, CVE, CWE, is_vulnerable=True):
    llm.is_vulnerable_to_CVE_CWE(commit_hash, code_block, CVE, CWE, is_vulnerable)

# Fetch function IDs and commit hashes
llm = LLMInteraction()
db_file = llm.db_file

# Fetch all commit hashes and related information from the database
llm.cursor.execute("SELECT COMMIT_HASH, vulnerable_code_block, patched_code_block, VULNERABILITY_YEAR, description_in_patch, VULNERABILITY_CVE, VULNERABILITY_CWE, IS_VULNERABLE_Vuln, IS_VULNERABLE_Patch, IS_VULNERABLE_Vuln_CVE_CWE, IS_VULNERABLE_Patch_CVE_CWE, LLM_Ranked_CVE, LLM_Ranked_CWE, Patched_Block_LLM, Patched_Block_LLM_F FROM vulnerabilities")
vulnerability_data = llm.cursor.fetchall()
llm.conn.close()

def worker_function(func, db_file, *args, max_retries=3):
    llm = LLMInteraction(db_file)
    retries = 0
    while retries < max_retries:
        try:
            func(llm, *args)
            break
        except Exception as e:
            retries += 1
            print(f"Error processing commit {args[0]}, retry {retries}/{max_retries}: {e}")
            if retries == max_retries:
                print(f"Failed to process commit {args[0]} after {max_retries} retries.")
        finally:
            llm.conn.close()

# ranking CVEs (Zero-shot)
with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
    futures_rank_cve_z = [
        executor.submit(worker_function, process_rank_cve, db_file, data[0], data[1], data[3], False)
        for data in vulnerability_data if data[1]  and  data[11] is None  # Ensure the code block is not None and CVE is not ranked
    ]
    for future in as_completed(futures_rank_cve_z):
        try:
            future.result()
        except Exception as e:
            print(f"Error ranking CVEs for commit: {e}")

# ranking CWEs (Zero-shot)
with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
    futures_rank_cwe_z = [
        executor.submit(worker_function, process_rank_cwe, db_file, data[0], data[1], False)
        for data in vulnerability_data if data[1] and data[12] is None  # Ensure the code block is not None and CWE is not ranked
    ]
    for future in as_completed(futures_rank_cwe_z):
        try:
            future.result()
        except Exception as e:
            print(f"Error ranking CWEs for commit: {e}")

# is_vulnerable (vulnerable code block)
with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
    futures_is_vuln = [
        executor.submit(worker_function, process_is_vulnerable, db_file, data[0], data[1], True)
        for data in vulnerability_data if data[7] is None  # Assuming IS_VULNERABLE_Vuln is at index 7
    ]
    for future in as_completed(futures_is_vuln):
        try:
            future.result()
        except Exception as e:
            print(f"Error processing is_vulnerable for commit: {e}")

# is_vulnerable (patched code block)
with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
    futures_is_vuln_patch = [
        executor.submit(worker_function, process_is_vulnerable, db_file, data[0], data[2], False)
        for data in vulnerability_data if data[8] is None  # Assuming IS_VULNERABLE_Patch is at index 8
    ]
    for future in as_completed(futures_is_vuln_patch):
        try:
            future.result()
        except Exception as e:
            print(f"Error processing is_vulnerable for commit: {e}")

# is vulnerable to CVE and CWE (vulnerable code block)
with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
    futures_is_vuln_cve_cwe = [
        executor.submit(worker_function, process_is_vulnerable_to_CVE_CWE, db_file, data[0], data[1], data[5], data[6], True)
        for data in vulnerability_data if data[9] is None  # Assuming IS_VULNERABLE_Vuln_CVE_CWE
    ]
    for future in as_completed(futures_is_vuln_cve_cwe):
        try:
            future.result()
        except Exception as e:
            print(f"Error processing is_vulnerable_to_CVE_CWE for commit: {e}")

# is vulnerable to CVE and CWE (patched code block)
with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
    futures_is_vuln_cve_cwe_patch = [
        executor.submit(worker_function, process_is_vulnerable_to_CVE_CWE, db_file, data[0], data[2], data[5], data[6], False)
        for data in vulnerability_data if data[10] is None  # Assuming IS_VULNERABLE_Patch_CVE_CWE
    ]
    for future in as_completed(futures_is_vuln_cve_cwe_patch):
        try:
            future.result()
        except Exception as e:
            print(f"Error processing is_vulnerable_to_CVE_CWE for commit: {e}")

# suggest a fix (Zero-shot)
with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
    futures_fix = [
        executor.submit(worker_function, process_suggest_a_fix, db_file, data[0], data[1], data[5], data[6], False)
        for data in vulnerability_data if data[13] is None or data[13] == ''  # Assuming Patched_Block_LLM is at index 13
    ]
    for future in as_completed(futures_fix):
        try:
            future.result()
        except Exception as e:
            print(f"Error processing fixation for commit: {e}")

# suggest a fix (Few-shot)
with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
    futures_fix_fewshot = [
        executor.submit(worker_function, process_suggest_a_fix, db_file, data[0], data[1], data[5], data[6], data[4], True)
        for data in vulnerability_data if data[14] is None or data[14] == ''  # Assuming Patched_Block_LLM_F is at index 14
    ]
    for future in as_completed(futures_fix_fewshot):
        try:
            future.result()
        except Exception as e:
            print(f"Error processing fixation for commit: {e}")

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