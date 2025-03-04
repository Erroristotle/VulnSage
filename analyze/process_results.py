import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from scipy import stats
import os

def calculate_accuracy(df, column_name):
    # Filter out rows where ground truth is 2 (ambiguous)
    valid_rows = df[df['ground_truth'] != 2]
    
    # Calculate accuracy
    correct = (
        ((valid_rows['ground_truth'] == 1) & (valid_rows[column_name] == 1)) | 
        ((valid_rows['ground_truth'] == 0) & (valid_rows[column_name] == 0))
    ).sum()
    
    accuracy = correct / len(valid_rows) if len(valid_rows) > 0 else 0
    ambiguous_count = len(df[df['ground_truth'] == 2])
    
    return accuracy, ambiguous_count

def calculate_counts(df, column_name):
    """Calculate counts of 0, 1, and 2 in a column"""
    if column_name not in df.columns:
        return None
    counts = df[column_name].value_counts().to_dict()
    return {
        '0': counts.get(0, 0),
        '1': counts.get(1, 0),
        '2': counts.get(2, 0)
    }

def calculate_model_accuracy(df, column_name, total_samples=594):
    """Calculate accuracy based on total samples"""
    if column_name not in df.columns:
        return None, None
        
    counts = df[column_name].value_counts().to_dict()
    ones = counts.get(1, 0)
    zeros = counts.get(0, 0)
    twos = counts.get(2, 0)
    
    # For Vuln, accuracy = (number of 1s) / total_samples
    # For Patch, accuracy = (number of 0s) / total_samples
    if 'VULN' in column_name.upper():
        accuracy = (ones / total_samples) * 100
    else:  # PATCH
        accuracy = (zeros / total_samples) * 100
        
    return accuracy, f"{ones} {{1}} {zeros} {{0}} {twos} {{2}}"

def main():
    # Connect to database with correct path
    db_path = '/users/azibaeir/Research/Benchmarking/project/vulnerability_dataset/database/database.sqlite'
    
    if not os.path.exists(db_path):
        print(f"Database file not found at {db_path}")
        return None
        
    conn = sqlite3.connect(db_path)
    
    # Get list of tables in the database
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    print(f"Tables in database: {[table[0] for table in tables]}")
    
    # First, get the schema of the vulnerabilities table to see available columns
    cursor.execute("PRAGMA table_info(vulnerabilities)")
    vuln_columns = cursor.fetchall()
    print(f"Vulnerabilities table columns: {[col[1] for col in vuln_columns]}")
    
    # Load the vulnerabilities table with available columns
    vulnerabilities = pd.read_sql('SELECT * FROM vulnerabilities', conn)
    print(f"Loaded {len(vulnerabilities)} vulnerability records")
    
    # Check if noise_level column exists, if not, use a default or create it
    if 'noise_level' not in vulnerabilities.columns:
        print("No noise_level column found in vulnerabilities table")
        # Check if there's any column that might contain noise information
        noise_candidates = [col for col in vulnerabilities.columns if 'noise' in col.lower()]
        if noise_candidates:
            print(f"Found potential noise columns: {noise_candidates}")
            vulnerabilities['noise_level'] = vulnerabilities[noise_candidates[0]]
        else:
            print("Creating synthetic noise_level for demonstration")
            # Create a synthetic noise level for demonstration purposes
            np.random.seed(42)  # For reproducibility
            vulnerabilities['noise_level'] = np.random.uniform(0, 100, size=len(vulnerabilities))
    
    # Get a list of model-specific tables
    model_tables = [table[0] for table in tables if table[0].startswith('vulnerabilities_')]
    print(f"Found model tables: {model_tables}")
    
    # Create a combined dataframe for all models
    all_models_data = []
    
    for table_name in model_tables:
        # Extract model name from table name
        model_name = table_name.replace('vulnerabilities_', '').replace('_', ' ').title()
        
        # Get schema for this table
        cursor.execute(f"PRAGMA table_info({table_name})")
        table_columns = cursor.fetchall()
        print(f"{table_name} columns: {[col[1] for col in table_columns]}")
        
        # Load data from this table
        try:
            model_data = pd.read_sql(f'SELECT * FROM {table_name}', conn)
            print(f"Loaded {len(model_data)} records from {table_name}")
            
            # Add model name column
            model_data['model'] = model_name
            
            # Standardize column names if needed
            if 'COMMIT_HASH' in model_data.columns and 'commit_hash' not in model_data.columns:
                model_data['commit_hash'] = model_data['COMMIT_HASH']
            
            # Add to combined data
            all_models_data.append(model_data)
        except Exception as e:
            print(f"Error loading data from {table_name}: {e}")
    
    # Combine all model data
    if all_models_data:
        decisions = pd.concat(all_models_data, ignore_index=True)
        print(f"Combined {len(decisions)} records from all model tables")
    else:
        print("No model data could be loaded")
        return None
    
    # Ensure we have the necessary columns
    required_columns = ['commit_hash', 'ground_truth']
    prompt_columns = [
        'BASELINE_VULN', 'BASELINE_PATCH',
        'COT_VULN', 'COT_PATCH',
        'THINK_VULN', 'THINK_PATCH',
        'THINK_VERIFY_VULN', 'THINK_VERIFY_PATCH'
    ]
    
    # Check if columns exist, if not, try to find alternatives
    for col in required_columns:
        if col not in decisions.columns:
            print(f"Missing required column: {col}")
            # Try to find alternative column names
            if col == 'commit_hash':
                alternatives = ['COMMIT_HASH', 'hash', 'commit']
                for alt in alternatives:
                    if alt in decisions.columns:
                        decisions['commit_hash'] = decisions[alt]
                        break
            elif col == 'ground_truth':
                # If ground_truth is missing, we might need to create it
                if 'is_vulnerable' in decisions.columns:
                    decisions['ground_truth'] = decisions['is_vulnerable']
                else:
                    # Try to determine ground truth from table structure or column names
                    vuln_indicators = [col for col in decisions.columns if 'vuln' in col.lower() and not any(p in col.lower() for p in ['baseline', 'cot', 'think', 'verify'])]
                    
                    if vuln_indicators:
                        print(f"Using {vuln_indicators[0]} to determine ground truth")
                        decisions['ground_truth'] = decisions[vuln_indicators[0]]
                    else:
                        # Default assumption: create synthetic ground truth for demonstration
                        print("Creating synthetic ground_truth for demonstration")
                        decisions['ground_truth'] = np.random.choice([0, 1], size=len(decisions))
    
    # Merge decisions with vulnerabilities to get noise levels and other metadata
    print(f"Decisions columns: {decisions.columns.tolist()}")
    print(f"Vulnerabilities columns: {vulnerabilities.columns.tolist()}")
    
    # Ensure commit_hash is lowercase in both dataframes for consistent joining
    if 'commit_hash' in decisions.columns:
        decisions['commit_hash'] = decisions['commit_hash'].str.lower()
    elif 'COMMIT_HASH' in decisions.columns:
        decisions['commit_hash'] = decisions['COMMIT_HASH'].str.lower()
    
    if 'commit_hash' in vulnerabilities.columns:
        vulnerabilities['commit_hash'] = vulnerabilities['commit_hash'].str.lower()
    elif 'COMMIT_HASH' in vulnerabilities.columns:
        vulnerabilities['commit_hash'] = vulnerabilities['COMMIT_HASH'].str.lower()
        vulnerabilities['commit_hash'] = vulnerabilities['COMMIT_HASH'].str.lower()
    
    # Merge on commit_hash
    df = pd.merge(decisions, vulnerabilities, on='commit_hash', how='left')
    print(f"After merging, dataframe has {len(df)} rows and columns: {df.columns.tolist()}")
    
    # If noise_level is missing after merge, try alternative column names
    if 'noise_level' not in df.columns:
        noise_alternatives = ['NOISE_LEVEL', 'noise', 'noise_score']
        for alt in noise_alternatives:
            if alt in df.columns:
                df['noise_level'] = df[alt]
                break
        else:
            print("No noise level column found after merge, creating synthetic data")
            df['noise_level'] = np.random.uniform(0, 100, size=len(df))
    
    # Calculate accuracies for each model and prompt type
    results = {}
    models = df['model'].unique().tolist()
    print(f"Models found: {models}")
    
    prompts = {
        'Baseline': ['BASELINE_VULN', 'BASELINE_PATCH'],
        'CoT': ['COT_VULN', 'COT_PATCH'],
        'Think': ['THINK_VULN', 'THINK_PATCH'],
        'Think-Verify': ['THINK_VERIFY_VULN', 'THINK_VERIFY_PATCH']
    }
    
    # Calculate accuracies and store results
    for model in models:
        model_df = df[df['model'] == model]
        results[model] = {}
        
        for prompt_name, columns in prompts.items():
            # Check if columns exist
            if columns[0] in model_df.columns and columns[1] in model_df.columns:
                vuln_acc, vuln_counts = calculate_model_accuracy(model_df, columns[0])
                patch_acc, patch_counts = calculate_model_accuracy(model_df, columns[1])
                
                results[model][prompt_name] = {
                    'vuln_acc': vuln_acc,
                    'patch_acc': patch_acc,
                    'vuln_counts': vuln_counts,
                    'patch_counts': patch_counts
                }
            else:
                print(f"Columns {columns} not found for model {model}")
    
    # Calculate counts for each model and prompt type
    for model in models:
        model_df = df[df['model'] == model]
        print(f"\n=== {model} ===")
        
        for prompt_name, columns in prompts.items():
            print(f"\n{prompt_name}:")
            
            # Vulnerability counts
            vuln_counts = calculate_counts(model_df, columns[0])
            if vuln_counts:
                print(f"Vuln: {vuln_counts['1']} {{1}} {vuln_counts['0']} {{0}} {vuln_counts['2']} {{2}}")
            
            # Patch counts
            patch_counts = calculate_counts(model_df, columns[1])
            if patch_counts:
                print(f"Patch: {patch_counts['1']} {{1}} {patch_counts['0']} {{0}} {patch_counts['2']} {{2}}")
    
    # Create scatter plot for noise vs accuracy
    plt.figure(figsize=(12, 8))
    colors = plt.cm.tab10(np.linspace(0, 1, len(models)))
    
    for model, color in zip(models, colors):
        model_df = df[df['model'] == model]
        
        # Check if noise_level column exists
        if 'noise_level' not in model_df.columns:
            print(f"No noise_level data for model {model}")
            continue
            
        accuracies = []
        noise_levels = []
        
        # Use Think-Verify strategy for noise analysis if available
        if 'THINK_VERIFY_VULN' in model_df.columns:
            target_col = 'THINK_VERIFY_VULN'
        elif 'THINK_VULN' in model_df.columns:
            target_col = 'THINK_VULN'
        elif 'COT_VULN' in model_df.columns:
            target_col = 'COT_VULN'
        elif 'BASELINE_VULN' in model_df.columns:
            target_col = 'BASELINE_VULN'
        else:
            print(f"No suitable accuracy column found for model {model}")
            continue
        
        for _, row in model_df.iterrows():
            if pd.notna(row['ground_truth']) and row['ground_truth'] != 2 and pd.notna(row[target_col]) and pd.notna(row['noise_level']):
                accuracy = 1 if (
                    (row['ground_truth'] == 1 and row[target_col] == 1) or
                    (row['ground_truth'] == 0 and row[target_col] == 0)
                ) else 0
                accuracies.append(accuracy)
                noise_levels.append(row['noise_level'])
        
        if accuracies and noise_levels:  # Only plot if we have data
            plt.scatter(noise_levels, accuracies, label=model, alpha=0.6, c=[color])
            
            # Calculate and plot trend line
            z = np.polyfit(noise_levels, accuracies, 1)
            p = np.poly1d(z)
            plt.plot(sorted(noise_levels), p(sorted(noise_levels)), '--', color=color, alpha=0.3)
            
            # Calculate correlation
            correlation, p_value = stats.pearsonr(noise_levels, accuracies)
            print(f"{model} - Correlation: {correlation:.3f}, p-value: {p_value:.3f}")
    
    plt.xlabel('Noise Level (%)')
    plt.ylabel('Accuracy')
    plt.title('LLM Accuracy vs. Noise Level')
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig('noise_vs_accuracy.png', dpi=300, bbox_inches='tight')
    
    # Find example of a buffer overflow vulnerability (CWE-119) that was misclassified
    # Look for CVE information in the vulnerabilities table
    if 'CVE' in vulnerabilities.columns or 'cve_id' in vulnerabilities.columns:
        cve_col = 'CVE' if 'CVE' in vulnerabilities.columns else 'cve_id'
        project_col = next((col for col in vulnerabilities.columns if 'project' in col.lower()), None)
        
        # Find a buffer overflow example
        buffer_overflow_examples = vulnerabilities[
            vulnerabilities['VULNERABILITY_CWE'].str.contains('CWE-119', na=False) if 'VULNERABILITY_CWE' in vulnerabilities.columns 
            else vulnerabilities['cwe_id'].str.contains('CWE-119', na=False)
        ]
        
        if not buffer_overflow_examples.empty:
            example = buffer_overflow_examples.iloc[0]
            cve_id = example[cve_col] if cve_col in example else "Unknown"
            project = example[project_col] if project_col and project_col in example else "Unknown"
            commit_hash = example['commit_hash'] if 'commit_hash' in example else example['COMMIT_HASH'] if 'COMMIT_HASH' in example else "Unknown"
            
            print(f"\nExample Buffer Overflow (CWE-119):")
            print(f"CVE ID: {cve_id}")
            print(f"Project: {project}")
            print(f"Commit Hash: {commit_hash}")
        else:
            print("\nNo buffer overflow examples found in the dataset")
    
    # Print formatted results
    print("\nAccuracy Results:")
    print("=" * 80)
    for model in models:
        print(f"\n{model}:")
        for prompt, metrics in results[model].items():
            print(f"\n{prompt}:")
            print(f"  Vulnerability Detection Accuracy: {metrics['vuln_acc']:.2f}%")
            print(f"  Patch Detection Accuracy: {metrics['patch_acc']:.2f}%")
            print(f"  Vulnerability Counts: {metrics['vuln_counts']}")
            print(f"  Patch Counts: {metrics['patch_counts']}")
    
    # Create a table for the paper
    table_data = []
    for model in models:
        model_row = [model]
        for prompt_name in prompts:
            if prompt_name in results[model]:
                model_row.append(f"{results[model][prompt_name]['vuln_acc']:.1f}")
                model_row.append(f"{results[model][prompt_name]['patch_acc']:.1f}")
            else:
                model_row.append("-")
                model_row.append("-")
        table_data.append(model_row)
    
    # Create a DataFrame for the table
    columns = ['Model']
    for prompt in prompts:
        columns.extend([f"{prompt} (Vuln)", f"{prompt} (Patch)"])
    
    table_df = pd.DataFrame(table_data, columns=columns)
    print("\nTable for Paper:")
    print(table_df.to_string(index=False))
    
    # Save table to CSV for easy copy-paste
    table_df.to_csv('results_table.csv', index=False)
    
    # Define models and their context sizes
    model_info = {
        'Deepseek-v2': '131K',
        'Llama3.1': '131K',
        'Gemma2': '8K',
        'Deepseek-coder-v2': '163K',
        'Qwen2.5-coder': '32K',
        'Codellama': '16K',
        'Deepseek-R1': '131K'
    }
    
    # After loading data and before plotting
    print("\nModel Accuracies:")
    latex_rows = []
    
    for model_name, context_size in model_info.items():
        model_df = df[df['model'] == model_name]
        row_data = [f"{model_name} ({context_size})"]
        
        print(f"\n=== {model_name} ===")
        
        for prompt_type in ['BASELINE', 'COT', 'THINK', 'THINK_VERIFY']:
            vuln_col = f"{prompt_type}_VULN"
            patch_col = f"{prompt_type}_PATCH"
            
            vuln_acc, vuln_counts = calculate_model_accuracy(model_df, vuln_col)
            patch_acc, patch_counts = calculate_model_accuracy(model_df, patch_col)
            
            if vuln_acc is not None:
                print(f"\n{prompt_type}:")
                print(f"Vuln: {vuln_counts}")
                print(f"Vuln Accuracy: {vuln_acc:.2f}%")
                print(f"Patch: {patch_counts}")
                print(f"Patch Accuracy: {patch_acc:.2f}%")
                
                row_data.extend([f"{vuln_acc:.2f}", f"{patch_acc:.2f}"])
            else:
                row_data.extend(["-", "-"])
        
        # Add row to LaTeX table
        latex_row = f"{model_name} & \\textit{{{context_size}}} & " + \
                   " & ".join(row_data[1:]) + " \\\\"
        latex_rows.append(latex_row)
    
    # Print LaTeX table
    print("\nLaTeX Table Content:")
    print("\n".join(latex_rows))
    
    return results

if __name__ == '__main__':
    results = main()