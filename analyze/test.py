import pandas as pd
import matplotlib.pyplot as plt

# Load vulnerabilities.csv to find the top 5 most frequent CWEs
vuln_file_path = "vulnerabilities.csv"
vuln_df = pd.read_csv(vuln_file_path)

# Find the top 5 most frequent CWEs
top_cwes = vuln_df["VULNERABILITY_CWE"].value_counts().head(5).index.tolist()
print(top_cwes)
print(f"number of each CWE: {vuln_df['VULNERABILITY_CWE'].value_counts()}")
# Load the llama3_1_8b.csv file
llama_file_path = "vulnerabilities_llama3_1_8b.csv"
llama_df = pd.read_csv(llama_file_path)

# Merge vulnerabilities.csv with llama3_1_8b.csv on COMMIT_HASH to get CWE labels
merged_df = vuln_df[['COMMIT_HASH', 'VULNERABILITY_CWE']].merge(llama_df, on='COMMIT_HASH')

# Filter for only the top 5 CWEs
filtered_df = merged_df[merged_df['VULNERABILITY_CWE'].isin(top_cwes)]

# Define correct answers (1 for VULN, 0 for PATCH)
correct_vuln = 1
correct_patch = 0

# Compute accuracy for each prompt
accuracy_results = {}

for prompt in ['BASELINE_VULN', 'BASELINE_PATCH', 'COT_VULN', 'COT_PATCH', 
               'THINK_VULN', 'THINK_PATCH', 'THINK_VERIFY_VULN', 'THINK_VERIFY_PATCH']:
    if 'VULN' in prompt:
        accuracy = (filtered_df[prompt] == correct_vuln).mean() * 100  # Percentage accuracy
    else:
        accuracy = (filtered_df[prompt] == correct_patch).mean() * 100
    accuracy_results[prompt] = accuracy

# Convert to DataFrame for visualization
accuracy_df = pd.DataFrame(list(accuracy_results.items()), columns=['Prompt', 'Accuracy'])

# Generate a bar chart for accuracy of each prompt
plt.figure(figsize=(12, 6))
plt.bar(accuracy_df['Prompt'], accuracy_df['Accuracy'])
plt.xlabel('Prompt')
plt.ylabel('Accuracy (%)')
plt.title('Accuracy of Each Prompt for Top 5 CWEs')
plt.xticks(rotation=45)
plt.ylim(0, 100)
plt.show()
