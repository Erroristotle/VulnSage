import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# LOWESS smoother
from statsmodels.nonparametric.smoothers_lowess import lowess

# -----------------------------
# 1. Connect to the database
# -----------------------------
db_path = '/users/azibaeir/Research/Benchmarking/project/vulnerability_dataset/database/database.sqlite'
conn = sqlite3.connect(db_path)

# ----------------------------------------------------
# 2. Read Noise info (commit -> noise amount) once
# ----------------------------------------------------
vuln_df = pd.read_sql_query(
    """
    SELECT COMMIT_HASH, NOISE_AMOUNT
    FROM vulnerabilities
    WHERE NOISE_AMOUNT IS NOT NULL
    """,
    conn
)

# ----------------------------------------------------
# 3. List of model tables to process
# ----------------------------------------------------
model_tables = [
    'vulnerabilities_deepseek_r1_7b',
    'vulnerabilities_llama3_1_8b',
    'vulnerabilities_gemma2_9b',
    'vulnerabilities_qwen2_5_coder_7b',
    'vulnerabilities_codellama_7b',
    'vulnerabilities_deepseek_r1_32b',
    'vulnerabilities_deepseek_v2_16b',
    'vulnerabilities_deepseek_coder_16b',
    'vulnerabilities_qwen2_5_coder_32b',
    'vulnerabilities_codellama_34b'
]

# ----------------------------------------------------
# 4. Define columns to average for Overall Accuracy
# ----------------------------------------------------
vuln_cols = ['BASELINE_VULN', 'COT_VULN', 'THINK_VULN', 'THINK_VERIFY_VULN']
patch_cols = ['BASELINE_PATCH', 'COT_PATCH', 'THINK_PATCH', 'THINK_VERIFY_PATCH']

# ----------------------------------------------------
# 5. Convert "2" to 0.5, keep "0" or "1" as-is
# ----------------------------------------------------
def map_ambiguous_to_half(x):
    try:
        val = float(x)
        if val == 2:
            return 0.5
        return val
    except:
        return np.nan

all_models_list = []

# ----------------------------------------------------
# 6. Read each model's data and compute accuracy
# ----------------------------------------------------
for table_name in model_tables:
    try:
        query = f"""
            SELECT 
                COMMIT_HASH,
                BASELINE_VULN, BASELINE_PATCH,
                COT_VULN, COT_PATCH,
                THINK_VULN, THINK_PATCH,
                THINK_VERIFY_VULN, THINK_VERIFY_PATCH
            FROM {table_name}
            WHERE BASELINE_VULN IS NOT NULL
              AND COT_VULN IS NOT NULL
              AND THINK_VULN IS NOT NULL
              AND THINK_VERIFY_VULN IS NOT NULL
        """
        model_df = pd.read_sql_query(query, conn)
        
        if len(model_df) == 0:
            print(f"[WARNING] No valid data in table {table_name}")
            continue
        
        # Convert columns to numeric & handle "2" -> 0.5
        for col in vuln_cols + patch_cols:
            model_df[col] = pd.to_numeric(model_df[col], errors='coerce').apply(map_ambiguous_to_half)
        
        # Mean across all four prompts => final vulns & patch accuracies
        model_df['vuln_accuracy'] = model_df[vuln_cols].mean(axis=1) * 100.0
        model_df['patch_accuracy'] = model_df[patch_cols].mean(axis=1) * 100.0
        
        # Merge with noise amounts
        merged = pd.merge(model_df, vuln_df, on='COMMIT_HASH', how='inner')
        if len(merged) == 0:
            print(f"[WARNING] After merge, no matching data for {table_name}")
            continue
        
        # Clean up model name
        model_name = table_name.replace('vulnerabilities_', '').replace('_', ' ').title()
        merged['model_name'] = model_name
        
        # Keep relevant columns
        merged = merged[['COMMIT_HASH', 'model_name', 'vuln_accuracy', 'patch_accuracy', 'NOISE_AMOUNT']]
        merged['vuln_accuracy']   = pd.to_numeric(merged['vuln_accuracy'], errors='coerce')
        merged['patch_accuracy']  = pd.to_numeric(merged['patch_accuracy'], errors='coerce')
        merged['NOISE_AMOUNT']    = pd.to_numeric(merged['NOISE_AMOUNT'], errors='coerce')
        
        all_models_list.append(merged)
        
    except Exception as e:
        print(f"[ERROR] Problem reading table {table_name}: {str(e)}")

conn.close()

# ----------------------------------------------------
# 7. Combine all models' data and drop missing
# ----------------------------------------------------
if not all_models_list:
    print("No valid data found across all tables.")
    exit()

final_df = pd.concat(all_models_list, ignore_index=True).dropna()
if len(final_df) == 0:
    print("No valid rows remain after dropping NAs.")
    exit()

# ----------------------------------------------------
# 8. Bin noise amounts in 0–10%, 10–20%, ... 90–100%
# ----------------------------------------------------
bins = np.arange(0, 101, 10)  # [0,10,20,30,...,90,100]
labels = [f"{b}-{b+10}" for b in bins[:-1]]  # e.g. '0-10', '10-20', ...
final_df['noise_bin'] = pd.cut(
    final_df['NOISE_AMOUNT'],
    bins=bins,
    labels=labels,
    include_lowest=True,
    right=False  # each bin includes left edge, excludes right edge
)

# ----------------------------------------------------
# 9. For each model & noise_bin, compute mean accuracy
# ----------------------------------------------------
df_vuln_binned = (
    final_df
    .groupby(['model_name','noise_bin'])['vuln_accuracy']
    .mean()
    .reset_index()
)
df_patch_binned = (
    final_df
    .groupby(['model_name','noise_bin'])['patch_accuracy']
    .mean()
    .reset_index()
)

# ----------------------------------------------------
# 10. Convert noise_bin to numeric bin centers
#     so we can do a smooth line in Matplotlib
# ----------------------------------------------------
# Each 'noise_bin' is an interval like [0,10) in pd.cut()
# or a label like "0-10". We can map them to mid-points (5,15,...).
# If you used right=False, each bin is something like [0,10).
# We can parse that from the bin interval, or from the string label.
def bin_label_to_center(label: str) -> float:
    # label is "0-10", "10-20", ...
    left_str, right_str = label.split('-')
    return (float(left_str) + float(right_str)) / 2.0

df_vuln_binned['bin_center']  = df_vuln_binned['noise_bin'].astype(str).apply(bin_label_to_center)
df_patch_binned['bin_center'] = df_patch_binned['noise_bin'].astype(str).apply(bin_label_to_center)

# ----------------------------------------------------
# 11. Plot: Vulnerability Accuracy vs Noise
# ----------------------------------------------------
plt.figure(figsize=(10,6))
ax1 = plt.gca()

unique_models = df_vuln_binned['model_name'].unique()

for model_name in unique_models:
    model_data = df_vuln_binned[df_vuln_binned['model_name'] == model_name].dropna()
    # If not enough points, skip
    if len(model_data) < 1:
        continue
    
    # Sort by bin_center to avoid zig-zag lines
    model_data = model_data.sort_values(by='bin_center')
    
    # Scatter the binned means
    ax1.scatter(
        model_data['bin_center'],
        model_data['vuln_accuracy'],
        label=model_name,
        alpha=0.6
    )
    
    # LOWESS smoothing
    if len(model_data) >= 3:
        smoothed_vuln = lowess(
            endog=model_data['vuln_accuracy'],
            exog=model_data['bin_center'],
            frac=0.5  # smoothing parameter; tune as needed
        )
        ax1.plot(smoothed_vuln[:,0], smoothed_vuln[:,1])
    else:
        # With <3 points, just connect them directly
        ax1.plot(model_data['bin_center'], model_data['vuln_accuracy'])

ax1.set_xticks([5,15,25,35,45,55,65,75,85,95])
ax1.set_xticklabels(labels)
ax1.set_xlabel('Noise Bins (%)')
ax1.set_ylabel('Vulnerability Accuracy (%)')
ax1.set_title('Vulnerability Detection vs. Noise (Binned + LOWESS)')
ax1.grid(True, alpha=0.3)
# ax1.legend(loc='best', title='Model', ncol=1)
ax1.legend(
    loc='upper left', bbox_to_anchor=(1.02, 1), title='Model', ncol=2, frameon=True
)

plt.tight_layout()
plt.savefig('vulnerability_vs_noise_binned_lowess.png', dpi=300)
plt.close()

# ----------------------------------------------------
# 12. Plot: Patch Accuracy vs Noise
# ----------------------------------------------------
plt.figure(figsize=(10,6))
ax2 = plt.gca()

for model_name in unique_models:
    model_data = df_patch_binned[df_patch_binned['model_name'] == model_name].dropna()
    if len(model_data) < 1:
        continue
    
    model_data = model_data.sort_values(by='bin_center')
    
    ax2.scatter(
        model_data['bin_center'],
        model_data['patch_accuracy'],
        label=model_name,
        alpha=0.6
    )
    
    # LOWESS smoothing
    if len(model_data) >= 3:
        smoothed_patch = lowess(
            endog=model_data['patch_accuracy'],
            exog=model_data['bin_center'],
            frac=0.5
        )
        ax2.plot(smoothed_patch[:,0], smoothed_patch[:,1])
    else:
        ax2.plot(model_data['bin_center'], model_data['patch_accuracy'])

ax2.set_xticks([5,15,25,35,45,55,65,75,85,95])
ax2.set_xticklabels(labels)
ax2.set_xlabel('Noise Bins (%)')
ax2.set_ylabel('Patch Correctness Accuracy (%)')
ax2.set_title('Patch Correctness vs. Noise (Binned + LOWESS)')
ax2.grid(True, alpha=0.3)
# ax2.legend(loc='best', title='Model', ncol=1)
ax2.legend(
    loc='upper left', bbox_to_anchor=(1.02, 1), title='Model', ncol=2, frameon=True
)

plt.tight_layout()
plt.savefig('patch_vs_noise_binned_lowess.png', dpi=300)
plt.close()

print("Done! Two charts saved:\n"
      " - vulnerability_vs_noise_binned_lowess.png\n"
      " - patch_vs_noise_binned_lowess.png\n")
