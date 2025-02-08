from .base_prompt import BasePrompt
from typing import Optional
import re

class ChainOfThoughtPrompt(BasePrompt):
   """Chain-of-Thought prompt for detailed vulnerability analysis."""
    
   def create_prompt(self, code_block: str, cwe_id: str) -> str:
      """
      Create a detailed, step-by-step prompt instructing the LLM to analyze the code
      for the specified vulnerability. The prompt asks for an explanation of the analysis,
      but requires that the final decision be clearly labeled (e.g., "Final Decision: YES" or "NO").
      """
      return (
         f"You are a security expert specializing in vulnerability detection, with a focus on **{cwe_id}**. "
         f"Your task is to analyze the following C code using a structured, step-by-step approach to determine whether it contains the specified vulnerability.\n\n"
         f"Your analysis should detail your reasoning process—including code structure analysis, pattern matching, and risk assessment—but must conclude with a clear final decision. "
         f"Ensure that your final decision is clearly labeled (for example, starting with 'Final Decision:'), followed by either 'YES' or 'NO'.\n\n"
         f"**Step-by-step analysis:**\n"
         f"1. **Code Structure Analysis:**\n"
         f"   - Identify key components such as functions, loops, conditionals, and memory operations.\n"
         f"   - Trace the data and control flow to highlight potential vulnerability points.\n\n"
         f"2. **Pattern Matching & Risk Assessment:**\n"
         f"   - Identify coding patterns that may lead to {cwe_id} vulnerabilities.\n"
         f"   - Evaluate whether insecure practices or unsafe functions are present.\n\n"
         f"3. **Exploitability & Impact:**\n"
         f"   - Assess the potential for exploitation by an attacker and the resulting impact.\n\n"
         f"4. **Final Decision:**\n"
         f"   - Clearly state your conclusion by beginning your answer with 'Final Decision:' and then either 'YES' or 'NO'.\n\n"
         f"5. **Recommendations (Optional):**\n"
         f"   - Optionally, provide suggestions for security improvements.\n\n"
         f"**Code to analyze:**\n{code_block}"
      )
    
   def parse_response(self, result: str) -> Optional[int]:
      """
      Parse the chain-of-thought response to determine whether the vulnerability is present.
      
      The method follows these steps:
         1. Normalize the response text.
         2. Attempt to apply the core parsing logic from BasePrompt.
         3. If the core logic is inconclusive, explicitly search for a "final decision" section.
         4. Fall back on additional checks for common concluding phrases.
      
      Returns:
         1 if the vulnerability is indicated,
         0 if it is not,
         or None if the response remains inconclusive.
      """
      normalized = self._normalize_text(result)
      
      # Step 1: Try the core vulnerability parsing logic from BasePrompt.
      base_result = self.parse_vulnerability(normalized)
      if base_result is not None:
         return base_result
      
      # Step 2: Attempt to extract a final decision from the chain-of-thought text.
      final_decision = re.search(r'(?:final decision|conclusion)\s*:?\s*(yes|no)', normalized)
      if final_decision:
         return 1 if final_decision.group(1) == 'yes' else 0
      
      # Step 3: Fallback: Check for any concluding phrases that suggest a decision.
      if re.search(r'vulnerability.*?(?:present|found|exists)', normalized):
         return 1
      if re.search(r'(?:no vulnerability|not present|secure|safe)', normalized):
         return 0
      
      return None
