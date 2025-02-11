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
      Parse the LLM's response for the chain-of-thought prompt.
      
      Instead of attempting to extract the final decision with regex, this method simply delegates
      the decision extraction to the deepseek-r1-7b model. In our base class, the method parse_vulnerability()
      calls llm_final_decision() which sends the entire response to deepseek-r1-7b with a prompt asking
      for a final single-digit answer.
      
      Returns:
         1 if the vulnerability is detected,
         0 if it is not,
         or None if the decision is ambiguous.
      """
      return self.parse_vulnerability(result)
