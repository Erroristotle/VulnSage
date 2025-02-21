import requests
import json

def test_ollama_api():
    # Set your API URL and model identifier.
    # Adjust the model identifier as needed; here we use "codellama:custom" as an example.
    API_URL = "http://localhost:11434/api/generate"
    model = "deepseek-r1-32b:custom"
    
    prompt = "What is 2+2?"
    payload = {
        "model": model,
        "prompt": prompt,
        "temperature": 0.7,
        "stream": False
    }
    
    try:
        response = requests.post(API_URL, json=payload, timeout=30)
        if response.status_code == 200:
            # The response may be streamed as separate lines.
            output = ""
            for line in response.content.decode("utf-8").splitlines():
                if line.strip():
                    try:
                        parsed = json.loads(line)
                        output += parsed.get("response", "")
                    except Exception as parse_error:
                        print("Error parsing line:", parse_error)
            print("Ollama API response:")
            print(output)
        else:
            print(f"Error: Received status code {response.status_code}")
    except Exception as e:
        print("Error calling Ollama API:", e)

if __name__ == "__main__":
    test_ollama_api()
