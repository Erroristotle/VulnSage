import requests
import json
import time

def test_single_query(model_name: str) -> bool:
    """Test a single query to Ollama."""
    API_URL = "http://localhost:11434/api/generate"
    
    payload = {
        "model": model_name,
        "prompt": "Hi, what is your model name?"
    }
    
    try:
        print(f"\nTesting single query with model: {model_name}")
        response = requests.post(API_URL, json=payload)
        
        if response.status_code == 200:
            response_lines = response.content.decode('utf-8').splitlines()
            full_response = ''.join([json.loads(line)["response"] for line in response_lines if line])
            print("Single Query Response:", full_response)
            return True
        else:
            print(f"Error: Received status code {response.status_code}")
            return False
            
    except Exception as e:
        print(f"Error in single query: {e}")
        return False

def test_batch_query(model_name: str) -> bool:
    """Test if Ollama supports batch processing."""
    API_URL = "http://localhost:11434/api/generate"
    
    # Test with a small batch of prompts
    batch_prompts = [
        "What is 2+2?",
        "What is your model name?",
        "Hello, how are you?"
    ]
    
    # Try different batch payload formats
    payloads = [
        # Format 1: List of prompts
        {
            "model": model_name,
            "prompts": batch_prompts
        },
        # Format 2: Array of complete requests
        [{
            "model": model_name,
            "prompt": prompt
        } for prompt in batch_prompts],
        # Format 3: Single request with array
        {
            "model": model_name,
            "prompt": batch_prompts
        }
    ]
    
    print("\nTesting batch processing capabilities...")
    
    for i, payload in enumerate(payloads, 1):
        try:
            print(f"\nTrying batch format {i}:")
            print(f"Payload structure: {json.dumps(payload, indent=2)}")
            
            response = requests.post(API_URL, json=payload)
            print(f"Status Code: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    # Try to parse the response
                    if isinstance(response.content, bytes):
                        response_text = response.content.decode('utf-8')
                    else:
                        response_text = response.content
                        
                    print(f"Raw Response: {response_text[:500]}...")  # Show first 500 chars
                    
                    # Try to parse as JSON
                    try:
                        json_response = response.json()
                        print("Parsed JSON Response:", json.dumps(json_response, indent=2))
                    except json.JSONDecodeError:
                        print("Response is not JSON format")
                        
                    print("\nBatch format seems to work!")
                except Exception as e:
                    print(f"Error parsing response: {e}")
            else:
                print(f"Request failed: {response.text}")
                
        except Exception as e:
            print(f"Error testing batch format {i}: {e}")
        
        print("\nWaiting before next test...")
        time.sleep(2)
    
    return False  # Return False as we haven't found a working batch format

def main():
    """Main test function."""
    model_name = "deepseek-r1"  # Use your current model
    
    # First test single query
    if not test_single_query(model_name):
        print("\nSingle query test failed. Please check if Ollama is running correctly.")
        return
        
    # Then test batch processing
    batch_support = test_batch_query(model_name)
    
    print("\nTest Results:")
    print("Single Query: Success")
    print(f"Batch Processing: {'Supported' if batch_support else 'Not Supported'}")
    
    if not batch_support:
        print("\nRecommendation: Implement sequential processing for multiple prompts")

if __name__ == "__main__":
    main()