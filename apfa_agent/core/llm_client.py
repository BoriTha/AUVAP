import logging
import sys
import os
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class UniversalLLMClient:
    """
    Universal LLM Client supporting multiple providers via LiteLLM.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.use_dummy = False
        self.litellm_available = False
        self.model = None
        self.api_base = None
        
        try:
            import litellm
            self.litellm = litellm
            self.litellm_available = True
        except ImportError:
            self.litellm_available = False
        
        # Determine model to use from config ONLY
        llm_config = self.config.get('llm', {})
        models = llm_config.get('models', [])
        
        # Debug: print available models
        logger.info(f"Configured models: {[m.get('name') for m in models]}")
        
        if models:
            # Get enabled models
            enabled_models = [x for x in models if x.get('enabled')]
            idx = 0
            
            while idx < len(enabled_models):
                m = enabled_models[idx]
                model_name = m.get('model')
                
                if model_name:
                    # Use model name as-is from config (user controls the format)
                    self.model = str(model_name)
                    self.api_base = m.get('endpoint')  # Optional endpoint override
                    self.provider = m.get('provider', 'unknown')
                    
                    # For OpenRouter, prepend openrouter/ if not already present
                    if self.provider == 'openrouter' and not self.model.startswith('openrouter/'):
                        self.model = f"openrouter/{self.model}"
                    
                    print(f"\n[{idx + 1}/{len(enabled_models)}] Testing model: {m.get('name')} ({self.provider})")
                    print(f"    Model: {self.model}")
                    if self.api_base:
                        print(f"    Endpoint: {self.api_base}")
                    
                    # Try to use this model
                    if not self.litellm_available:
                        print(f"    ✗ Failed: litellm not installed")
                        idx += 1
                        continue
                        
                    try:
                        # Test with a simple completion
                        test_kwargs = {
                            "model": self.model,
                            "messages": [{"role": "user", "content": "test"}],
                            "max_tokens": 10
                        }
                        if self.api_base:
                            test_kwargs['api_base'] = self.api_base
                            
                        test_response = self.litellm.completion(**test_kwargs)
                        if test_response and (hasattr(test_response, 'choices') or isinstance(test_response, dict)):
                            print(f"    ✓ Connection successful! Using {m.get('name')}")
                            logger.info(f"✓ {self.model} is working!")
                            break  # Success! Use this model
                        else:
                            raise Exception("Invalid response format")
                            
                    except Exception as test_e:
                        error_msg = str(test_e)
                        print(f"    ✗ Failed: {error_msg}")
                        logger.error(f"✗ {self.model} failed: {error_msg}")
                        
                        # Count remaining enabled models
                        remaining = len(enabled_models) - idx - 1
                        
                        if remaining > 0:
                            next_model = enabled_models[idx + 1]
                            print(f"\n    Next available: {next_model.get('name')} ({next_model.get('provider', 'unknown')})")
                            
                            # Check for non-interactive mode
                            if os.environ.get('APFA_NON_INTERACTIVE') == 'true':
                                print("    Non-interactive mode: Switching to next model...")
                                idx += 1
                                continue
                            
                            while True:
                                choice = input("    [R]etry / [S]witch to next / [Q]uit: ").strip().lower()
                                if choice in ['r', 'retry']:
                                    print("    Retrying current model...")
                                    # Don't increment idx - retry same model
                                    break
                                elif choice in ['s', 'switch', 'next', 'n']:
                                    print("    Switching to next model...")
                                    idx += 1
                                    break
                                elif choice in ['q', 'quit', 'exit']:
                                    print("    Exiting...")
                                    sys.exit(1)
                                else:
                                    print("    Invalid choice. Please enter R, S, or Q.")
                        else:
                            # No more models to try
                            print("    No more models available.")
                            idx += 1
                else:
                    idx += 1
        
        # If no model found in list, check legacy single model config, but DO NOT default to GPT-3.5
        if not self.model and self.config.get('model'):
             self.model = str(self.config.get('model'))
             self.api_base = None # Legacy config didn't support complex endpoint overrides easily here
             logger.info(f"Selected legacy model: {self.model}")

        if not self.model:
            logger.warning("No enabled model found in config.yaml!")
        
        # Store enabled models list for runtime fallback
        self.enabled_models = [x for x in models if x.get('enabled')] if models else []
        self.current_model_idx = 0  # Track which model we're using

    def _try_next_model(self) -> bool:
        """
        Try to switch to the next available model.
        Returns True if a new model was found, False otherwise.
        """
        if not self.enabled_models:
            return False
        
        self.current_model_idx += 1
        
        while self.current_model_idx < len(self.enabled_models):
            m = self.enabled_models[self.current_model_idx]
            model_name = m.get('model')
            
            if model_name:
                # Use model name as-is from config
                self.model = str(model_name)
                self.api_base = m.get('endpoint')
                self.provider = m.get('provider', 'unknown')
                
                # For OpenRouter, prepend openrouter/ if not already present
                if self.provider == 'openrouter' and not self.model.startswith('openrouter/'):
                    self.model = f"openrouter/{self.model}"
                
                print(f"\n[Auto-switching] Trying model: {m.get('name')} ({self.provider})")
                print(f"    Model: {self.model}")
                
                # Test the model
                try:
                    test_kwargs = {
                        "model": self.model,
                        "messages": [{"role": "user", "content": "test"}],
                        "max_tokens": 10
                    }
                    if self.api_base:
                        test_kwargs['api_base'] = self.api_base
                    
                    test_response = self.litellm.completion(**test_kwargs)
                    if test_response:
                        print(f"    ✓ Success! Using {m.get('name')}")
                        logger.info(f"✓ Switched to {self.model}")
                        return True
                except Exception as e:
                    print(f"    ✗ Failed: {str(e)}")
                    logger.error(f"✗ {self.model} failed: {str(e)}")
                    self.current_model_idx += 1
                    continue
            else:
                self.current_model_idx += 1
        
        return False

    def _prompt_user_fallback(self, error_msg: str) -> bool:
        """
        Ask user if they want to switch to dummy mode or stop.
        Returns True if dummy mode selected, exits if stop selected.
        """
        print(f"\n[!] LLM Error: {error_msg}")
        print("    The agent cannot generate real exploits without a working LLM.")
        
        # Check for non-interactive environment
        if os.environ.get('APFA_NON_INTERACTIVE') == 'true':
            print("    Non-interactive mode detected. Exiting.")
            sys.exit(1)
            
        while True:
            print("    Do you want to switch to DUMMY mode (simulated exploits)?")
            choice = input("    [Y]es (dummy mode) / [N]o (stop execution): ").strip().lower()
            
            if choice in ['y', 'yes', 'dummy', 'd']:
                print("    -> Switching to DUMMY mode. Exploits will be simulated.")
                return True
            elif choice in ['n', 'no', 'stop', 's', '']:
                print("    -> Stopping execution. Please fix the LLM configuration.")
                sys.exit(1)

    def generate_code(self, prompt: str) -> str:
        """
        Generate code from the LLM.
        """
        # Return dummy immediately if already switched
        if self.use_dummy:
            return self._get_dummy_exploit()

        # Check if model is selected
        if not self.model:
            if self._prompt_user_fallback("No enabled model found in agent_config.yaml"):
                self.use_dummy = True
                return self._get_dummy_exploit()
            # If they didn't choose dummy (and somehow didn't exit), try one last check?
            # But prompt_user_fallback exits if they say 'stop'.
            return ""

        logger.info(f"Generating code with model {self.model}...")
        
        # Check for library availability
        if not self.litellm_available:
            if self._prompt_user_fallback("litellm library not found (pip install litellm)"):
                self.use_dummy = True
                return self._get_dummy_exploit()
        
        try:
            # self.model is guaranteed to be str here because of check above
            model_name = str(self.model) 
            
            # Construct kwargs
            kwargs = {
                "model": model_name,
                "messages": [{"role": "user", "content": prompt}]
            }
            
            # Add api_base if configured (crucial for custom Ollama endpoints)
            if hasattr(self, 'api_base') and self.api_base:
                kwargs['api_base'] = self.api_base
                
            response = self.litellm.completion(**kwargs)
            
            content = ""
            # Safe extraction that satisfies linter
            if isinstance(response, dict):
                choices = response.get('choices', [])
                if choices and len(choices) > 0:
                    msg = choices[0].get('message', {})
                    content = msg.get('content', '')
            else:
                # Assume object-like response from litellm (ModelResponse)
                # We use getattr to avoid static analysis errors on unknown types
                choices = getattr(response, 'choices', [])
                if choices and len(choices) > 0:
                    first = choices[0]
                    message = getattr(first, 'message', None)
                    if message:
                        content = getattr(message, 'content', '')
            
            if not content:
                content = str(response) # Last resort
                
            # Basic check to ensure we didn't get an empty response
            if not content:
                raise ValueError("Received empty response from LLM")
            return content
            
        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            
            # Check if it's a rate limit error
            error_str = str(e).lower()
            if 'rate' in error_str and 'limit' in error_str:
                print(f"\n[!] Rate limit hit on {self.model}")
                print("    Attempting to switch to next available model...")
                
                # Try to switch to next model automatically
                if self._try_next_model():
                    print("    Retrying with new model...")
                    return self.generate_code(prompt)  # Recursive retry with new model
                else:
                    print("    No more models available.")
            
            if self._prompt_user_fallback(f"Execution error: {str(e)}"):
                self.use_dummy = True
                return self._get_dummy_exploit()
            return "" # Should not be reached

    def _get_dummy_exploit(self) -> str:
        return """
import sys
print("STATUS: SUCCESS")
print("CREDENTIALS: admin:admin")
"""

