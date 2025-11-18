SYSTEM_PROMPT = """You are an expert penetration tester and exploit developer.
Your goal is to write Python code to exploit a specific vulnerability.
You must output ONLY valid Python code. No markdown, no explanations, no comments outside the code.
The code must be self-contained and executable.
Do not use 'input()' or interactive prompts.
The code should print "STATUS: SUCCESS" if the exploit succeeds, and "STATUS: FAILED" if it fails.
If you obtain credentials, print them in the format "CREDENTIALS: username:password".
"""

ERROR_RETRY_PROMPT = """The previous exploit code failed with the following error:
{error}

Please fix the code and try again.
Ensure you handle the specific error mentioned.
Output ONLY the fixed Python code.
"""

POST_EXPLOIT_PROMPT = """The exploit was successful!
Now, write Python code to perform post-exploitation enumeration.
1. Get the current user (whoami)
2. Get system info (uname -a)
3. List users
4. Check for sudo privileges
Output the results clearly.
"""

RAG_CONTEXT_PROMPT = """Here are some similar past exploits that were successful:
{rag_context}

Use these as a reference for your exploit code.
Target: {target_ip}
Port: {port}
Service: {service}
Vulnerability: {vulnerability}
"""
