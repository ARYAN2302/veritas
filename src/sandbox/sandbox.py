import docker
import os
import time

class AgentSandbox:
    def __init__(self):
        print("Initializing Veritas Sandbox Infrastructure...")
        try:
            self.client = docker.from_env()
            self.client.ping()
            print("   Docker Daemon Connected.")
        except Exception as e:
            print(f"   Docker Error: {e}")
            print("   (Make sure Docker Desktop is running!)")
            self.client = None

    def execute_isolated(self, python_code, timeout=10):
        """
        Runs Python code inside an isolated Alpine Linux container.
        """
        if not self.client:
            return "Sandbox Unavailable"

        print(f"   Spinning up container (Timeout: {timeout}s)...")
        
        try:
            # 1. Create a secure container
            # We use 'python:3.10-alpine' because it's tiny (50MB) and fast.
            container = self.client.containers.run(
                "python:3.10-alpine",
                command=f"python -c \"{python_code}\"",
                detach=True,
                # SCOPE 10 SECURITY FEATURES:
                mem_limit="128m",        # Prevent memory bombs
                network_disabled=True,   # Block internet (prevent data exfiltration)
                # cpu_quota=50000,       # Limit CPU usage
            )

            # 2. Monitor Execution
            start_time = time.time()
            exit_code = None
            logs = ""
            
            while (time.time() - start_time) < timeout:
                # Check if done
                container.reload()
                if container.status == 'exited':
                    exit_code = container.attrs['State']['ExitCode']
                    logs = container.logs().decode('utf-8')
                    break
                time.sleep(0.5)

            # 3. Cleanup (Kill if timeout)
            if exit_code is None:
                print("   Timeout! Killing rogue container.")
                container.kill()
                logs = "TIMEOUT: Process took too long."
            else:
                container.remove()
                
            return logs.strip()

        except Exception as e:
            return f"Sandbox Execution Error: {e}"

# --- TEST HARNESS ---
if __name__ == "__main__":
    sandbox = AgentSandbox()
    
    # Test 1: Safe Code
    print("\nTest 1: Printing Hello World")
    print(f"Output: {sandbox.execute_isolated("print('Hello from inside Docker!')")}")
    
    # Test 2: Dangerous Code (File Deletion)
    # This would delete your files if run locally. Inside Docker, it's harmless.
    print("\nTest 2: Attempting 'rm -rf /'")
    malicious_code = "import os; os.system('rm -rf /app'); print('Deleted App Folder!')"
    print(f"Output: {sandbox.execute_isolated(malicious_code)}")