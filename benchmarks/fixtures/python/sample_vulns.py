import subprocess
import pickle

def run_user_code(user_input, safe_data):
    # Dangerous dynamic eval
    eval(user_input)
    # Dangerous shell injection
    subprocess.run(user_input, shell=True)
    # Dangerous deserialization
    pickle.loads(safe_data)
