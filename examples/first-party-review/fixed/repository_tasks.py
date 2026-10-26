import subprocess


def run_task(task):
    # Callers choose a known task; they cannot supply a command or arguments.
    commands = {"check": ["make", "check"], "test": ["make", "test"]}
    if task not in commands:
        raise ValueError("Choose check or test")
    return subprocess.run(commands[task], shell=False, check=True)
