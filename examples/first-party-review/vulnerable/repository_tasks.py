import subprocess


def run_task(task):
    # A caller's task name becomes shell syntax.
    return subprocess.run(f"make {task}", shell=True, check=True)
