import subprocess


def evaluate_user_expression(expression: str) -> object:
    return eval(expression)


def execute_user_statement(statement: str) -> None:
    exec(statement)


def run_user_command(command: str) -> None:
    subprocess.run(command, shell=True, check=True)
