import ast
import subprocess


def parse_literal(expression: str) -> object:
    return ast.literal_eval(expression)


def show_status() -> None:
    subprocess.run(["printf", "%s\\n", "ready"], check=True)
