<?php

function evaluate_user_expression(string $expression): mixed
{
    return eval($expression);
}

function run_user_command(string $command): string
{
    return shell_exec($command);
}
