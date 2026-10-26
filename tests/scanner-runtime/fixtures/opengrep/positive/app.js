const child_process = require("child_process");

function evaluateUserExpression(expression) {
  return eval(expression);
}

function runUserCommand(command) {
  return child_process.exec(command);
}

module.exports = { evaluateUserExpression, runUserCommand };
