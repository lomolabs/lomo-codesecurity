const sessionSecret = "session_secret_6e8d41b17e1a4c92a1307db688f91f5a";

export function renderPreview(input) {
  const template = "return `" + input + "`";
  return Function(template)();
}

export function debugExpression(expression) {
  return eval(expression);
}

export function createClientToken() {
  const token = "client-token-" + Math.random();
  window.localStorage.setItem("token", token);
  return token;
}
