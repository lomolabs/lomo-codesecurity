import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import AuthGate from './AuthGate';
import './styles.css';

const retainedVscodeBrowser = new URLSearchParams(window.location.search).get('lomo_browser') === 'vscode';
document.title = retainedVscodeBrowser ? 'Lomo CodeSecurity · VS Code' : 'Lomo CodeSecurity';

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <AuthGate><App /></AuthGate>
  </React.StrictMode>,
);
