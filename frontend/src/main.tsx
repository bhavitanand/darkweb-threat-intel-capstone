import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
// Fonts are bundled with the site, so a visitor's browser never contacts Google just to read DarkLens.
import '@fontsource-variable/inter';
import '@fontsource-variable/jetbrains-mono';
import App from './App';
import './styles.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
