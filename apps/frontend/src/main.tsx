import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { createFixtureClient } from './client';
import './styles.css';

const root = document.getElementById('root');
if (!root) throw new Error('Application root is unavailable.');
createRoot(root).render(<StrictMode><App client={createFixtureClient()} /></StrictMode>);
