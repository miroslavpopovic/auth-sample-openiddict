import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.tsx'
import {AuthProvider} from 'react-oidc-context';
import './index.css'

const oidcConfig = {
  authority: 'https://localhost:7210',
  client_id: 'react-client',
  redirect_uri: 'http://localhost:7216/signin-oidc',
  scope: 'openid profile weather-api',
  onSigninCallback: () => {
    window.history.replaceState({}, document.title, '/');
  }
};

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AuthProvider {...oidcConfig}>
      <App/>
    </AuthProvider>
  </React.StrictMode>,
)
