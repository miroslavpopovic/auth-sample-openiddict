import {useEffect, useState} from 'react';
import reactLogo from './assets/react.svg'
import {useAuth} from 'react-oidc-context';
import viteLogo from '/vite.svg'
import './App.css'

function App() {
  const loggedOutMessage = 'You need to log in to be able to retrieve the data';
  const loggedInMessage = 'Click "Get weather forecast" button to retrieve the data';

  const auth = useAuth();
  const [data, setData] = useState<string>(
    auth.isAuthenticated
      ? loggedInMessage
      : loggedOutMessage);

  useEffect(() => {
    setData(auth.isAuthenticated ? loggedInMessage : loggedOutMessage)
  }, [auth]);

  switch (auth.activeNavigator) {
    case 'signinSilent':
      return <div>Signing you in...</div>;
    case 'signoutRedirect':
      return <div>Signing you out...</div>;
  }

  if (auth.isLoading) {
    return <div>Loading...</div>;
  }

  if (auth.error) {
    return <div>Error: {auth.error.message}</div>;
  }

  async function fetchData() {
    const request = new Request('https://localhost:7212/WeatherForecast', {
      headers: new Headers({
        'Authorization': `Bearer ${(auth.user!.access_token)}`,
        'X-CSRF': '1'
      })
    });

    let data: string;
    try {
      const response = await fetch(request);

      if (response.ok) {
        let jsonResponse = await response.json();
        data = JSON.stringify(jsonResponse, null, 2);
      } else {
        data = await response.text();
      }
    } catch (e) {
      data = 'Error getting weather forecast: ' + e;
    }

    setData(data);
  }

  return (
    <>
      <div>
        <a href="https://vitejs.dev" target="_blank">
          <img src={viteLogo} className="logo" alt="Vite logo"/>
        </a>
        <a href="https://react.dev" target="_blank">
          <img src={reactLogo} className="logo react" alt="React logo"/>
        </a>
      </div>
      <h1>Vite + React Auth client</h1>

      {auth.isAuthenticated ?
        <>
          <p>
            <button onClick={() => auth.removeUser()}>Log out</button>
            &nbsp;
            <button onClick={() => fetchData()}>Get weather forecast</button>
          </p>
        </>
        :
        <p>
          <button onClick={() => auth.signinRedirect()}>Log in</button>
        </p>
      }
      <pre>
        {data}
      </pre>
    </>);
}

export default App
