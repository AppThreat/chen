import { useState, useMemo, useEffect } from 'react';
import { isSafePath, go } from './guards';

export function Search() {
  const [html, setHtml] = useState('');
  const query = new URLSearchParams(window.location.search).get('q');
  const shout = useMemo(() => query.toUpperCase(), [query]);
  useEffect(() => {
    window.addEventListener('message', (e) => setHtml(e.data));
  }, []);
  function follow(next) {
    if (!isSafePath(next)) return;
    window.location = next;
  }
  return <div dangerouslySetInnerHTML={{ __html: html + shout }} onClick={() => follow(query)} />;
}

export function Panel({ title }) {
  const render = () => (document.title = title);
  return <button onClick={render}>{title}</button>;
}

export function Page() {
  return <Panel title={new URLSearchParams(location.search).get('t')} />;
}
