(() => {
  const port = window.location.port;
  const normalizePath = (pathname) => {
    if (pathname.startsWith('/public/')) {
      return pathname.slice('/public'.length);
    }
    if (pathname === '/public') {
      return '/';
    }
    return pathname;
  };

  if (port === '5500' || window.location.protocol === 'file:') {
    const safePath = normalizePath(window.location.pathname);
    const target = `http://localhost:5000${safePath}${window.location.search}${window.location.hash}`;
    window.location.replace(target);
    return;
  }

  if (port === '5000' && window.location.pathname.startsWith('/public/')) {
    const safePath = normalizePath(window.location.pathname);
    const target = `${window.location.origin}${safePath}${window.location.search}${window.location.hash}`;
    window.location.replace(target);
    return;
  }

  window.API_BASE = window.location.origin;
})();
