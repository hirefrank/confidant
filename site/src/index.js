export default {
  fetch(request, env) {
    const url = new URL(request.url);
    const prefix = '/confidant';
    if (url.pathname === prefix || url.pathname.startsWith(prefix + '/')) {
      url.pathname = url.pathname.slice(prefix.length) || '/';
      return env.ASSETS.fetch(new Request(url, request));
    }
    return env.ASSETS.fetch(request);
  },
};
