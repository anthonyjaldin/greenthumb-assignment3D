// public/app.js
//
// Client-side code for the listing page. It supports a "shared note" feature:
// a note can be appended to the URL, e.g.  /listing/1#note=hello  and the page
// shows it in a banner.
//
// FIX 4 (DOM-based XSS): the note comes from location.hash, which an attacker
// controls through a crafted link. It is rendered with .textContent, never
// .innerHTML, so markup in the URL is shown literally instead of executed.

(function () {
  const bannerEl = document.getElementById('share-banner');
  if (!bannerEl) return;

  if (location.hash.startsWith('#note=')) {
    const note = decodeURIComponent(location.hash.replace(/^#note=/, ''));

    const banner = document.createElement('div');
    banner.className = 'banner';
    banner.textContent = `📎 Shared note: ${note}`;
    bannerEl.replaceChildren(banner);
  }
})();
