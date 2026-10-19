// Applied synchronously in <head> to avoid a flash of the wrong theme.
// Only the UI theme preference is persisted; never keys or data.
(function () {
  try {
    var t = localStorage.getItem("skycipher-theme");
    if (t === "dark" || t === "light") document.documentElement.dataset.theme = t;
  } catch (_) { /* storage unavailable */ }
})();
