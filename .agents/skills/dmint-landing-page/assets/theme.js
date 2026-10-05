/* Dmint landing page — theme toggle with a spreading-circle reveal.
 *
 * Clicking the icon doesn't just swap colors — the new theme expands
 * outward from the icon across the whole page. This uses the View
 * Transitions API (document.startViewTransition), which snapshots the
 * page before and after a DOM change and lets us animate between them.
 * We drive that animation with an expanding circle clip-path centered
 * on the click coordinates, sized to reach the farthest corner of the
 * viewport so the whole page is covered by the end of the animation.
 *
 * Browsers without View Transitions support (or a user with
 * prefers-reduced-motion: reduce) get an instant swap instead — never a
 * broken or half-finished animation.
 */
(function () {
  var toggle = document.getElementById('theme-toggle');
  if (!toggle) return;

  function getTheme() {
    return (
      document.documentElement.getAttribute('data-theme') ||
      (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark')
    );
  }

  function updateLabel(theme) {
    // The label always names the action, not the current state.
    toggle.setAttribute(
      'aria-label',
      theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'
    );
  }

  updateLabel(getTheme());

  toggle.addEventListener('click', function (event) {
    var current = getTheme();
    var next = current === 'dark' ? 'light' : 'dark';

    function applyTheme() {
      document.documentElement.setAttribute('data-theme', next);
      updateLabel(next);
      try {
        localStorage.setItem('dmint-theme', next);
      } catch (e) {
        /* localStorage can throw in private/locked-down contexts —
           the toggle still works for the rest of this visit. */
      }
    }

    var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if (reduceMotion || typeof document.startViewTransition !== 'function') {
      applyTheme();
      return;
    }

    // Circle origin: the icon's own center, not the raw click point —
    // keyboard activation (Enter/Space) fires a click with no
    // coordinates, so this works the same way for mouse and keyboard.
    var rect = toggle.getBoundingClientRect();
    var x = rect.left + rect.width / 2;
    var y = rect.top + rect.height / 2;

    var endRadius = Math.hypot(
      Math.max(x, window.innerWidth - x),
      Math.max(y, window.innerHeight - y)
    );

    var transition = document.startViewTransition(applyTheme);

    transition.ready
      .then(function () {
        document.documentElement.animate(
          {
            clipPath: [
              'circle(0px at ' + x + 'px ' + y + 'px)',
              'circle(' + endRadius + 'px at ' + x + 'px ' + y + 'px)',
            ],
          },
          {
            duration: 600,
            easing: 'ease-in-out',
            pseudoElement: '::view-transition-new(root)',
          }
        );
      })
      .catch(function () {
        /* transition.ready rejecting doesn't undo applyTheme() — the
           theme change already happened, we just lose the animation. */
      });
  });
})();
