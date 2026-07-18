(function () {
	'use strict';

	document.querySelectorAll('.ghost-mode-toggle-password').forEach(function (btn) {
		btn.addEventListener('click', function () {
			var id = btn.getAttribute('data-target');
			var input = id ? document.getElementById(id) : null;
			if (!input) {
				return;
			}

			var show = input.type === 'password';
			input.type = show ? 'text' : 'password';
			btn.classList.toggle('is-visible', show);
			btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
			btn.setAttribute('aria-pressed', show ? 'true' : 'false');
		});
	});
})();
