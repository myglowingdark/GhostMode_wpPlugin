(function () {
	'use strict';

	document.querySelectorAll('.ghost-mode-copy').forEach(function (btn) {
		btn.addEventListener('click', function () {
			var id = btn.getAttribute('data-copy-target');
			var input = id ? document.getElementById(id) : null;
			if (!input) {
				return;
			}

			var value = input.value;
			var done = function () {
				var original = btn.textContent;
				btn.textContent = 'Copied';
				btn.classList.add('is-copied');
				setTimeout(function () {
					btn.textContent = original;
					btn.classList.remove('is-copied');
				}, 1500);
			};

			if (navigator.clipboard && navigator.clipboard.writeText) {
				navigator.clipboard.writeText(value).then(done).catch(function () {
					input.select();
					document.execCommand('copy');
					done();
				});
			} else {
				input.select();
				document.execCommand('copy');
				done();
			}
		});
	});

	var cfg = typeof ghostModeQuick !== 'undefined' ? ghostModeQuick : null;
	var modal = document.getElementById('ghost-mode-quick-modal');
	if (!cfg || !modal) {
		return;
	}

	var setup = modal.querySelector('[data-step="setup"]');
	var doneStep = modal.querySelector('[data-step="done"]');
	var pinEl = document.getElementById('ghost_mode_quick_pin');
	var pin2El = document.getElementById('ghost_mode_quick_pin2');
	var errEl = document.getElementById('ghost_mode_quick_error');
	var createBtn = document.getElementById('ghost_mode_quick_create');
	var dismissBtn = document.getElementById('ghost_mode_quick_dismiss');
	var savedBtn = document.getElementById('ghost_mode_quick_saved');
	var copyBtn = document.getElementById('ghost_mode_quick_copy');
	var urlEl = document.getElementById('ghost_mode_quick_url');

	function showError(msg) {
		if (!errEl) {
			return;
		}
		errEl.hidden = !msg;
		errEl.textContent = msg || '';
	}

	function digitsOnly(el) {
		if (!el) {
			return;
		}
		el.addEventListener('input', function () {
			el.value = el.value.replace(/\D/g, '').slice(0, 4);
		});
	}
	digitsOnly(pinEl);
	digitsOnly(pin2El);

	function closeModal() {
		modal.remove();
	}

	function post(action, data) {
		var body = new FormData();
		body.append('action', action);
		body.append('nonce', cfg.nonce);
		Object.keys(data || {}).forEach(function (k) {
			body.append(k, data[k]);
		});
		return fetch(cfg.ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			body: body,
		}).then(function (r) {
			return r.json();
		});
	}

	if (createBtn) {
		createBtn.addEventListener('click', function () {
			var pin = pinEl ? pinEl.value : '';
			var pin2 = pin2El ? pin2El.value : '';
			showError('');
			if (!/^\d{4}$/.test(pin)) {
				showError(cfg.i18n.pinInvalid);
				return;
			}
			if (pin !== pin2) {
				showError(cfg.i18n.pinMismatch);
				return;
			}
			createBtn.disabled = true;
			post('ghost_mode_quick_create', { pin: pin, pin2: pin2 })
				.then(function (res) {
					createBtn.disabled = false;
					if (!res || !res.success) {
						showError((res && res.data && res.data.message) || cfg.i18n.error);
						return;
					}
					if (urlEl) {
						urlEl.value = res.data.url || '';
					}
					if (setup) {
						setup.hidden = true;
					}
					if (doneStep) {
						doneStep.hidden = false;
					}
				})
				.catch(function () {
					createBtn.disabled = false;
					showError(cfg.i18n.error);
				});
		});
	}

	function dismiss() {
		post('ghost_mode_quick_dismiss', {}).finally(closeModal);
	}

	if (dismissBtn) {
		dismissBtn.addEventListener('click', dismiss);
	}
	if (savedBtn) {
		savedBtn.addEventListener('click', closeModal);
	}

	if (copyBtn && urlEl) {
		copyBtn.addEventListener('click', function () {
			var value = urlEl.value;
			var label = cfg.i18n.copy;
			var mark = function () {
				copyBtn.textContent = cfg.i18n.copied;
				setTimeout(function () {
					copyBtn.textContent = label;
				}, 1500);
			};
			if (navigator.clipboard && navigator.clipboard.writeText) {
				navigator.clipboard.writeText(value).then(mark).catch(function () {
					urlEl.select();
					document.execCommand('copy');
					mark();
				});
			} else {
				urlEl.select();
				document.execCommand('copy');
				mark();
			}
		});
	}
})();
