// Mobile dropdown toggle (tap to open on small screens)
document.querySelectorAll('.dropdown-toggle').forEach(function (btn) {
  btn.addEventListener('click', function () {
    var parent = btn.closest('.dropdown');
    if (window.innerWidth <= 760) {
      parent.classList.toggle('open');
    }
  });
});

// Footer newsletter: Subscribe button opens a popup with the signup form
(function () {
  var overlay = document.getElementById('newsletter-modal');
  if (!overlay) return;
  var closeBtn = overlay.querySelector('.newsletter-modal-close');
  var firstField = overlay.querySelector('.newsletter-form input');

  function open() {
    overlay.classList.add('show');
    overlay.setAttribute('aria-hidden', 'false');
    if (firstField) firstField.focus();
  }

  function close() {
    overlay.classList.remove('show');
    overlay.setAttribute('aria-hidden', 'true');
  }

  document.querySelectorAll('.newsletter-toggle').forEach(function (btn) {
    btn.addEventListener('click', open);
  });

  closeBtn.addEventListener('click', close);
  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) close();
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') close();
  });
})();

// Cookie consent banner
(function () {
  var COOKIE_KEY = 'rgc_cookie_consent';
  var banner = document.getElementById('cookie-banner');
  if (!banner) return;

  function getConsent() {
    var match = document.cookie.match(new RegExp('(?:^|; )' + COOKIE_KEY + '=([^;]*)'));
    return match ? decodeURIComponent(match[1]) : null;
  }

  function setConsent(value) {
    var maxAge = 60 * 60 * 24 * 365;
    document.cookie = COOKIE_KEY + '=' + encodeURIComponent(value) + '; max-age=' + maxAge + '; path=/';
  }

  if (!getConsent()) {
    banner.classList.add('show');
  }

  var acceptBtn = document.getElementById('cookie-accept');
  var declineBtn = document.getElementById('cookie-decline');

  if (acceptBtn) {
    acceptBtn.addEventListener('click', function () {
      setConsent('accepted');
      banner.classList.remove('show');
    });
  }
  if (declineBtn) {
    declineBtn.addEventListener('click', function () {
      setConsent('declined');
      banner.classList.remove('show');
    });
  }
})();

// Click-to-enlarge product photos
(function () {
  var overlay = document.getElementById('image-lightbox');
  if (!overlay) return;
  var overlayImg = overlay.querySelector('img');
  var closeBtn = overlay.querySelector('.lightbox-close');

  function open(src, alt) {
    overlayImg.src = src;
    overlayImg.alt = alt || '';
    overlay.classList.add('show');
    overlay.setAttribute('aria-hidden', 'false');
  }

  function close() {
    overlay.classList.remove('show');
    overlay.setAttribute('aria-hidden', 'true');
    overlayImg.src = '';
  }

  document.querySelectorAll('.product-image').forEach(function (img) {
    // Images inside a link (e.g. shop grid cards, which link through to the
    // product detail page) should navigate normally, not pop the lightbox.
    if (img.closest('a')) return;
    img.addEventListener('click', function () {
      open(img.getAttribute('src'), img.getAttribute('alt'));
    });
  });

  closeBtn.addEventListener('click', close);
  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) close();
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') close();
  });
})();

// Product detail page: clicking a thumbnail swaps the main photo
(function () {
  var mainImage = document.getElementById('pd-main-image');
  var thumbs = document.querySelectorAll('.pd-thumb-btn');
  if (!mainImage || !thumbs.length) return;

  thumbs.forEach(function (thumb) {
    thumb.addEventListener('click', function () {
      var newSrc = thumb.getAttribute('data-img');
      if (!newSrc) return;
      mainImage.setAttribute('src', newSrc);
      thumbs.forEach(function (t) { t.classList.remove('active'); });
      thumb.classList.add('active');
    });
  });
})();

// Quantity stepper buttons (product cards)
document.querySelectorAll('.qty-stepper').forEach(function (stepper) {
  var input = stepper.querySelector('input[type=number]');
  var minus = stepper.querySelector('.qty-minus');
  var plus = stepper.querySelector('.qty-plus');
  if (!input) return;

  function clamp(value) {
    var min = parseInt(input.min, 10) || 1;
    var max = parseInt(input.max, 10) || 99;
    if (isNaN(value)) value = min;
    return Math.min(max, Math.max(min, value));
  }

  if (minus) {
    minus.addEventListener('click', function () {
      input.value = clamp(parseInt(input.value, 10) - 1);
    });
  }
  if (plus) {
    plus.addEventListener('click', function () {
      input.value = clamp(parseInt(input.value, 10) + 1);
    });
  }
  input.addEventListener('change', function () {
    input.value = clamp(parseInt(input.value, 10));
  });
});

// Book a Pick Up: box-count quick-pick grid
(function () {
  var grid = document.querySelector('.box-count-grid');
  var input = document.querySelector('.box-count-custom-input');
  if (!grid || !input) return;
  var buttons = grid.querySelectorAll('.box-count-btn');

  function markSelected(value) {
    buttons.forEach(function (b) {
      b.classList.toggle('selected', b.getAttribute('data-value') === String(value));
    });
  }

  buttons.forEach(function (btn) {
    btn.addEventListener('click', function () {
      input.value = btn.getAttribute('data-value');
      markSelected(input.value);
    });
  });

  input.addEventListener('input', function () {
    markSelected(input.value);
  });

  if (input.value) markSelected(input.value);
})();

// Admin: manual invoice line-item rows (add / remove)
(function () {
  var body = document.getElementById('invoice-items-body');
  var addBtn = document.getElementById('add-invoice-item');
  var template = document.getElementById('invoice-item-row-template');
  if (!body || !addBtn || !template) return;

  function wireRemove(row) {
    var removeBtn = row.querySelector('.remove-item-row');
    if (!removeBtn) return;
    removeBtn.addEventListener('click', function () {
      // Always keep at least one row so the form has somewhere to type.
      if (body.querySelectorAll('.invoice-item-row').length > 1) {
        row.remove();
      } else {
        row.querySelectorAll('input').forEach(function (input) {
          input.value = input.type === 'number' && input.name === 'item_quantity' ? '1' : '';
        });
      }
    });
  }

  body.querySelectorAll('.invoice-item-row').forEach(wireRemove);

  addBtn.addEventListener('click', function () {
    body.appendChild(template.content.cloneNode(true));
    wireRemove(body.lastElementChild);
  });
})();

// Book a Pickup: "Custom Time" radio reveals a text field for the
// customer's own preferred time; picking a fixed window hides it again and
// the field is only marked required while it's actually visible.
(function () {
  var customRadio = document.getElementById('tw-custom');
  var customField = document.getElementById('custom-time-field');
  var customInput = document.getElementById('custom_time_window');
  var timeRadios = document.querySelectorAll('.time-slot-radio');
  if (!customRadio || !customField || !customInput || !timeRadios.length) return;

  function sync() {
    var showCustom = customRadio.checked;
    customField.hidden = !showCustom;
    if (showCustom) {
      customInput.setAttribute('required', 'required');
    } else {
      customInput.removeAttribute('required');
    }
  }

  timeRadios.forEach(function (radio) {
    radio.addEventListener('change', sync);
  });
  sync();
})();
