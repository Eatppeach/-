(function () {
    'use strict';

    var body = document.body;
    body.dataset.page = window.location.pathname.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '') || 'dashboard';
    var toggle = document.querySelector('.mobile-nav-toggle');
    var backdrop = document.querySelector('.nav-backdrop');
    var navbar = document.getElementById('primaryNav');

    function setNavigation(open) {
        body.classList.toggle('nav-open', open);
        if (toggle) {
            toggle.setAttribute('aria-expanded', String(open));
            toggle.setAttribute('aria-label', open ? '关闭导航' : '打开导航');
        }
    }

    if (toggle) toggle.addEventListener('click', function () { setNavigation(!body.classList.contains('nav-open')); });
    if (backdrop) backdrop.addEventListener('click', function () { setNavigation(false); });
    if (navbar) navbar.addEventListener('click', function (event) {
        if (event.target.closest('a') && window.innerWidth <= 768) setNavigation(false);
    });

    window.addEventListener('resize', function () {
        if (window.innerWidth > 768) setNavigation(false);
    });

    document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape' && body.classList.contains('nav-open')) setNavigation(false);
    });

    document.querySelectorAll('.modal-overlay').forEach(function (overlay) {
        overlay.setAttribute('aria-hidden', overlay.classList.contains('show') ? 'false' : 'true');
    });

    document.querySelectorAll('button').forEach(function (button) {
        if (!button.getAttribute('type') && !button.closest('form')) button.setAttribute('type', 'button');
    });

    document.querySelectorAll('.table-wrap').forEach(function (wrap) {
        wrap.setAttribute('tabindex', '0');
        wrap.setAttribute('role', 'region');
        wrap.setAttribute('aria-label', '数据表格，可横向滚动');
    });
})();
