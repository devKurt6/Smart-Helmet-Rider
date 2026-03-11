/* ============================================
   HELMET GPS TRACKER — Shared Scripts
   Auth pages: login, register, forgot, reset
   ============================================ */

/* ── Utility Helpers ────────────────────────── */
function showMsg(id, text) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text;
  el.classList.add('show');
}

function hideMsg(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove('show');
}

function hideAllMsgs() {
  document.querySelectorAll('.message').forEach(el => el.classList.remove('show'));
}

function setLoading(btnId, loading) {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  btn.classList.toggle('loading', loading);
  btn.disabled = loading;
}

/* ── Login Page ─────────────────────────────── */
function initLoginPage() {
  const form = document.getElementById('loginForm');
  if (!form) return;

  // Restore saved credentials on page load
  const savedUsername = localStorage.getItem('saved_username');
  const savedPassword = localStorage.getItem('saved_password');
  if (savedUsername && savedPassword) {
    document.getElementById('username').value = savedUsername;
    document.getElementById('password').value = savedPassword;
    document.getElementById('rememberMe').checked = true;
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username   = document.getElementById('username').value;
    const password   = document.getElementById('password').value;
    const rememberMe = document.getElementById('rememberMe').checked;

    // Save or clear credentials based on checkbox
    if (rememberMe) {
      localStorage.setItem('saved_username', username);
      localStorage.setItem('saved_password', password);
    } else {
      localStorage.removeItem('saved_username');
      localStorage.removeItem('saved_password');
    }

    setLoading('loginBtn', true);
    hideAllMsgs();

    try {
      const res  = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, remember_me: rememberMe })
      });
      const data = await res.json();

      if (res.ok && data.success) {
        if (data.token) {
          (rememberMe ? localStorage : sessionStorage).setItem('auth_token', data.token);
        }
        window.location.href = '/dashboard';
      } else {
        showMsg('errorMessage', data.message || 'Invalid username or password');
      }
    } catch {
      showMsg('errorMessage', 'Connection error. Please try again.');
    } finally {
      setLoading('loginBtn', false);
    }
  });

  ['username', 'password'].forEach(id => {
    document.getElementById(id)?.addEventListener('input', () => hideMsg('errorMessage'));
  });
}

/* ── Register Page ──────────────────────────── */
function initRegisterPage() {
  const form    = document.getElementById('registerForm');
  if (!form) return;

  const pwdIn   = document.getElementById('password');
  const confIn  = document.getElementById('confirmPassword');
  const strengthWrap = document.getElementById('passwordStrength');
  const fillEl  = document.getElementById('strengthFill');
  const textEl  = document.getElementById('strengthText');

  pwdIn?.addEventListener('input', function () {
    const pw = this.value;
    if (strengthWrap) strengthWrap.style.display = 'block';

    let score = 0;
    if (pw.length >= 6) score++;
    if (pw.length >= 8) score++;
    if (/[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;

    if (fillEl) {
      fillEl.className = 'strength-fill';
      if (score <= 2) { fillEl.classList.add('strength-weak');   textEl.textContent = 'Weak password'; }
      else if (score <= 3) { fillEl.classList.add('strength-medium'); textEl.textContent = 'Medium password'; }
      else { fillEl.classList.add('strength-strong'); textEl.textContent = 'Strong password'; }
    }
    validateRequirements();
  });

  confIn?.addEventListener('input', validateRequirements);

  function validateRequirements() {
    const pw   = pwdIn.value;
    const conf = confIn.value;
    const lenEl = document.getElementById('req-length');
    const matEl = document.getElementById('req-match');

    lenEl?.classList.toggle('valid', pw.length >= 6);
    matEl?.classList.toggle('valid', !!(pw && conf && pw === conf));
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const email    = document.getElementById('email').value;
    const password = pwdIn.value;
    const confirm  = confIn.value;

    if (password !== confirm)       { showMsg('errorMessage', 'Passwords do not match!'); return; }
    if (password.length < 6)        { showMsg('errorMessage', 'Password must be at least 6 characters!'); return; }
    if (username.length < 3)        { showMsg('errorMessage', 'Username must be at least 3 characters!'); return; }

    setLoading('registerBtn', true);
    hideAllMsgs();

    try {
      const res  = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password })
      });
      const data = await res.json();

      if (res.ok && data.success) {
        showMsg('successMessage', 'Account created! Redirecting to login...');
        form.reset();
        setTimeout(() => { window.location.href = '/'; }, 2000);
      } else {
        showMsg('errorMessage', data.message || 'Registration failed. Try again.');
      }
    } catch {
      showMsg('errorMessage', 'Connection error. Please try again.');
    } finally {
      setLoading('registerBtn', false);
    }
  });

  document.querySelectorAll('#registerForm input').forEach(inp =>
    inp.addEventListener('input', hideAllMsgs)
  );
}

/* ── Forgot Password Page ───────────────────── */
function initForgotPage() {
  const form = document.getElementById('forgotForm');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('email').value;

    setLoading('resetBtn', true);
    hideAllMsgs();

    try {
      const res  = await fetch('/api/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      const data = await res.json();

      if (res.ok && data.success) {
        showMsg('successMessage', data.message || 'Reset link sent! Check your email.');
        form.reset();
      } else {
        showMsg('errorMessage', data.message || 'Failed to send reset link.');
      }
    } catch {
      showMsg('errorMessage', 'Connection error. Please try again.');
    } finally {
      setLoading('resetBtn', false);
    }
  });

  document.getElementById('email')?.addEventListener('input', hideAllMsgs);
}

/* ── Reset Password Page ────────────────────── */
function initResetPage() {
  const form = document.getElementById('resetForm');
  if (!form) return;

  const pwdIn  = document.getElementById('password');
  const confIn = document.getElementById('confirmPassword');
  const fillEl = document.getElementById('strengthFill');
  const textEl = document.getElementById('strengthText');
  const wrap   = document.getElementById('passwordStrength');

  pwdIn?.addEventListener('input', function () {
    const pw = this.value;
    if (wrap) wrap.style.display = 'block';

    let score = 0;
    if (pw.length >= 8) score++;
    if (/[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;

    if (fillEl) {
      fillEl.className = 'strength-fill';
      if (score <= 1) { fillEl.classList.add('strength-weak');   textEl.textContent = 'Weak'; }
      else if (score <= 2) { fillEl.classList.add('strength-medium'); textEl.textContent = 'Medium'; }
      else { fillEl.classList.add('strength-strong'); textEl.textContent = 'Strong'; }
    }
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = pwdIn.value;
    const confirm  = confIn.value;

    if (password !== confirm) { showMsg('errorMessage', 'Passwords do not match!'); return; }
    if (password.length < 8)  { showMsg('errorMessage', 'Password must be at least 8 characters!'); return; }

    // Token is injected by Flask Jinja2 into a hidden input
    const token = document.getElementById('resetToken')?.value;

    setLoading('saveBtn', true);
    hideAllMsgs();

    try {
      const res  = await fetch('/api/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, password })
      });
      const data = await res.json();

      if (res.ok && data.success) {
        showMsg('successMessage', 'Password reset! Redirecting to login...');
        form.reset();
        setTimeout(() => { window.location.href = '/'; }, 2500);
      } else {
        showMsg('errorMessage', data.message || 'Reset failed. Please try again.');
      }
    } catch {
      showMsg('errorMessage', 'Connection error. Please try again.');
    } finally {
      setLoading('saveBtn', false);
    }
  });
}

/* ── Settings Page ──────────────────────────── */
function initSettingsPage() {
  const settingsForm = document.getElementById('settingsForm');
  if (!settingsForm) return;

  function showSettingsMsg(type, text) {
    document.querySelectorAll('.settings-msg').forEach(el => el.classList.remove('show'));
    const el = document.getElementById(type + 'Message');
    if (el) { el.textContent = text; el.classList.add('show'); }
  }

  window.addEventListener('load', async () => {
    try {
      const res  = await fetch('/api/settings');
      const data = await res.json();
      if (data.success && data.settings) {
        data.settings.forEach(s => {
          switch (s.key) {
            case 'email_enabled': document.getElementById('emailEnabled').checked = s.value === 'true'; break;
            case 'smtp_server':   document.getElementById('smtpServer').value = s.value; break;
            case 'smtp_port':     document.getElementById('smtpPort').value = s.value; break;
            case 'smtp_username': document.getElementById('smtpUsername').value = s.value; break;
            case 'smtp_password':
              if (s.value !== '********' && s.value)
                document.getElementById('smtpPassword').placeholder = 'Password set (enter new to change)';
              break;
            case 'sender_email': document.getElementById('senderEmail').value = s.value; break;
            case 'sender_name':  document.getElementById('senderName').value = s.value; break;
          }
        });
      }
    } catch (err) { console.error('Error loading settings:', err); }
  });

  settingsForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const settings = {
      email_enabled: document.getElementById('emailEnabled').checked ? 'true' : 'false',
      smtp_server:   document.getElementById('smtpServer').value,
      smtp_port:     document.getElementById('smtpPort').value,
      smtp_username: document.getElementById('smtpUsername').value,
      smtp_password: document.getElementById('smtpPassword').value,
      sender_email:  document.getElementById('senderEmail').value,
      sender_name:   document.getElementById('senderName').value
    };
    try {
      const res  = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings)
      });
      const data = await res.json();
      if (data.success) {
        showSettingsMsg('success', data.message || 'Settings saved!');
        document.getElementById('smtpPassword').value = '';
        document.getElementById('smtpPassword').placeholder = 'Password set (enter new to change)';
      } else { showSettingsMsg('error', data.message || 'Failed to save settings.'); }
    } catch { showSettingsMsg('error', 'Connection error.'); }
  });

  window.testEmail = async function () {
    showSettingsMsg('info', 'Testing email configuration...');
    try {
      const res  = await fetch('/api/settings/test-email', { method: 'POST' });
      const data = await res.json();
      showSettingsMsg(data.success ? 'success' : 'error', data.message);
    } catch { showSettingsMsg('error', 'Failed to test email.'); }
  };

  window.togglePassword = function () {
    const f = document.getElementById('smtpPassword');
    const t = document.querySelector('.toggle-password');
    if (f.type === 'password') { f.type = 'text';     t.textContent = '🙈'; }
    else                       { f.type = 'password'; t.textContent = '👁️'; }
  };
}

/* ── Global Theme (shared across ALL pages) ─── */
function applyTheme(mode) {
  // Toggle on <html> so the class exists before <body> renders
  if (mode === 'light') {
    document.documentElement.classList.add('light-mode');
    const icon  = document.getElementById('themeIcon');
    const label = document.getElementById('themeLabel');
    if (icon)  icon.textContent  = '🌙';
    if (label) label.textContent = 'Dark';
  } else {
    document.documentElement.classList.remove('light-mode');
    const icon  = document.getElementById('themeIcon');
    const label = document.getElementById('themeLabel');
    if (icon)  icon.textContent  = '☀️';
    if (label) label.textContent = 'Light';
  }
}

function toggleTheme() {
  const next = document.documentElement.classList.contains('light-mode') ? 'dark' : 'light';
  localStorage.setItem('theme', next);
  applyTheme(next);
}

/* ── Admin Check — hide/show Settings nav ────── */
function checkAdminAccess() {
  fetch('/api/user')
    .then(res => res.json())
    .then(data => {
      const settingsNav = document.getElementById('settingsNav');
      if (!settingsNav) return;
      // Show Settings only if user is admin
      if (data.is_admin === true || data.role === 'admin' || data.username === 'admin') {
        settingsNav.style.display = 'flex';
      } else {
        settingsNav.style.display = 'none';
      }
    })
    .catch(() => {
      // If we can't verify, hide Settings to be safe
      const settingsNav = document.getElementById('settingsNav');
      if (settingsNav) settingsNav.style.display = 'none';
    });
}

/* ── Auto-init on DOMContentLoaded ─────────── */
document.addEventListener('DOMContentLoaded', () => {
  // Apply saved theme instantly (no transition yet)
  applyTheme(localStorage.getItem('theme') || 'dark');

  // Enable smooth transitions AFTER first paint so page load looks clean
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      document.documentElement.classList.add('theme-ready');
    });
  });

  initLoginPage();
  initRegisterPage();
  initForgotPage();
  initResetPage();
  initSettingsPage();
});
