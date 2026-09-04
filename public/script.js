document.addEventListener('DOMContentLoaded', () => {
  const gateForm = document.getElementById('gate-form');
  const gatePassword = document.getElementById('gate-password');
  const gateError = document.getElementById('gate-error');
  const passwordGate = document.getElementById('password-gate');
  const mainApp = document.getElementById('main-app');
  const toggleGatePassword = document.getElementById('toggle-gate-password');

  const senderNameInput = document.getElementById('sender-name');
  const emailInput = document.getElementById('dashboard-email');
  const passwordInput = document.getElementById('dashboard-password');
  const subjectInput = document.getElementById('subject');
  const messageBodyInput = document.getElementById('message-body');
  const recipientsInput = document.getElementById('recipients-input');
  const detectedCount = document.getElementById('detected-count');
  const togglePassword = document.getElementById('toggle-password');

  const sendBtn = document.getElementById('send-btn');
  const stopBtn = document.getElementById('stop-btn');
  const logoutBtn = document.getElementById('logout-btn');

  const statTotal = document.getElementById('stat-total');
  const statSent = document.getElementById('stat-sent');
  const statFailed = document.getElementById('stat-failed');
  const statRemaining = document.getElementById('stat-remaining');
  const progressBar = document.getElementById('progress-bar');
  const statusText = document.getElementById('status-text');
  const statusIcon = document.getElementById('status-icon');

  // Load Saved Credentials
  if (localStorage.getItem('auth_passed') === 'true') {
    passwordGate.classList.add('hidden');
    mainApp.classList.remove('hidden');
  }

  emailInput.value = localStorage.getItem('saved_email') || '';
  passwordInput.value = localStorage.getItem('saved_pass') || '';
  senderNameInput.value = localStorage.getItem('saved_name') || '';

  // Gate Verification
  gateForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    gateError.classList.add('hidden');

    try {
      const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: gatePassword.value })
      });
      const data = await res.json();
      if (data.success) {
        localStorage.setItem('auth_passed', 'true');
        passwordGate.classList.add('hidden');
        mainApp.classList.remove('hidden');
      } else {
        gateError.classList.remove('hidden');
      }
    } catch {
      gateError.classList.remove('hidden');
    }
  });

  // Toggle Passwords
  toggleGatePassword?.addEventListener('click', () => {
    gatePassword.type = gatePassword.type === 'password' ? 'text' : 'password';
  });

  togglePassword?.addEventListener('click', () => {
    passwordInput.type = passwordInput.type === 'password' ? 'text' : 'password';
  });

  // Double Click Logout
  logoutBtn.addEventListener('dblclick', () => {
    localStorage.removeItem('auth_passed');
    window.location.reload();
  });

  // Recipients Parser
  function getCleanRecipientsList() {
    const raw = recipientsInput.value.trim();
    if (!raw) return [];
    return raw
      .split(/[\n,;]+/)
      .map(e => e.trim())
      .filter(e => e && e.includes('@'));
  }

  recipientsInput.addEventListener('input', () => {
    const list = getCleanRecipientsList();
    detectedCount.textContent = `${list.length} found`;
    statTotal.textContent = list.length;
    statRemaining.textContent = list.length;
  });

  // Send Streaming Event Handler
  sendBtn.addEventListener('click', async () => {
    const recipients = getCleanRecipientsList();
    if (recipients.length === 0) {
      alert('Please enter valid recipient emails.');
      return;
    }

    if (!emailInput.value || !passwordInput.value || !subjectInput.value || !messageBodyInput.value) {
      alert('Please fill all required fields.');
      return;
    }

    // Save Creds
    localStorage.setItem('saved_email', emailInput.value);
    localStorage.setItem('saved_pass', passwordInput.value);
    localStorage.setItem('saved_name', senderNameInput.value);

    let cfToken = '';
    if (window.turnstile) {
      cfToken = window.turnstile.getResponse();
    }

    sendBtn.classList.add('hidden');
    stopBtn.classList.remove('hidden');

    let sent = 0;
    let failed = 0;
    const total = recipients.length;

    statTotal.textContent = total;
    statSent.textContent = '0';
    statFailed.textContent = '0';
    statRemaining.textContent = total;
    progressBar.style.width = '0%';
    statusText.textContent = 'Sending in batches of 2...';
    statusIcon.className = 'fa-solid fa-spinner fa-spin text-primary';

    try {
      const response = await fetch('/api/send-stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: emailInput.value,
          appPassword: passwordInput.value,
          senderName: senderNameInput.value,
          subject: subjectInput.value,
          messageBody: messageBodyInput.value,
          recipients: recipients,
          cfToken: cfToken
        })
      });

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop(); // Incomplete line preserve

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const rawData = line.slice(6).trim();
            if (rawData === '[DONE]') break;

            try {
              const res = JSON.parse(rawData);
              if (res.success) {
                sent++;
                statSent.textContent = sent;
              } else if (res.recipient) {
                failed++;
                statFailed.textContent = failed;
              }

              const remaining = Math.max(0, total - (sent + failed));
              statRemaining.textContent = remaining;
              const percent = Math.round(((sent + failed) / total) * 100);
              progressBar.style.width = `${percent}%`;
            } catch {}
          }
        }
      }

      statusText.textContent = 'Completed!';
      statusIcon.className = 'fa-solid fa-circle-check text-success';

    } catch (err) {
      statusText.textContent = `Error: ${err.message}`;
      statusIcon.className = 'fa-solid fa-circle-xmark text-danger';
    } finally {
      sendBtn.classList.remove('hidden');
      stopBtn.classList.add('hidden');
      if (window.turnstile) window.turnstile.reset();
    }
  });

  // Stop Action
  stopBtn.addEventListener('click', async () => {
    await fetch('/api/stop', { method: 'POST' });
    statusText.textContent = 'Stopped by user';
    statusIcon.className = 'fa-solid fa-circle-stop text-warning';
    sendBtn.classList.remove('hidden');
    stopBtn.classList.add('hidden');
  });
});
