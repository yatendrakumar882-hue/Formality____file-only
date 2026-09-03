document.addEventListener('DOMContentLoaded', () => {

    // ==================== PASSWORD GATE & LOGOUT ====================
    const passwordGate = document.getElementById('password-gate');
    const mainApp = document.getElementById('main-app');
    const gateForm = document.getElementById('gate-form');
    const gatePassword = document.getElementById('gate-password');
    const gateError = document.getElementById('gate-error');
    const gateSubmitBtn = document.getElementById('gate-submit-btn');
    const toggleGatePassword = document.getElementById('toggle-gate-password');
    const logoutBtn = document.getElementById('logout-btn');

    if (sessionStorage.getItem('authenticated') === 'true') {
        passwordGate.classList.add('hidden');
        mainApp.classList.remove('hidden');
    } else {
        passwordGate.classList.remove('hidden');
        mainApp.classList.add('hidden');
    }

    toggleGatePassword.addEventListener('click', () => {
        const type = gatePassword.getAttribute('type') === 'password' ? 'text' : 'password';
        gatePassword.setAttribute('type', type);
        toggleGatePassword.innerHTML = type === 'password' ? '<i class="fa-regular fa-eye"></i>' : '<i class="fa-regular fa-eye-slash"></i>';
    });

    gateForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = gatePassword.value.trim();
        if (!password) return;

        gateSubmitBtn.disabled = true;
        gateSubmitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Verifying...';
        gateError.classList.add('hidden');

        try {
            const response = await fetch('/api/auth', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });

            const result = await response.json();

            if (result.success) {
                sessionStorage.setItem('authenticated', 'true');
                passwordGate.classList.add('gate-unlocked');
                setTimeout(() => {
                    passwordGate.classList.add('hidden');
                    mainApp.classList.remove('hidden');
                }, 400);
            } else {
                gateError.classList.remove('hidden');
                gatePassword.value = '';
                gatePassword.focus();
            }
        } catch (err) {
            gateError.querySelector('span').textContent = 'Connection error. Try again.';
            gateError.classList.remove('hidden');
        } finally {
            gateSubmitBtn.disabled = false;
            gateSubmitBtn.innerHTML = '<i class="fa-solid fa-arrow-right-to-bracket"></i> Enter';
        }
    });

    // Real Double-Click Logout Handler
    if (logoutBtn) {
        logoutBtn.addEventListener('dblclick', () => {
            sessionStorage.removeItem('authenticated');
            window.location.reload();
        });

        let clickTimer;
        logoutBtn.addEventListener('click', () => {
            clearTimeout(clickTimer);
            clickTimer = setTimeout(() => {
                logoutBtn.classList.add('btn-shake');
                setTimeout(() => logoutBtn.classList.remove('btn-shake'), 400);
            }, 250);
        });
    }

    // ==================== MAIN DISPATCH ENGINE ====================
    const dashboardEmail = document.getElementById('dashboard-email');
    const dashboardPassword = document.getElementById('dashboard-password');
    const togglePasswordBtn = document.getElementById('toggle-password');

    const senderName = document.getElementById('sender-name');
    const subject = document.getElementById('subject');
    const messageBody = document.getElementById('message-body');

    const recipientsInput = document.getElementById('recipients-input');
    const detectedCount = document.getElementById('detected-count');
    const emailValidationError = document.getElementById('email-validation-error');

    const statTotal = document.getElementById('stat-total');
    const statSent = document.getElementById('stat-sent');
    const statFailed = document.getElementById('stat-failed');
    const statRemaining = document.getElementById('stat-remaining');
    const progressBar = document.getElementById('progress-bar');
    const statusIcon = document.getElementById('status-icon');
    const statusText = document.getElementById('status-text');

    const sendBtn = document.getElementById('send-btn');
    const stopBtn = document.getElementById('stop-btn');

    let extractedEmails = [];
    let isSending = false;
    let stopRequested = false;

    togglePasswordBtn.addEventListener('click', () => {
        const type = dashboardPassword.getAttribute('type') === 'password' ? 'text' : 'password';
        dashboardPassword.setAttribute('type', type);
        togglePasswordBtn.innerHTML = type === 'password' ? '<i class="fa-regular fa-eye"></i>' : '<i class="fa-regular fa-eye-slash"></i>';
    });

    recipientsInput.addEventListener('input', extractEmails);

    function extractEmails() {
        const text = recipientsInput.value;
        if (!text.trim()) {
            extractedEmails = [];
            detectedCount.textContent = '0 found';
            return;
        }

        const emailRegex = /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/gi;
        const matches = text.match(emailRegex) || [];
        extractedEmails = [...new Set(matches.map(e => e.toLowerCase().trim()))];

        detectedCount.textContent = `${extractedEmails.length} found`;
        if (extractedEmails.length > 0) {
            emailValidationError.classList.add('hidden');
        }
    }

    sendBtn.addEventListener('click', async () => {
        if (isSending) return;

        const emailVal = dashboardEmail.value.trim();
        const appPasswordVal = dashboardPassword.value.trim();
        const senderNameVal = senderName.value.trim();
        const subjectVal = subject.value.trim();
        const messageBodyVal = messageBody.value.trim();

        if (!emailVal || !appPasswordVal || !senderNameVal || !subjectVal || !messageBodyVal) {
            alert('Please fill in all input fields and write the email content.');
            return;
        }

        if (extractedEmails.length === 0) {
            emailValidationError.classList.remove('hidden');
            alert('Please enter recipient emails.');
            return;
        }

        const recipientsToSend = [...extractedEmails];
        const turnstileResponse = document.querySelector('[name="cf-turnstile-response"]')?.value || "";

        sendBtn.disabled = true;
        sendBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Verifying...';

        try {
            const verifyRes = await fetch('/api/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: emailVal, appPassword: appPasswordVal, cfToken: turnstileResponse })
            });

            const verifyResult = await verifyRes.json();
            if (!verifyResult.success) {
                alert(verifyResult.message || 'SMTP Authentication failed. Check your App Password.');
                finishSendingUI();
                return;
            }

            startSendingUI(recipientsToSend.length);

            let sentCount = 0;
            let failedCount = 0;

            const response = await fetch('/api/send-stream', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email: emailVal,
                    appPassword: appPasswordVal,
                    senderName: senderNameVal,
                    subject: subjectVal,
                    messageBody: messageBodyVal,
                    recipients: recipientsToSend,
                    cfToken: turnstileResponse
                })
            });

            if (!response.ok) throw new Error('Streaming connection failed.');

            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';

            while (true) {
                if (stopRequested) break;

                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split('\n\n');
                buffer = lines.pop();

                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        const dataStr = line.replace('data: ', '').trim();
                        if (dataStr === '[DONE]') break;

                        try {
                            const event = JSON.parse(dataStr);
                            if (event.success) {
                                sentCount++;
                                updateProgressUI(sentCount, failedCount, recipientsToSend.length, `Sent: ${event.recipient}`);
                            } else {
                                failedCount++;
                                updateProgressUI(sentCount, failedCount, recipientsToSend.length, `Failed: ${event.recipient}`);
                            }
                        } catch (e) { }
                    }
                }
            }

            isSending = false;
            if (stopRequested) {
                statusIcon.className = 'fa-solid fa-circle-stop text-danger';
                statusText.textContent = 'Process stopped by user.';
            } else {
                statusIcon.className = 'fa-solid fa-circle-check text-success';
                statusText.textContent = 'Completed successfully!';
            }

        } catch (err) {
            console.error('Send error:', err);
            alert('Connection error occurred during send stream.');
        } finally {
            isSending = false;
            finishSendingUI();
        }
    });

    stopBtn.addEventListener('click', async () => {
        stopRequested = true;
        statusIcon.className = 'fa-solid fa-spinner fa-spin text-warning';
        statusText.textContent = 'Stopping send process...';
        stopBtn.disabled = true;

        try {
            await fetch('/api/stop', { method: 'POST' });
        } catch (e) {
            console.error('Stop error', e);
        }
    });

    function startSendingUI(total) {
        isSending = true;
        stopRequested = false;

        statTotal.textContent = total;
        statSent.textContent = '0';
        statFailed.textContent = '0';
        statRemaining.textContent = total;
        progressBar.style.width = '0%';

        statusIcon.className = 'fa-solid fa-circle-notch fa-spin text-primary';
        statusText.textContent = 'Sending emails...';

        sendBtn.disabled = true;
        sendBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Sending...';
        stopBtn.classList.remove('hidden');
        stopBtn.disabled = false;
    }

    function updateProgressUI(sentCount, failedCount, total, customText) {
        statSent.textContent = sentCount;
        statFailed.textContent = failedCount;

        const remaining = Math.max(0, total - (sentCount + failedCount));
        statRemaining.textContent = remaining;

        const percentage = Math.min(100, Math.round(((sentCount + failedCount) / total) * 100));
        progressBar.style.width = `${percentage}%`;

        if (customText && statusText && isSending && !stopRequested) {
            statusText.textContent = customText;
        }
    }

    function finishSendingUI() {
        sendBtn.disabled = false;
        sendBtn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Send All';
        stopBtn.classList.add('hidden');

        if (window.turnstile) {
            try { window.turnstile.reset(); } catch (e) { }
        }
    }
});
