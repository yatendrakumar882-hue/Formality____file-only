:root {
    --primary-color: #3b82f6;
    --primary-hover: #2563eb;
    --success-color: #10b981;
    --success-hover: #059669;
    --danger-color: #ef4444;
    --danger-hover: #dc2626;
    --bg-color: #f8fafc;
    --card-bg: #ffffff;
    --text-main: #0f172a;
    --text-muted: #64748b;
    --border-color: #e2e8f0;
    --input-focus: rgba(59, 130, 246, 0.2);
    --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
    --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
    --radius-md: 8px;
    --radius-lg: 12px;
    --font-family: 'Outfit', sans-serif;
}

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {
    font-family: var(--font-family);
    background-color: var(--bg-color);
    color: var(--text-main);
    line-height: 1.5;
    background-image: radial-gradient(circle at top right, #e0e7ff, transparent 30%), radial-gradient(circle at bottom left, #dbeafe, transparent 30%);
    min-height: 100vh;
}

.app-container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem 1rem;
}

.app-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
    position: relative;
}

.app-header h1 {
    font-size: 2.2rem;
    font-weight: 700;
    color: var(--primary-color);
    background: linear-gradient(135deg, var(--primary-color), #8b5cf6);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
}

.btn-logout {
    padding: 0.45rem 0.9rem;
    font-size: 0.85rem;
    font-weight: 600;
    border-radius: var(--radius-md);
    border: 1px solid rgba(239, 68, 68, 0.2);
    color: var(--danger-color);
    background-color: #fff;
    cursor: pointer;
    transition: all 0.2s ease;
    box-shadow: var(--shadow-sm);
    user-select: none;
}

.btn-logout:hover {
    background-color: var(--danger-color);
    color: #fff;
    box-shadow: var(--shadow-md);
}

.btn-shake {
    animation: shake 0.3s ease-in-out;
}

@keyframes shake {
    0%, 100% { transform: translateX(0); }
    25% { transform: translateX(-4px); }
    75% { transform: translateX(4px); }
}

.card {
    background-color: var(--card-bg);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-md);
    padding: 2rem;
    border: 1px solid rgba(255, 255, 255, 0.5);
    backdrop-filter: blur(10px);
}

/* Forms */
.form-group {
    margin-bottom: 1.25rem;
}

.form-group label {
    display: block;
    font-size: 0.9rem;
    font-weight: 500;
    margin-bottom: 0.5rem;
    color: var(--text-main);
}

input[type="email"],
input[type="text"],
input[type="password"],
textarea {
    width: 100%;
    padding: 0.75rem 1rem;
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    font-family: var(--font-family);
    font-size: 1rem;
    transition: all 0.2s;
    background-color: #fff;
}

input:focus,
textarea:focus {
    outline: none;
    border-color: var(--primary-color);
    box-shadow: 0 0 0 3px var(--input-focus);
}

.password-wrapper {
    position: relative;
}

.password-wrapper input {
    padding-right: 3rem;
}

.icon-button {
    position: absolute;
    right: 0.5rem;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    padding: 0.5rem;
    border-radius: 50%;
}

.btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 0.75rem 1.5rem;
    border: none;
    border-radius: var(--radius-md);
    font-family: var(--font-family);
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
}

.btn-primary { background: linear-gradient(to right, var(--primary-color), #2563eb); color: white; }
.btn-success { background: linear-gradient(to right, var(--success-color), #059669); color: white; }
.btn-danger { background: linear-gradient(to right, var(--danger-color), #dc2626); color: white; }
.btn-block { width: 100%; }

.hidden { display: none !important; }

.dashboard-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
}

.dashboard-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
    align-items: start;
}

@media (max-width: 860px) {
    .dashboard-grid { grid-template-columns: 1fr; }
    .app-header { flex-direction: column; gap: 1rem; }
}

.composer-card {
    display: flex;
    flex-direction: column;
    height: 100%;
}

.composer-card form {
    display: flex;
    flex-direction: column;
    flex: 1;
}

.form-row {
    display: flex;
    gap: 1rem;
}

.half { flex: 1; }

.flex-grow {
    flex-grow: 1;
    display: flex;
    flex-direction: column;
}

#message-body {
    resize: none;
    flex-grow: 1;
    min-height: 250px;
}

.right-column {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
}

.recipients-card {
    display: flex;
    flex-direction: column;
}

.card-header-flex {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.help-subtext {
    font-size: 0.85rem;
    color: var(--text-muted);
    margin-bottom: 0.5rem;
    margin-top: -0.5rem;
}

.badge {
    background-color: #eff6ff;
    color: var(--primary-color);
    padding: 0.25rem 0.5rem;
    border-radius: 99px;
    font-size: 0.75rem;
    font-weight: 600;
}

#recipients-input {
    resize: none;
    min-height: 150px;
    font-family: monospace;
    font-size: 0.9rem;
    line-height: 1.6;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 1rem;
    margin-bottom: 1.5rem;
}

.stat-box {
    padding: 1rem;
    border-radius: var(--radius-md);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    border: 1px solid var(--border-color);
}

.stat-label {
    font-size: 0.85rem;
    color: var(--text-muted);
    font-weight: 500;
    text-transform: uppercase;
}

.stat-value {
    font-size: 1.75rem;
    font-weight: 700;
    margin-top: 0.25rem;
}

.neutral .stat-value { color: var(--primary-color); }
.success .stat-value { color: var(--success-color); }
.danger .stat-value { color: var(--danger-color); }
.warning .stat-value { color: #f59e0b; }

.progress-bar-container {
    height: 8px;
    background-color: var(--border-color);
    border-radius: 99px;
    overflow: hidden;
    margin-bottom: 1rem;
}

.progress-bar {
    height: 100%;
    background: linear-gradient(to right, var(--primary-color), var(--success-color));
    transition: width 0.3s ease;
}

.status-indicator {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    margin-bottom: 1.5rem;
    font-size: 0.95rem;
    font-weight: 500;
}

.control-buttons { display: flex; gap: 1rem; }
.flex-1 { flex: 1; }

.error-message {
    background-color: #fef2f2;
    color: var(--danger-color);
    padding: 0.75rem;
    border-radius: var(--radius-md);
    font-size: 0.9rem;
    margin-top: 0.5rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    border-left: 3px solid var(--danger-color);
}

.password-gate {
    position: fixed;
    inset: 0;
    z-index: 9999;
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 40%, #312e81 100%);
}

.gate-card {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(24px);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 20px;
    padding: 3rem 2.5rem;
    width: 100%;
    max-width: 400px;
    text-align: center;
}

.gate-card h2 { color: #f1f5f9; font-size: 1.6rem; margin-bottom: 0.25rem; }
.gate-card p { color: #94a3b8; font-size: 0.95rem; margin-bottom: 1.75rem; }
.gate-icon { width: 70px; height: 70px; border-radius: 50%; background: linear-gradient(135deg, #6366f1, #3b82f6); display: flex; align-items: center; justify-content: center; margin: 0 auto 1.25rem auto; font-size: 1.75rem; color: white; }
.gate-card input[type="password"] { background: rgba(255, 255, 255, 0.07); border: 1px solid rgba(255, 255, 255, 0.15); color: #f1f5f9; }
.gate-error { background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.25); color: #fca5a5; padding: 0.65rem 0.85rem; border-radius: 8px; font-size: 0.9rem; margin-bottom: 1rem; }
