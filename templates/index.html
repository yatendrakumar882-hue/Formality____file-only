<!doctype html>
<html lang="en">

<head>

<meta charset="utf-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1"
>

<meta
    name="autocomplete"
    content="off"
>

<title>Secure Mail Console</title>

<link
    rel="stylesheet"
    href="{{ url_for('static', filename='style.css') }}"
>

<link
    rel="stylesheet"
    href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
>

{% if turnstile_site_key %}
<script
src="https://challenges.cloudflare.com/turnstile/v0/api.js"
async
defer
></script>
{% endif %}

</head>


<body
    autocomplete="off"
>


<header class="topbar">

<div class="brand">

<div class="brand-icon">
<i class="fa-solid fa-shield-halved"></i>
</div>

<div class="brand-title">
Secure Mail Console
</div>

</div>


<a
href="{{ url_for('logout') }}"
class="logout-button"
>

<i class="fa-solid fa-right-from-bracket"></i>

Logout

</a>

</header>


<main class="container">


<div class="page-heading">

<h1>
<i class="fa-solid fa-paper-plane"></i>
Bulk Email Sender
</h1>

</div>


<div class="dashboard-grid">


<!-- COMPOSE -->

<section class="card compose-card">


<div class="section-title">

<i class="fa-solid fa-pen-to-square"></i>

<span>
Compose Message
</span>

</div>


<div class="two-column">


<div class="field">

<label>
Sender Name
</label>

<input
id="senderName"
type="text"
autocomplete="off"
placeholder="Your name"
>

</div>


<div class="field">

<label>
Your Gmail
</label>

<input
id="gmail"
type="email"
autocomplete="off"
placeholder="your@gmail.com"
>

</div>


<div class="field">

<label>
App Password
</label>

<div class="password-field">

<input
id="appPassword"
type="password"
autocomplete="new-password"
placeholder="Google App Password"
>

<button
type="button"
onclick="togglePassword()"
>

<i
id="passwordIcon"
class="fa-regular fa-eye"
></i>

</button>

</div>

</div>


<div class="field">

<label>
Email Subject
</label>

<input
id="subject"
type="text"
autocomplete="off"
placeholder="Email subject"
>

</div>

</div>


<div class="field body-field">


<div class="body-header">

<label>
Message Body
</label>


<div class="mode-buttons">

<button
id="plainButton"
class="mode active"
type="button"
onclick="setMode(false)"
>
Plain Text
</button>


<button
id="htmlButton"
class="mode"
type="button"
onclick="setMode(true)"
>
HTML
</button>

</div>

</div>


<!-- IMPORTANT:
     This textarea intentionally contains NOTHING.
     Do not add default text here.
-->

<textarea
id="messageBody"
name="messageBody"
autocomplete="off"
autocorrect="off"
autocapitalize="off"
spellcheck="false"
></textarea>


</div>


<!-- SPINTAX STATUS -->

<div class="spintax-status">

<i class="fa-solid fa-shuffle"></i>

<div>

<strong>
Spintax Enabled
</strong>

<span>
Spintax is always ON.
</span>

</div>

</div>


<div class="security-title">

<i class="fa-solid fa-shield-halved"></i>

Spam Protection

</div>


<div class="security-box">

{% if turnstile_site_key %}

<div
class="cf-turnstile"
data-sitekey="{{ turnstile_site_key }}"
data-theme="light"
data-callback="turnstileCompleted"
data-expired-callback="turnstileExpired"
data-error-callback="turnstileError"
></div>

{% else %}

<div class="turnstile-warning">
Turnstile Site Key is not configured.
</div>

{% endif %}

</div>


</section>


<!-- RIGHT -->

<section class="right-column">


<div class="card recipients-card">


<div class="section-title">

<i class="fa-solid fa-users"></i>

<span>
Recipients
</span>

<span
id="recipientCount"
class="count-badge"
>
0 found
</span>

</div>


<div class="recipient-subtitle">
Paste emails (comma separated, new lines, or Excel copy)
</div>


<textarea
id="recipients"
class="recipients-box"
autocomplete="off"
spellcheck="false"
></textarea>


</div>


<!-- PROGRESS -->

<div class="card progress-card">


<div class="section-title">

<i class="fa-solid fa-chart-pie"></i>

<span>
Progress Monitor
</span>

</div>


<div class="stats-grid">


<div class="stat-box">

<span>TOTAL</span>

<strong id="totalCount">
0
</strong>

</div>


<div class="stat-box">

<span>SENT</span>

<strong
id="sentCount"
class="green"
>
0
</strong>

</div>


<div class="stat-box">

<span>FAILED</span>

<strong
id="failedCount"
class="red"
>
0
</strong>

</div>


<div class="stat-box">

<span>REMAINING</span>

<strong
id="remainingCount"
class="orange"
>
0
</strong>

</div>


</div>


<div class="progress-track">

<div
id="progressBar"
class="progress-fill"
></div>

</div>


<div
id="status"
class="status"
>
Ready to send
</div>


<div class="send-row">


<button
id="sendButton"
class="send-button"
type="button"
onclick="sendBatch()"
>

<i class="fa-solid fa-paper-plane"></i>

Send All

</button>


<button
id="stopButton"
class="stop-button"
type="button"
onclick="stopSending()"
disabled
>

<i class="fa-solid fa-stop"></i>

Stop Sending

</button>


</div>


</div>

</section>

</div>

</main>


<!-- COMPLETION POPUP -->

<div
id="completeModal"
class="complete-modal"
>

<div
class="complete-box"
id="completeBox"
>


<div class="complete-icon">

<i class="fa-solid fa-circle-check"></i>

</div>


<div class="complete-title">
YATENDRA ❤️
</div>


<div
id="completeDetails"
class="complete-details"
>
All emails have been processed.
</div>


<button
type="button"
class="complete-button"
onclick="closeCompletePopup()"
>
OK
</button>


</div>

</div>


<div
id="toast"
class="toast"
></div>


<script>

let isHTML = false;

let sending = false;

let turnstileToken = "";

let currentController = null;


/*
=========================================================
FORCE MESSAGE BODY BLANK
=========================================================
*/

function forceBlankMessageBody() {

    const body =
        document.getElementById(
            "messageBody"
        );

    if (body) {
        body.value = "";
        body.defaultValue = "";
    }
}


/*
Run immediately after DOM is ready.
This also clears any browser-restored value.
*/

document.addEventListener(
    "DOMContentLoaded",
    function() {

        forceBlankMessageBody();

        setTimeout(
            forceBlankMessageBody,
            50
        );

        setTimeout(
            forceBlankMessageBody,
            300
        );

    }
);


/*
Also clear when browser restores page
from back/forward cache.
*/

window.addEventListener(
    "pageshow",
    function() {
        forceBlankMessageBody();
    }
);


/*
=========================================================
TURNSTILE
=========================================================
*/

function turnstileCompleted(token) {
    turnstileToken = token || "";
}

function turnstileExpired() {
    turnstileToken = "";
}

function turnstileError() {
    turnstileToken = "";
}


/*
=========================================================
PASSWORD
=========================================================
*/

function togglePassword() {

    const input =
        document.getElementById(
            "appPassword"
        );

    const icon =
        document.getElementById(
            "passwordIcon"
        );


    if (input.type === "password") {

        input.type = "text";

        icon.className =
            "fa-regular fa-eye-slash";

    } else {

        input.type = "password";

        icon.className =
            "fa-regular fa-eye";

    }
}


/*
=========================================================
MODE
=========================================================
*/

function setMode(htmlMode) {

    isHTML = htmlMode;


    document
        .getElementById("plainButton")
        .classList.toggle(
            "active",
            !htmlMode
        );


    document
        .getElementById("htmlButton")
        .classList.toggle(
            "active",
            htmlMode
        );
}


/*
=========================================================
EMAIL
=========================================================
*/

function isValidEmail(email) {

    return /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/
        .test(email);

}


/*
=========================================================
RECIPIENTS
=========================================================
*/

function getRecipients() {

    const value =
        document
            .getElementById(
                "recipients"
            )
            .value;


    const pieces =
        value.split(
            /[\s,;]+/
        );


    const unique = [];


    for (const piece of pieces) {

        const email =
            piece
                .trim()
                .toLowerCase();


        if (!email) continue;

        if (!isValidEmail(email)) continue;

        if (!unique.includes(email)) {

            unique.push(email);

        }

    }


    return unique.slice(
        0,
        25
    );
}


function updateRecipientCount() {

    const list =
        getRecipients();


    document
        .getElementById(
            "recipientCount"
        )
        .textContent =
        list.length + " found";


    if (!sending) {

        document
            .getElementById(
                "totalCount"
            )
            .textContent =
            list.length;


        document
            .getElementById(
                "remainingCount"
            )
            .textContent =
            list.length;

    }
}


document
    .getElementById(
        "recipients"
    )
    .addEventListener(
        "input",
        updateRecipientCount
    );


/*
=========================================================
STATUS
=========================================================
*/

function setStatus(
    message,
    type = ""
) {

    const status =
        document.getElementById(
            "status"
        );


    status.textContent =
        message;


    status.className =
        "status " + type;
}


/*
=========================================================
PROGRESS
=========================================================
*/

function updateProgress(
    total,
    sent,
    failed,
    remaining
) {

    const completed =
        sent + failed;


    const percent =
        total > 0
            ? Math.round(
                completed /
                total *
                100
            )
            : 0;


    document
        .getElementById(
            "totalCount"
        )
        .textContent =
        total;


    document
        .getElementById(
            "sentCount"
        )
        .textContent =
        sent;


    document
        .getElementById(
            "failedCount"
        )
        .textContent =
        failed;


    document
        .getElementById(
            "remainingCount"
        )
        .textContent =
        remaining;


    document
        .getElementById(
            "progressBar"
        )
        .style.width =
        percent + "%";
}


/*
=========================================================
POPUP
=========================================================
*/

function showCompletePopup(
    sent,
    failed
) {

    document
        .getElementById(
            "completeDetails"
        )
        .textContent =
        `${sent} sent${failed ? ` • ${failed} failed` : ""}`;


    document
        .getElementById(
            "completeModal"
        )
        .classList.add(
            "show"
        );
}


function closeCompletePopup() {

    document
        .getElementById(
            "completeModal"
        )
        .classList.remove(
            "show"
        );
}


/*
=========================================================
CLOSE POPUP BY CLICKING ANYWHERE
=========================================================
*/

document.addEventListener(
    "click",
    function(event) {

        const modal =
            document.getElementById(
                "completeModal"
            );


        if (
            modal &&
            modal.classList.contains(
                "show"
            )
        ) {

            /*
            Clicking anywhere closes it.
            */

            closeCompletePopup();

        }

    }
);


/*
=========================================================
CLOSE POPUP WITH ANY KEY
=========================================================
*/

document.addEventListener(
    "keydown",
    function() {

        const modal =
            document.getElementById(
                "completeModal"
            );


        if (
            modal &&
            modal.classList.contains(
                "show"
            )
        ) {

            closeCompletePopup();

        }

    }
);


/*
=========================================================
SEND
=========================================================
*/

async function sendBatch() {

    if (sending) return;


    const senderName =
        document
            .getElementById(
                "senderName"
            )
            .value
            .trim();


    const gmail =
        document
            .getElementById(
                "gmail"
            )
            .value
            .trim();


    const appPassword =
        document
            .getElementById(
                "appPassword"
            )
            .value
            .trim();


    const subject =
        document
            .getElementById(
                "subject"
            )
            .value
            .trim();


    const body =
        document
            .getElementById(
                "messageBody"
            )
            .value;


    const recipients =
        getRecipients();


    if (!senderName) {

        showToast(
            "Enter Sender Name."
        );

        return;
    }


    if (!isValidEmail(gmail)) {

        showToast(
            "Enter a valid Gmail address."
        );

        return;
    }


    if (!appPassword) {

        showToast(
            "Enter Google App Password."
        );

        return;
    }


    if (!subject) {

        showToast(
            "Enter email subject."
        );

        return;
    }


    if (!body.trim()) {

        showToast(
            "Enter message body."
        );

        return;
    }


    if (!recipients.length) {

        showToast(
            "Add at least one valid recipient."
        );

        return;
    }


    if (!turnstileToken) {

        showToast(
            "Complete Cloudflare verification."
        );

        return;
    }


    sending = true;


    currentController =
        new AbortController();


    const sendButton =
        document.getElementById(
            "sendButton"
        );


    const stopButton =
        document.getElementById(
            "stopButton"
        );


    sendButton.disabled = true;

    stopButton.disabled = false;


    updateProgress(
        recipients.length,
        0,
        0,
        recipients.length
    );


    setStatus(
        "Sending emails...",
        "sending"
    );


    try {

        const response =
            await fetch(
                "/send-batch",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    signal:
                        currentController.signal,

                    body: JSON.stringify({

                        sender_name:
                            senderName,

                        gmail:
                            gmail,

                        app_password:
                            appPassword,

                        subject:
                            subject,

                        body:
                            body,

                        is_html:
                            isHTML,

                        recipients:
                            recipients,

                        turnstile_token:
                            turnstileToken

                    })
                }
            );


        if (!response.ok) {

            let message =
                "Sending request failed.";


            try {

                const data =
                    await response.json();

                message =
                    data.message ||
                    message;

            } catch (e) {}


            throw new Error(
                message
            );
        }


        const reader =
            response.body.getReader();


        const decoder =
            new TextDecoder(
                "utf-8"
            );


        let buffer = "";


        while (true) {

            const {
                value,
                done
            } =
                await reader.read();


            if (done) break;


            buffer +=
                decoder.decode(
                    value,
                    {
                        stream: true
                    }
                );


            const lines =
                buffer.split(
                    "\n"
                );


            buffer =
                lines.pop() || "";


            for (
                const line
                of lines
            ) {

                if (!line.trim()) {
                    continue;
                }


                let event;


                try {

                    event =
                        JSON.parse(
                            line
                        );

                } catch (e) {

                    continue;
                }


                if (
                    event.type ===
                    "start"
                ) {

                    updateProgress(
                        event.total,
                        event.sent,
                        event.failed,
                        event.remaining
                    );

                }


                else if (
                    event.type ===
                    "progress"
                ) {

                    updateProgress(
                        event.total,
                        event.sent,
                        event.failed,
                        event.remaining
                    );


                    setStatus(
                        `Sending emails... ${event.sent}/${event.total}`,
                        "sending"
                    );

                }


                else if (
                    event.type ===
                    "complete"
                ) {

                    updateProgress(
                        event.total,
                        event.sent,
                        event.failed,
                        event.remaining
                    );


                    setStatus(
                        event.message,
                        "success"
                    );


                    showCompletePopup(
                        event.sent,
                        event.failed
                    );

                }


                else if (
                    event.type ===
                    "error"
                ) {

                    updateProgress(
                        event.total ||
                        recipients.length,

                        event.sent || 0,

                        event.failed || 0,

                        event.remaining ?? 0
                    );


                    setStatus(
                        event.message ||
                        "Sending failed.",
                        "error"
                    );


                    showToast(
                        event.message ||
                        "Sending failed."
                    );

                }

            }

        }


    } catch (error) {

        if (
            error.name ===
            "AbortError"
        ) {

            setStatus(
                "Sending stopped.",
                "error"
            );


            showToast(
                "Sending stopped."
            );

        } else {

            setStatus(
                error.message ||
                "Connection error.",
                "error"
            );


            showToast(
                error.message ||
                "Unable to contact server."
            );

        }

    }


    sending = false;

    currentController = null;

    sendButton.disabled = false;

    stopButton.disabled = true;
}


/*
=========================================================
STOP
=========================================================
*/

function stopSending() {

    if (
        !sending ||
        !currentController
    ) {
        return;
    }


    currentController.abort();


    setStatus(
        "Stopping...",
        "error"
    );
}


/*
=========================================================
TOAST
=========================================================
*/

function showToast(message) {

    const toast =
        document.getElementById(
            "toast"
        );


    toast.textContent =
        message;


    toast.classList.add(
        "show"
    );


    setTimeout(
        function() {

            toast.classList.remove(
                "show"
            );

        },
        3500
    );
}


/*
Initial state
*/

updateRecipientCount();

forceBlankMessageBody();

</script>

</body>
</html>
