import 'dotenv/config';
import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { HttpsProxyAgent } from 'https-proxy-agent';
import PDFDocument from 'pdfkit';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const SITE_PASSWORD = process.env.SITE_PASSWORD || 'Y##';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '1x0000000000000000000000000000000AA';

const globalSession = { stopRequested: false };
const poolMap = new Map();

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

/* ==========================================================================
   1. TURNSTILE BOT PROTECTION
   ========================================================================== */
async function verifyTurnstileToken(token, remoteIp) {
  if (!token || TURNSTILE_SECRET_KEY.startsWith('1x0000000000000000000000000000000AA')) {
    return true;
  }

  try {
    const formData = new URLSearchParams();
    formData.append('secret', TURNSTILE_SECRET_KEY);
    formData.append('response', token);
    if (remoteIp) formData.append('remoteip', remoteIp);

    const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: formData,
      headers: { 'content-type': 'application/x-www-form-urlencoded' }
    });
    const outcome = await result.json();
    return outcome.success === true;
  } catch (error) {
    return false;
  }
}

/* ==========================================================================
   2. AUTHENTIC GMAIL TRANSPORTER POOL
   ========================================================================== */
function getNativeTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPass = appPassword.replace(/\s+/g, '').trim();
  const key = `perfect_inbox_${cleanEmail}_${cleanPass}`;

  if (!poolMap.has(key)) {
    const proxyUrl = process.env.PROXY_URL;
    const agent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : null;

    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: {
        user: cleanEmail,
        pass: cleanPass
      },
      ...(agent && { agent }),
      pool: true,
      maxConnections: 5,
      maxMessages: 10000,
      socketTimeout: 30000,
      connectionTimeout: 30000
    });
    poolMap.set(key, transporter);
  }
  return poolMap.get(key);
}

/* ==========================================================================
   3. ULTRA-LIGHT COMPRESSED PDF GENERATOR (1.5 - 2 KB Size)
   ========================================================================== */
function createSuperLightPdfBuffer(title, senderName, senderEmail, bodyText) {
  return new Promise((resolve, reject) => {
    // A5 size and compressed metadata reduces overall size by 50-60%
    const doc = new PDFDocument({ size: 'A5', margin: 30, compress: true });
    const buffers = [];

    doc.on('data', buffers.push.bind(buffers));
    doc.on('end', () => resolve(Buffer.concat(buffers)));
    doc.on('error', reject);

    const dateStr = new Date().toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });

    // Clean Minimal Layout
    doc.fillColor('#111827')
       .fontSize(16)
       .font('Helvetica-Bold')
       .text(title, { align: 'left' });

    doc.moveDown(0.5);

    doc.strokeColor('#e5e7eb')
       .lineWidth(0.8)
       .moveTo(30, doc.y)
       .lineTo(390, doc.y)
       .stroke();

    doc.moveDown(0.8);

    doc.fontSize(9)
       .font('Helvetica')
       .fillColor('#6b7280')
       .text(`From: ${senderName} <${senderEmail}> | Date: ${dateStr}`);

    doc.moveDown(0.8);

    doc.fontSize(10)
       .font('Helvetica')
       .fillColor('#111827')
       .text(bodyText, { lineGap: 3 });

    doc.end();
  });
}

/* ==========================================================================
   4. RECIPIENT DATA & SPINTAX ENGINE
   ========================================================================== */
function parseRecipientData(input) {
  let email = '';
  let rawName = '';

  if (typeof input === 'object' && input !== null) {
    email = (input.email || input.recipient || '').trim();
    rawName = (input.name || input.fullName || input.first_name || '').trim();
  } else if (typeof input === 'string') {
    const str = input.trim();
    const angleMatch = str.match(/^(?:"?([^"]*)"?\s)?<([^>]+)>$/);
    if (angleMatch) {
      rawName = angleMatch[1] ? angleMatch[1].trim() : '';
      email = angleMatch[2].trim();
    } else if (str.includes(',')) {
      const parts = str.split(',');
      if (parts[0].includes('@')) {
        email = parts[0].trim();
        rawName = parts[1].trim();
      } else {
        rawName = parts[0].trim();
        email = parts[1].trim();
      }
    } else {
      email = str;
    }
  }

  if (!rawName && email.includes('@')) {
    const prefix = email.split('@')[0];
    rawName = prefix.replace(/[0-9_.-]/g, ' ').trim();
  }

  const formattedName = rawName
    ? rawName.split(/\s+/).map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' ')
    : '';

  const firstName = formattedName ? formattedName.split(' ')[0] : '';
  const domain = email.includes('@') ? email.split('@')[1] : '';

  return {
    email: email.toLowerCase(),
    name: formattedName,
    firstName: firstName,
    domain: domain
  };
}

function parseSpintax(text) {
  if (!text) return '';
  let spun = String(text);
  const regex = /\{([^{}]+)\}/s;
  let iterations = 0;

  while (regex.test(spun) && iterations < 25) {
    spun = spun.replace(regex, (_, choices) => {
      if (!choices.includes('|')) return choices;
      const options = choices.split('|');
      const pick = options[Math.floor(Math.random() * options.length)];
      return pick ? pick.trim() : '';
    });
    iterations++;
  }
  return spun.replace(/[\{\}]/g, '');
}

function personalizeContent(template, recipient) {
  if (!template) return '';
  let content = parseSpintax(template);

  const displayName = recipient.name || recipient.firstName || 'there';
  const displayFirstName = recipient.firstName || displayName;

  content = content.replace(/{Name}/gi, displayName);
  content = content.replace(/{FirstName}/gi, displayFirstName);
  content = content.replace(/{First_Name}/gi, displayFirstName);
  content = content.replace(/{Email}/gi, recipient.email);
  content = content.replace(/{Domain}/gi, recipient.domain);

  return content.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
}

/* ==========================================================================
   5. API ROUTES
   ========================================================================== */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/auth', (req, res) => {
  const { password } = req.body;
  if (password === SITE_PASSWORD) return res.json({ success: true, message: 'Authorized' });
  return res.status(401).json({ success: false, message: 'Unauthorized Password' });
});

app.post('/api/verify', async (req, res) => {
  const { email, appPassword, cfToken } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!email || !appPassword) {
    return res.status(400).json({ success: false, message: 'Credentials required' });
  }

  const cleanPass = appPassword.replace(/\s+/g, '').trim();
  if (cleanPass.length !== 16) {
    return res.status(400).json({ success: false, message: 'App Password must be 16 characters' });
  }

  if (cfToken) {
    const isHuman = await verifyTurnstileToken(cfToken, clientIp);
    if (!isHuman) {
      return res.status(403).json({ success: false, message: 'Security Verification Failed' });
    }
  }

  getNativeTransporter(email, appPassword);
  return res.json({ success: true, message: 'SMTP ready' });
});

/* ==========================================================================
   6. HIGH-INBOX & SMART-REPLY STREAMING ROUTE
   ========================================================================== */
app.post('/api/send-stream', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const { email, appPassword, senderName, subject, messageBody, recipients, cfToken } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!email || !appPassword || !Array.isArray(recipients) || recipients.length === 0) {
    res.write(`data: ${JSON.stringify({ success: false, error: 'Invalid Request Data' })}\n\n`);
    res.end();
    return;
  }

  if (cfToken) {
    const isHuman = await verifyTurnstileToken(cfToken, clientIp);
    if (!isHuman) {
      res.write(`data: ${JSON.stringify({ success: false, error: 'Turnstile Verification Failed' })}\n\n`);
      res.end();
      return;
    }
  }

  const cleanEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || 'Dheeru').replace(/["\r\n]/g, '').trim();
  globalSession.stopRequested = false;

  const keepAlivePing = setInterval(() => {
    res.write(': keep-alive\n\n');
  }, 2500);

  const transporter = getNativeTransporter(email, appPassword);

  const defaultSubject = 'Referrals';
  const defaultBody = `Hi! Your webpage looks great, but it's not showing on the front page of Google. May I send the quote?`;

  const finalSubjectTemplate = (subject && subject.trim()) ? subject : defaultSubject;
  const finalBodyTemplate = (messageBody && messageBody.trim()) ? messageBody : defaultBody;

  for (let i = 0; i < recipients.length; i++) {
    if (globalSession.stopRequested) {
      res.write(`data: ${JSON.stringify({ success: false, error: 'Stopped by User' })}\n\n`);
      break;
    }

    const recipient = parseRecipientData(recipients[i]);
    if (!recipient.email) continue;

    try {
      const personalizedSubject = personalizeContent(finalSubjectTemplate, recipient);
      const rawPersonalizedBody = personalizeContent(finalBodyTemplate, recipient);

      // Clean single spacing triggers Gmail's Smart Reply Chips
      const emailBodyFormatted = `\r\n${rawPersonalizedBody}\r\n\r\n`;

      // 50% smaller PDF buffer (1.5KB - 2KB)
      const pdfBuffer = await createSuperLightPdfBuffer(
        personalizedSubject,
        cleanSenderName,
        cleanEmail,
        rawPersonalizedBody
      );

      const mailOptions = {
        from: `"${cleanSenderName}" <${cleanEmail}>`,
        to: recipient.name ? `"${recipient.name}" <${recipient.email}>` : recipient.email,
        replyTo: cleanEmail,
        subject: personalizedSubject,
        text: emailBodyFormatted,
        attachments: [
          {
            filename: '(web-page) Error.pdf',
            content: pdfBuffer,
            contentType: 'application/pdf'
          }
        ],
        headers: {
          'X-Mailer': 'Gmail Native Compose',
          'Content-Transfer-Encoding': '7bit'
        }
      };

      await transporter.sendMail(mailOptions);
      
      const successData = { success: true, recipient: recipient.email, name: recipient.name };
      res.write(`data: ${JSON.stringify(successData)}\n\n`);

    } catch (err) {
      const failData = { success: false, recipient: recipient.email, error: err.message };
      res.write(`data: ${JSON.stringify(failData)}\n\n`);
    }

    // 160ms delay = 25 emails in 3 seconds
    if (i < recipients.length - 1 && !globalSession.stopRequested) {
      await new Promise(resolve => setTimeout(resolve, 160));
    }
  }

  clearInterval(keepAlivePing);
  res.write('data: [DONE]\n\n');
  res.end();
});

app.post('/api/stop', (req, res) => {
  globalSession.stopRequested = true;
  res.json({ success: true, message: 'Stopped by User' });
});

app.listen(PORT, () => {
  console.log(`🚀 Perfect Mailer Server running on port ${PORT}`);
});

export default app;
