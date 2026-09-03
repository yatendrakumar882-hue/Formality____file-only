import 'dotenv/config';
import express from 'express';
import http from 'http';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);

const SITE_PASSWORD = process.env.SITE_PASSWORD || 'changeme';

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.static(path.join(__dirname, "public")));

const transporters = new Map();

function getTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cacheKey = `${cleanEmail}_${appPassword}`;

  if (!transporters.has(cacheKey)) {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: cleanEmail,
        pass: appPassword
      }
    });
    transporters.set(cacheKey, transporter);
  }
  return transporters.get(cacheKey);
}

// Authentication
app.post("/api/auth", (req, res) => {
  const { password } = req.body;
  if (!password) {
    return res.status(400).json({ success: false, message: "Password is required" });
  }
  if (password === SITE_PASSWORD) {
    return res.json({ success: true, message: "Access granted" });
  }
  return res.status(401).json({ success: false, message: "Incorrect password" });
});

// Verify Credentials
app.post("/api/verify", async (req, res) => {
  const { email, appPassword } = req.body;

  if (!email || !appPassword) {
    return res.status(400).json({ success: false, message: "Credentials required" });
  }

  try {
    const transporter = getTransporter(email, appPassword);
    await transporter.verify();
    return res.json({ success: true, message: "SMTP connection verified" });
  } catch (error) {
    return res.status(401).json({ success: false, message: "Authentication failed" });
  }
});

// Stream Endpoint
app.post("/api/send-stream", async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const { email, appPassword, senderName, subject, messageBody, recipients } = req.body;

  if (!email || !appPassword || !Array.isArray(recipients) || recipients.length === 0) {
    res.write(`data: ${JSON.stringify({ success: false, error: "Missing required fields" })}\n\n`);
    res.end();
    return;
  }

  const senderEmail = email.toLowerCase().trim();
  const transporter = getTransporter(email, appPassword);
  const cleanSenderName = (senderName || "").replace(/"/g, "").trim();

  for (let index = 0; index < recipients.length; index++) {
    const recipient = recipients[index] ? recipients[index].trim() : "";
    if (!recipient) continue;

    const mailOptions = {
      from: cleanSenderName ? `"${cleanSenderName}" <${senderEmail}>` : senderEmail,
      to: recipient,
      subject: subject,
      text: messageBody
    };

    try {
      await transporter.sendMail(mailOptions);
      res.write(`data: ${JSON.stringify({ success: true, recipient })}\n\n`);
    } catch (error) {
      res.write(`data: ${JSON.stringify({ success: false, recipient, error: error.message })}\n\n`);
    }

    // Standard rate delay (1.5 seconds)
    if (index < recipients.length - 1) {
      await new Promise(resolve => setTimeout(resolve, 1500));
    }
  }

  res.write("data: [DONE]\n\n");
  res.end();
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
