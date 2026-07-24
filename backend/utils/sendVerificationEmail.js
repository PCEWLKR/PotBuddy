const nodemailer = require("nodemailer");

function createTransporter() {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_APP_PASSWORD) {
    throw new Error("Email credentials are not configured");
  }

  return nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_APP_PASSWORD,
    },
  });
}

async function sendVerificationEmail(email, token) {
  const appUrl = process.env.APP_URL || "http://localhost:5000";
  const verificationUrl =
    `${appUrl}/api/auth/verify-email?token=${encodeURIComponent(token)}`;

  await createTransporter().sendMail({
    from: `"PotBuddy" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Verify your PotBuddy email",
    text: `Verify your PotBuddy account: ${verificationUrl}`,
    html: `
      <h1>Welcome to PotBuddy!</h1>
      <p>Click below to verify your email address:</p>
      <p><a href="${verificationUrl}">Verify email</a></p>
      <p>This link expires in one hour.</p>
    `,
  });
}

module.exports = sendVerificationEmail;