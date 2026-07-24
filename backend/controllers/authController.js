const crypto = require("crypto");
const sendVerificationEmail = require("../utils/sendVerificationEmail");
const bcrypt = require("bcrypt");
const { client } = require("../config/db");
const generateToken = require("../utils/generateToken");

const usersCollection = () => client.db().collection("users");

function createEmailVerificationToken() {
  const token = crypto.randomBytes(32).toString("hex");
  const tokenHash = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");

  return {
    token,
    tokenHash,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  };
}

function safeUser(user) {
  return {
    id: user._id.toString(),
    username: user.username,
    email: user.email,
    emailVerified: user.emailVerified,
    featuredPlantId: user.featuredPlantId ?? null,
    createdAt: user.createdAt,
  };
}

async function register(req, res) {
  try {
    const username = req.body.username?.trim();
    const email = req.body.email?.trim().toLowerCase();
    const password = req.body.password;

    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Username, email, and password are required",
      });
    }

    if (username.length < 3 || username.length > 30) {
      return res.status(422).json({
        success: false,
        message: "Username must be between 3 and 30 characters",
      });
    }

    if (!/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(422).json({
        success: false,
        message: "Enter a valid email address",
      });
    }

    if (password.length < 8) {
      return res.status(422).json({
        success: false,
        message: "Password must contain at least 8 characters",
      });
    }

    const users = usersCollection();

    const existingUser = await users.findOne({
      $or: [{ email }, { username }],
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "Email or username is already registered",
      });
    }

    const now = new Date();
    const passwordHash = await bcrypt.hash(password, 12);
    const verification = createEmailVerificationToken();

    const userDocument = {
      username,
      email,
      passwordHash,
      googleId: null,
      authProvider: "local",
      emailVerified: false,
      emailVerificationTokenHash: verification.tokenHash,
      emailVerificationExpiresAt: verification.expiresAt,
      featuredPlantId: null,
      createdAt: now,
      updatedAt: now,
    };

    const result = await users.insertOne(userDocument);

    const createdUser = {
      ...userDocument,
      _id: result.insertedId,
    };
    let verificationEmailSent = true;

    try {
      await sendVerificationEmail(email, verification.token);
    } catch (emailError) {
      verificationEmailSent = false;
      console.error("Verification email failed:", emailError);
    }


    let registrationMessage;

    if (verificationEmailSent) {
      registrationMessage =
        "Registration successful. Check your email to verify your account.";
    } else {
      registrationMessage =
        "Registration successful, but the verification email could not be sent.";
    }

      return res.status(201).json({
      success: true,
      message: registrationMessage,
      data: {
        user: safeUser(createdUser),
        verificationEmailSent,
      },
    });
  } catch (error) {
    console.error("Registration error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to register user",
    });
  }
}

async function login(req, res) {
  try {
    const email = req.body.email?.trim().toLowerCase();
    const password = req.body.password;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }

    const user = await usersCollection().findOne({ email });

    if (!user || !user.passwordHash) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!passwordMatches) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    if (!user.emailVerified) {
  return res.status(403).json({
    success: false,
    message: "Verify your email before logging in",
  });
}

    const token = generateToken(user._id);

    return res.status(200).json({
      success: true,
      data: {
        token,
        user: safeUser(user),
      },
    });
  } catch (error) {
    console.error("Login error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to log in",
    });
  }
}
async function verifyEmail(req, res) {
  try {
    const token = req.query.token;

    if (!token) {
      return res.status(400).json({
        success: false,
        message: "Verification token is required",
      });
    }

    const tokenHash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const result = await usersCollection().updateOne(
      {
        emailVerificationTokenHash: tokenHash,
        emailVerificationExpiresAt: { $gt: new Date() },
      },
      {
        $set: {
          emailVerified: true,
          emailVerificationTokenHash: null,
          emailVerificationExpiresAt: null,
          updatedAt: new Date(),
        },
      }
    );

    if (result.matchedCount === 0) {
      return res.status(400).json({
        success: false,
        message: "Verification link is invalid or expired",
      });
    }

    return res.status(200).json({
      success: true,
      message: "Email verified successfully. You can now log in.",
    });
  } catch (error) {
    console.error("Email verification error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to verify email",
    });
  }
}

async function resendVerification(req, res) {
  try {
    const email = req.body.email?.trim().toLowerCase();

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    const user = await usersCollection().findOne({ email });

    // Generic response avoids revealing whether an account exists.
    if (!user || user.emailVerified) {
      return res.status(200).json({
        success: true,
        message: "If an unverified account exists, a new email has been sent.",
      });
    }

    const verification = createEmailVerificationToken();

    await usersCollection().updateOne(
      { _id: user._id },
      {
        $set: {
          emailVerificationTokenHash: verification.tokenHash,
          emailVerificationExpiresAt: verification.expiresAt,
          updatedAt: new Date(),
        },
      }
    );

    await sendVerificationEmail(email, verification.token);

    return res.status(200).json({
      success: true,
      message: "If an unverified account exists, a new email has been sent.",
    });
  } catch (error) {
    console.error("Resend verification error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to resend verification email",
    });
  }
}
module.exports = {
  register,
  login,
  verifyEmail,
  resendVerification,
};

