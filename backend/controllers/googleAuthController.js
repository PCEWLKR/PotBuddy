const { OAuth2Client } = require("google-auth-library");
const { client } = require("../config/db");
const generateToken = require("../utils/generateToken");

const usersCollection = () => client.db().collection("users");

function safeUser(user) {
  return {
    id: user._id.toString(),
    username: user.username,
    email: user.email,
    emailVerified: user.emailVerified,
    featuredPlantId: user.featuredPlantId || null,
    createdAt: user.createdAt,
  };
}

async function googleLogin(req, res) {
  try {
    const credential = req.body.credential;

    if (!credential) {
      return res.status(400).json({
        success: false,
        message: "Google credential is required",
      });
    }

    if (!process.env.GOOGLE_CLIENT_ID) {
      throw new Error("GOOGLE_CLIENT_ID is not configured");
    }

    const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();

    if (
      !payload ||
      !payload.sub ||
      !payload.email ||
      !payload.email_verified
    ) {
      return res.status(401).json({
        success: false,
        message: "Google account could not be verified",
      });
    }

    const email = payload.email.toLowerCase();
    const users = usersCollection();
    const now = new Date();

    let user = await users.findOne({
      $or: [{ googleId: payload.sub }, { email }],
    });

    if (user) {
      await users.updateOne(
        { _id: user._id },
        {
          $set: {
            googleId: payload.sub,
            emailVerified: true,
            emailVerificationTokenHash: null,
            emailVerificationExpiresAt: null,
            updatedAt: now,
          },
        }
      );

      user.googleId = payload.sub;
      user.emailVerified = true;
      user.emailVerificationTokenHash = null;
      user.emailVerificationExpiresAt = null;
      user.updatedAt = now;
    } else {
      const userDocument = {
        username: `google_${payload.sub}`.slice(0, 30),
        email,
        passwordHash: null,
        googleId: payload.sub,
        authProvider: "google",
        emailVerified: true,
        emailVerificationTokenHash: null,
        emailVerificationExpiresAt: null,
        featuredPlantId: null,
        createdAt: now,
        updatedAt: now,
      };

      const result = await users.insertOne(userDocument);

      user = {
        ...userDocument,
        _id: result.insertedId,
      };
    }

    return res.status(200).json({
      success: true,
      data: {
        token: generateToken(user._id),
        user: safeUser(user),
      },
    });
  } catch (error) {
    console.error("Google authentication error:", error);

    return res.status(401).json({
      success: false,
      message: "Google authentication failed",
    });
  }
}

module.exports = {
  googleLogin,
};