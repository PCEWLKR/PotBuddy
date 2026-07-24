jest.mock("../config/db", () => ({
  client: {
    db: jest.fn(),
  },
  connectDB: jest.fn(),
}));

const request = require("supertest");
const app = require("../app");

describe("PotBuddy API", () => {
  test("GET /api/health returns API status", async () => {
    const response = await request(app).get("/api/health");

    expect(response.statusCode).toBe(200);
    expect(response.body).toEqual({
      success: true,
      message: "PotBuddy API is running",
    });
  });

  test("unknown endpoint returns 404", async () => {
    const response = await request(app).get("/api/not-a-route");

    expect(response.statusCode).toBe(404);
    expect(response.body.success).toBe(false);
  });
});

describe("Authentication validation", () => {
  test("registration requires username, email, and password", async () => {
    const response = await request(app)
      .post("/api/auth/register")
      .send({});

    expect(response.statusCode).toBe(400);
    expect(response.body.success).toBe(false);
  });

  test("login requires email and password", async () => {
    const response = await request(app)
      .post("/api/auth/login")
      .send({});

    expect(response.statusCode).toBe(400);
    expect(response.body.success).toBe(false);
  });

  test("email verification requires a token", async () => {
    const response = await request(app)
      .get("/api/auth/verify-email");

    expect(response.statusCode).toBe(400);
    expect(response.body.success).toBe(false);
  });

  test("resending verification requires an email", async () => {
    const response = await request(app)
      .post("/api/auth/resend-verification")
      .send({});

    expect(response.statusCode).toBe(400);
    expect(response.body.success).toBe(false);
  });

  test("Google authentication requires a credential", async () => {
    const response = await request(app)
      .post("/api/auth/google")
      .send({});

    expect(response.statusCode).toBe(400);
    expect(response.body.success).toBe(false);
  });
});
