const request = require("supertest");
const sqlite3 = require("sqlite3").verbose();
const { app } = require("./server.js");

describe("Secure JWKS Server", () => {
  let db;

  beforeAll(() => {
    db = new sqlite3.Database("secure_jwks.db");
  });

  afterAll((done) => {
    db.close(() => {
      done();
    });
  });

  test("GET /.well-known/jwks.json should return JWKS", async () => {
    const response = await request(app).get("/.well-known/jwks.json");
    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty("keys");
  });

  test("POST /register should create a new user and return a password", async () => {
    const response = await request(app).post("/register").send({
      username: "testuser",
      email: "testuser@example.com",
    });

    expect(response.status).toBe(201);
    expect(response.body).toHaveProperty("password");
  });

  test("POST /register should fail for duplicate username or email", async () => {
    const response = await request(app).post("/register").send({
      username: "testuser",
      email: "testuser@example.com",
    });

    expect(response.status).toBe(400);
    expect(response.body).toHaveProperty("error", "Username or email already exists.");
  });

  test("POST /auth should authenticate a valid user", async () => {
    // Assuming the password from the registration response
    const registration = await request(app).post("/register").send({
      username: "authuser",
      email: "authuser@example.com",
    });

    const { password } = registration.body;

    const response = await request(app).post("/auth").send({
      username: "authuser",
      password,
    });

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty("message", "Authentication successful.");
  });

  test("POST /auth should fail for invalid credentials", async () => {
    const response = await request(app).post("/auth").send({
      username: "nonexistentuser",
      password: "wrongpassword",
    });

    expect(response.status).toBe(401);
    expect(response.body).toHaveProperty("error", "Invalid credentials.");
  });

  test("Rate limiting should enforce 10 requests per second on /auth", async () => {
    const username = `ratelimituser`;
    const email = `ratelimituser@example.com`;

    // Register the user
    const registration = await request(app).post("/register").send({
      username,
      email,
    });

    const { password } = registration.body;

    const promises = [];
    for (let i = 0; i < 15; i++) {
      promises.push(
        request(app).post("/auth").send({
          username,
          password,
        })
      );
    }

    const responses = await Promise.all(promises);
    const successResponses = responses.filter((res) => res.status === 200);
    const rateLimitedResponses = responses.filter((res) => res.status === 429);

    expect(successResponses.length).toBeLessThanOrEqual(10);
    expect(rateLimitedResponses.length).toBeGreaterThan(0);
    expect(rateLimitedResponses[0].body).toHaveProperty("error", "Too many requests. Please try again later.");
  });
});
