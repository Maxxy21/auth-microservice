# Authentication Microservice

A production-ready authentication microservice built with Kotlin and Spring Boot. Features JWT authentication, OAuth2 social login, role-based access control, and a fraud detection pipeline including rate limiting, IP blocking, and account lockout.

## Tech Stack

- **Language:** Kotlin
- **Framework:** Spring Boot 3.2
- **Security:** Spring Security, JWT (jjwt 0.12), OAuth2 (Google, GitHub)
- **Database:** PostgreSQL + Spring Data JPA
- **Testing:** JUnit 5, MockK
- **Build:** Maven

## Features

- JWT access tokens (15 min) with refresh token rotation (7 days)
- OAuth2 social login — Google and GitHub
- Role-based access control: `USER`, `ADMIN`, `MODERATOR`
- **Fraud detection pipeline:**
  - Rate limiting — max 10 login requests per minute per IP
  - Account lockout — locked for 30 min after 5 failed attempts
  - IP blocking — auto-block IPs exceeding 20 failed attempts per hour
  - Suspicious login detection — flags logins from unrecognised IPs
- Scheduled cleanup of expired tokens and old login records
- Admin endpoints for manual IP management

## Prerequisites

- Java 17+
- Maven 3.8+
- PostgreSQL 14+

## Getting Started

**1. Clone the repository**

```bash
git clone https://github.com/maxxy21/auth-microservice.git
cd auth-microservice
```

**2. Set up the database**

```sql
CREATE DATABASE authdb;
```

**3. Configure environment variables**

```bash
cp .env.example .env
```

Edit `.env` with your values (see [Environment Variables](#environment-variables) below).

**4. Run the application**

```bash
mvn spring-boot:run
```

The API will be available at `http://localhost:8080`.

**5. Explore the API**

Open [http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html) in your browser.
Click **Authorize**, paste the `accessToken` from `/api/auth/login`, and test every endpoint interactively.

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `DB_USERNAME` | PostgreSQL username | `postgres` |
| `DB_PASSWORD` | PostgreSQL password | — |
| `JWT_SECRET` | 256-bit hex secret for signing JWTs | — |
| `GOOGLE_CLIENT_ID` | Google OAuth2 client ID | — |
| `GOOGLE_CLIENT_SECRET` | Google OAuth2 client secret | — |
| `GITHUB_CLIENT_ID` | GitHub OAuth2 client ID | — |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth2 client secret | — |

Copy `.env.example` to `.env` and fill in the values. OAuth2 variables are optional — the app starts without them if you only need local auth.

## API Endpoints

### Auth — `/api/auth`

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/register` | Public | Register a new user |
| `POST` | `/login` | Public | Login, returns access + refresh tokens |
| `POST` | `/refresh` | Public | Exchange a refresh token for new tokens |
| `POST` | `/logout` | Bearer | Revoke all refresh tokens for the current user |

### Users — `/api/users`

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/me` | Bearer | Get current user profile |
| `GET` | `/` | ADMIN | List all users |
| `POST` | `/{id}/promote` | ADMIN | Promote a user to ADMIN |

### Admin — `/api/admin`

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/block-ip/{ip}` | ADMIN | Manually block an IP address |
| `DELETE` | `/block-ip/{ip}` | ADMIN | Unblock an IP address |

### Example: Register + Login

```bash
# Register
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret123","firstName":"Jane","lastName":"Doe"}'

# Login
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret123"}'

# Access protected endpoint
curl http://localhost:8080/api/users/me \
  -H "Authorization: Bearer <access_token>"
```

## Running Tests

```bash
mvn test
```

Unit tests use MockK, no database or running server required.

## OAuth2 Setup (optional)

To enable social login, create OAuth2 apps in the respective developer consoles and set the callback URL to:

```
http://localhost:8080/login/oauth2/code/google
http://localhost:8080/login/oauth2/code/github
```

Then add the client credentials to your `.env`.

## Project Structure

```
src/main/kotlin/com/maxwell/auth/
├── config/          # Security and application configuration
├── controller/      # REST controllers (auth, users, admin)
├── dto/             # Request/response data classes
├── entity/          # JPA entities (User, RefreshToken, LoginAttempt, BlockedIp)
├── exception/       # Custom exceptions and global error handler
├── repository/      # Spring Data JPA repositories
├── scheduler/       # Scheduled tasks (token cleanup)
├── security/        # JWT filter and OAuth2 success handler
└── service/         # Business logic
```
