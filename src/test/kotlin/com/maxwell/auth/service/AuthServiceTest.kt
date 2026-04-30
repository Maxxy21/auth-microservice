package com.maxwell.auth.service

import com.maxwell.auth.dto.LoginRequest
import com.maxwell.auth.dto.RegisterRequest
import com.maxwell.auth.entity.RefreshToken
import com.maxwell.auth.entity.User
import com.maxwell.auth.exception.*
import com.maxwell.auth.repository.RefreshTokenRepository
import com.maxwell.auth.repository.UserRepository
import io.mockk.*
import io.mockk.junit5.MockKExtension
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import java.time.LocalDateTime
import java.util.Optional

@ExtendWith(MockKExtension::class)
class AuthServiceTest {

    private val userRepository = mockk<UserRepository>()
    private val refreshTokenRepository = mockk<RefreshTokenRepository>()
    private val passwordEncoder = mockk<org.springframework.security.crypto.password.PasswordEncoder>()
    private val jwtService = mockk<JwtService>()
    private val userService = mockk<UserService>()
    private val loginAttemptService = mockk<LoginAttemptService>()
    private val rateLimitingService = mockk<RateLimitingService>()
    private val ipBlockingService = mockk<IpBlockingService>()
    private val authenticationManager = mockk<AuthenticationManager>()

    private lateinit var authService: AuthService

    @BeforeEach
    fun setup() {
        authService = AuthService(
            userRepository, refreshTokenRepository, passwordEncoder,
            jwtService, userService, loginAttemptService, rateLimitingService,
            ipBlockingService, authenticationManager, 604_800_000L,
        )
    }

    private fun buildUser(
        email: String = "user@example.com",
        enabled: Boolean = true,
        locked: Boolean = false,
    ) = User(id = 1L, email = email, firstName = "Test", lastName = "User", enabled = enabled, accountLocked = locked)

    // --- register ---

    @Test
    fun `register succeeds for a new email`() {
        every { userService.existsByEmail(any()) } returns false
        every { passwordEncoder.encode(any()) } returns "hashed"
        every { userRepository.save(any()) } answers { firstArg() }

        val result = authService.register(RegisterRequest("new@test.com", "password123", "New", "User"))

        assertTrue(result.success)
        verify(exactly = 1) { userRepository.save(any()) }
    }

    @Test
    fun `register throws UserAlreadyExistsException for duplicate email`() {
        every { userService.existsByEmail("dup@test.com") } returns true

        assertThrows<UserAlreadyExistsException> {
            authService.register(RegisterRequest("dup@test.com", "password123", "A", "B"))
        }
    }

    // --- login ---

    @Test
    fun `login throws RateLimitExceededException when rate limit is hit`() {
        every { rateLimitingService.isAllowed(any()) } returns false

        assertThrows<RateLimitExceededException> {
            authService.login(LoginRequest("a@b.com", "pass"), "1.2.3.4", null)
        }
    }

    @Test
    fun `login throws IpBlockedException for a blocked IP`() {
        every { rateLimitingService.isAllowed(any()) } returns true
        every { ipBlockingService.isBlocked("blocked") } returns true

        assertThrows<IpBlockedException> {
            authService.login(LoginRequest("a@b.com", "pass"), "blocked", null)
        }
    }

    @Test
    fun `login throws AccountLockedException for a locked user`() {
        val lockedUser = buildUser(locked = true).also {
            it.lockedUntil = LocalDateTime.now().plusMinutes(20)
        }
        every { rateLimitingService.isAllowed(any()) } returns true
        every { ipBlockingService.isBlocked(any()) } returns false
        every { userRepository.findByEmail(any()) } returns Optional.of(lockedUser)

        assertThrows<AccountLockedException> {
            authService.login(LoginRequest("user@example.com", "pass"), "127.0.0.1", null)
        }
    }

    @Test
    fun `login succeeds with valid credentials`() {
        val user = buildUser()
        val refreshToken = RefreshToken(token = "rt-token", user = user, expiresAt = LocalDateTime.now().plusDays(7))

        every { rateLimitingService.isAllowed(any()) } returns true
        every { ipBlockingService.isBlocked(any()) } returns false
        every { userRepository.findByEmail(any()) } returns Optional.of(user)
        every { authenticationManager.authenticate(any()) } returns
            UsernamePasswordAuthenticationToken(user, null)
        every { jwtService.generateAccessToken(any()) } returns "access-token"
        every { jwtService.getAccessTokenExpiration() } returns 900_000L
        every { refreshTokenRepository.save(any()) } returns refreshToken
        every { loginAttemptService.recordAttempt(any(), any(), any(), any(), any()) } just Runs
        every { loginAttemptService.handleSuccessfulLogin(any(), any()) } just Runs

        val result = authService.login(LoginRequest("user@example.com", "password123"), "127.0.0.1", "agent")

        assertEquals("access-token", result.accessToken)
        assertEquals("user@example.com", result.user.email)
    }
}
