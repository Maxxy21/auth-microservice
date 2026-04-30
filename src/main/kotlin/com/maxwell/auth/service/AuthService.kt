package com.maxwell.auth.service

import com.maxwell.auth.dto.*
import com.maxwell.auth.entity.RefreshToken
import com.maxwell.auth.entity.User
import com.maxwell.auth.exception.*
import com.maxwell.auth.repository.RefreshTokenRepository
import com.maxwell.auth.repository.UserRepository
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.password.PasswordEncoder
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.LocalDateTime
import java.util.UUID

@Service
class AuthService(
    private val userRepository: UserRepository,
    private val refreshTokenRepository: RefreshTokenRepository,
    private val passwordEncoder: PasswordEncoder,
    private val jwtService: JwtService,
    private val userService: UserService,
    private val loginAttemptService: LoginAttemptService,
    private val rateLimitingService: RateLimitingService,
    private val ipBlockingService: IpBlockingService,
    private val authenticationManager: AuthenticationManager,
    @Value("\${app.jwt.refresh-token-expiration}") private val refreshTokenExpiration: Long,
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @Transactional
    fun register(request: RegisterRequest): ApiResponse {
        if (userService.existsByEmail(request.email)) {
            throw UserAlreadyExistsException("Email ${request.email} is already registered")
        }
        val user = User(
            email = request.email,
            firstName = request.firstName,
            lastName = request.lastName,
            provider = "local",
            enabled = true,
        ).also { it.updatePassword(passwordEncoder.encode(request.password)) }

        userRepository.save(user)
        return ApiResponse(true, "Registration successful")
    }

    @Transactional
    fun login(request: LoginRequest, ipAddress: String, userAgent: String?): AuthResponse {
        if (!rateLimitingService.isAllowed("login:$ipAddress")) {
            throw RateLimitExceededException("Too many login attempts. Please try again later.")
        }
        if (ipBlockingService.isBlocked(ipAddress)) {
            throw IpBlockedException("Your IP has been temporarily blocked due to suspicious activity.")
        }

        val user = userRepository.findByEmail(request.email).orElse(null)
            ?: run {
                loginAttemptService.recordAttempt(ipAddress, request.email, false, userAgent, "User not found")
                ipBlockingService.checkAndBlockIfNeeded(ipAddress)
                throw BadCredentialsException("Invalid email or password")
            }

        if (!user.isAccountNonLocked) {
            throw AccountLockedException("Account locked until ${user.lockedUntil}. Contact support to unlock.")
        }
        if (!user.isEnabled) {
            throw AccountNotEnabledException("Please verify your email before logging in.")
        }

        try {
            authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken(request.email, request.password)
            )
        } catch (ex: BadCredentialsException) {
            loginAttemptService.recordAttempt(ipAddress, request.email, false, userAgent, "Invalid password")
            loginAttemptService.handleFailedAttempt(request.email)
            ipBlockingService.checkAndBlockIfNeeded(ipAddress)
            throw BadCredentialsException("Invalid email or password")
        }

        loginAttemptService.recordAttempt(ipAddress, request.email, true, userAgent)

        if (loginAttemptService.isSuspiciousLogin(user, ipAddress)) {
            log.warn("Suspicious login detected for user {} from IP {}", user.email, ipAddress)
        }

        loginAttemptService.handleSuccessfulLogin(user, ipAddress)

        return buildAuthResponse(user)
    }

    @Transactional
    fun refresh(request: RefreshTokenRequest): AuthResponse {
        val stored = refreshTokenRepository.findByToken(request.refreshToken)
            .orElseThrow { InvalidTokenException("Invalid refresh token") }

        if (stored.revoked || stored.expiresAt.isBefore(LocalDateTime.now())) {
            throw InvalidTokenException("Refresh token has expired or been revoked")
        }

        stored.revoked = true
        refreshTokenRepository.save(stored)

        return buildAuthResponse(stored.user)
    }

    @Transactional
    fun logout(userId: Long) {
        val user = userService.findById(userId)
        refreshTokenRepository.revokeAllByUser(user)
    }

    private fun buildAuthResponse(user: User): AuthResponse {
        val accessToken = jwtService.generateAccessToken(user)
        val refreshToken = issueRefreshToken(user)
        return AuthResponse(
            accessToken = accessToken,
            refreshToken = refreshToken.token,
            expiresIn = jwtService.getAccessTokenExpiration() / 1000,
            user = UserResponse(
                id = user.id,
                email = user.email,
                firstName = user.firstName,
                lastName = user.lastName,
                roles = user.roles.map { "ROLE_${it.name}" }.toSet(),
            ),
        )
    }

    private fun issueRefreshToken(user: User): RefreshToken =
        refreshTokenRepository.save(
            RefreshToken(
                token = UUID.randomUUID().toString(),
                user = user,
                expiresAt = LocalDateTime.now().plusSeconds(refreshTokenExpiration / 1000),
            )
        )
}
