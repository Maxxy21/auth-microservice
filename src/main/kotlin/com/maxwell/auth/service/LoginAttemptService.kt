package com.maxwell.auth.service

import com.maxwell.auth.entity.LoginAttempt
import com.maxwell.auth.entity.User
import com.maxwell.auth.repository.LoginAttemptRepository
import com.maxwell.auth.repository.UserRepository
import org.springframework.beans.factory.annotation.Value
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.LocalDateTime

@Service
class LoginAttemptService(
    private val loginAttemptRepository: LoginAttemptRepository,
    private val userRepository: UserRepository,
    @Value("\${app.security.max-login-attempts}") private val maxAttempts: Int,
    @Value("\${app.security.lockout-duration-minutes}") private val lockoutMinutes: Long,
) {
    @Transactional
    fun recordAttempt(
        ipAddress: String,
        email: String,
        success: Boolean,
        userAgent: String? = null,
        failureReason: String? = null,
    ) {
        loginAttemptRepository.save(
            LoginAttempt(
                ipAddress = ipAddress,
                email = email,
                success = success,
                userAgent = userAgent,
                failureReason = failureReason,
            )
        )
    }

    @Transactional
    fun handleFailedAttempt(email: String) {
        userRepository.findByEmail(email).ifPresent { user ->
            user.failedLoginAttempts++
            if (user.failedLoginAttempts >= maxAttempts) {
                user.accountLocked = true
                user.lockedUntil = LocalDateTime.now().plusMinutes(lockoutMinutes)
            }
            userRepository.save(user)
        }
    }

    @Transactional
    fun handleSuccessfulLogin(user: User, ipAddress: String) {
        user.failedLoginAttempts = 0
        user.accountLocked = false
        user.lockedUntil = null
        user.lastLoginAt = LocalDateTime.now()
        user.lastLoginIp = ipAddress
        userRepository.save(user)
    }

    fun isSuspiciousLogin(user: User, currentIp: String): Boolean {
        val recentLogins = loginAttemptRepository.findRecentSuccessfulLogins(user.email).take(10)
        if (recentLogins.isEmpty()) return false
        val knownIps = recentLogins.map { it.ipAddress }.toSet()
        return currentIp !in knownIps
    }

    @Scheduled(cron = "0 0 2 * * *")
    @Transactional
    fun purgeOldAttempts() {
        loginAttemptRepository.deleteByTimestampBefore(LocalDateTime.now().minusDays(30))
    }
}
