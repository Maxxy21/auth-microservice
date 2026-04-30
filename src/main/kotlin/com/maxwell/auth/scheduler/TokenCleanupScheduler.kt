package com.maxwell.auth.scheduler

import com.maxwell.auth.repository.RefreshTokenRepository
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import org.springframework.transaction.annotation.Transactional

@Component
class TokenCleanupScheduler(
    private val refreshTokenRepository: RefreshTokenRepository,
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @Scheduled(cron = "0 0 3 * * *")
    @Transactional
    fun purgeExpiredRefreshTokens() {
        val deleted = refreshTokenRepository.deleteExpiredTokens()
        log.info("Purged {} expired refresh tokens", deleted)
    }
}
