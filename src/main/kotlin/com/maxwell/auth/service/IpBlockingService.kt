package com.maxwell.auth.service

import com.maxwell.auth.entity.BlockedIp
import com.maxwell.auth.repository.BlockedIpRepository
import com.maxwell.auth.repository.LoginAttemptRepository
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.LocalDateTime

@Service
class IpBlockingService(
    private val blockedIpRepository: BlockedIpRepository,
    private val loginAttemptRepository: LoginAttemptRepository,
    @Value("\${app.security.ip-block.max-failed-attempts}") private val maxFailedAttempts: Int,
    @Value("\${app.security.ip-block.block-duration-hours}") private val blockDurationHours: Long,
) {
    fun isBlocked(ipAddress: String): Boolean =
        blockedIpRepository.existsByIpAddressAndActiveTrue(ipAddress)

    @Transactional
    fun checkAndBlockIfNeeded(ipAddress: String) {
        if (isBlocked(ipAddress)) return
        val since = LocalDateTime.now().minusHours(1)
        val failedCount = loginAttemptRepository
            .countByIpAddressAndSuccessAndTimestampAfter(ipAddress, false, since)
        if (failedCount >= maxFailedAttempts) {
            blockIp(ipAddress, "Exceeded $failedCount failed login attempts in 1 hour")
        }
    }

    @Transactional
    fun blockIp(ipAddress: String, reason: String, hours: Long = blockDurationHours): BlockedIp {
        val existing = blockedIpRepository.findActiveBlock(ipAddress)
        if (existing.isPresent) return existing.get()
        return blockedIpRepository.save(
            BlockedIp(
                ipAddress = ipAddress,
                reason = reason,
                expiresAt = LocalDateTime.now().plusHours(hours),
            )
        )
    }

    @Transactional
    fun unblockIp(ipAddress: String) {
        blockedIpRepository.findActiveBlock(ipAddress).ifPresent { block ->
            block.active = false
            blockedIpRepository.save(block)
        }
    }
}
