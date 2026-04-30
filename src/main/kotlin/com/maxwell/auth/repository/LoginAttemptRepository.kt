package com.maxwell.auth.repository

import com.maxwell.auth.entity.LoginAttempt
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.stereotype.Repository
import java.time.LocalDateTime

@Repository
interface LoginAttemptRepository : JpaRepository<LoginAttempt, Long> {

    fun countByIpAddressAndSuccessAndTimestampAfter(
        ipAddress: String,
        success: Boolean,
        timestamp: LocalDateTime,
    ): Long

    fun countByEmailAndSuccessAndTimestampAfter(
        email: String,
        success: Boolean,
        timestamp: LocalDateTime,
    ): Long

    @Query(
        "SELECT la FROM LoginAttempt la WHERE la.email = :email AND la.success = true " +
            "ORDER BY la.timestamp DESC"
    )
    fun findRecentSuccessfulLogins(email: String): List<LoginAttempt>

    @Modifying
    fun deleteByTimestampBefore(timestamp: LocalDateTime): Int
}
