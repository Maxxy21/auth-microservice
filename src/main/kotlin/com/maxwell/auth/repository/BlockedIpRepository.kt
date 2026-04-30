package com.maxwell.auth.repository

import com.maxwell.auth.entity.BlockedIp
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.stereotype.Repository
import java.util.Optional

@Repository
interface BlockedIpRepository : JpaRepository<BlockedIp, Long> {

    @Query(
        "SELECT b FROM BlockedIp b WHERE b.ipAddress = :ipAddress AND b.active = true " +
            "AND (b.expiresAt IS NULL OR b.expiresAt > CURRENT_TIMESTAMP)"
    )
    fun findActiveBlock(ipAddress: String): Optional<BlockedIp>

    fun existsByIpAddressAndActiveTrue(ipAddress: String): Boolean
}
