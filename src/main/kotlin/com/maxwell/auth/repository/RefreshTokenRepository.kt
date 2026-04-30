package com.maxwell.auth.repository

import com.maxwell.auth.entity.RefreshToken
import com.maxwell.auth.entity.User
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.stereotype.Repository
import java.util.Optional

@Repository
interface RefreshTokenRepository : JpaRepository<RefreshToken, Long> {
    fun findByToken(token: String): Optional<RefreshToken>

    @Modifying
    @Query("UPDATE RefreshToken t SET t.revoked = true WHERE t.user = :user")
    fun revokeAllByUser(user: User): Int

    @Modifying
    @Query("DELETE FROM RefreshToken t WHERE t.expiresAt < CURRENT_TIMESTAMP")
    fun deleteExpiredTokens(): Int
}
