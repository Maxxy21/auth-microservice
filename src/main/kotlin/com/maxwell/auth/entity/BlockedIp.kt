package com.maxwell.auth.entity

import jakarta.persistence.*
import java.time.LocalDateTime

@Entity
@Table(name = "blocked_ips")
class BlockedIp(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    var id: Long = 0,

    @Column(unique = true, nullable = false)
    var ipAddress: String = "",

    @Column(nullable = false)
    var reason: String = "",

    @Column(nullable = false, updatable = false)
    var blockedAt: LocalDateTime = LocalDateTime.now(),

    var expiresAt: LocalDateTime? = null,

    @Column(nullable = false)
    var active: Boolean = true,
)
