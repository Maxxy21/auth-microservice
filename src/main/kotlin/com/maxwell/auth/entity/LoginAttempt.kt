package com.maxwell.auth.entity

import jakarta.persistence.*
import java.time.LocalDateTime

@Entity
@Table(
    name = "login_attempts",
    indexes = [
        Index(name = "idx_login_ip", columnList = "ipAddress"),
        Index(name = "idx_login_email", columnList = "email"),
        Index(name = "idx_login_timestamp", columnList = "timestamp"),
    ],
)
class LoginAttempt(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    var id: Long = 0,

    @Column(nullable = false)
    var ipAddress: String = "",

    @Column(nullable = false)
    var email: String = "",

    @Column(nullable = false)
    var success: Boolean = false,

    @Column(nullable = false)
    var timestamp: LocalDateTime = LocalDateTime.now(),

    @Column(length = 512)
    var userAgent: String? = null,

    var failureReason: String? = null,
)
