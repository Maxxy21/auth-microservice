package com.maxwell.auth.entity

import jakarta.persistence.*
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import java.time.LocalDateTime

@Entity
@Table(name = "users")
class User(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    var id: Long = 0,

    @Column(unique = true, nullable = false)
    var email: String = "",

    @Column(name = "password_hash")
    private var passwordHash: String = "",

    @Column(nullable = false)
    var firstName: String = "",

    @Column(nullable = false)
    var lastName: String = "",

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    @CollectionTable(name = "user_roles", joinColumns = [JoinColumn(name = "user_id")])
    @Column(name = "role")
    var roles: MutableSet<Role> = mutableSetOf(Role.USER),

    @Column(nullable = false)
    var enabled: Boolean = false,

    @Column(nullable = false)
    var accountLocked: Boolean = false,

    var lockedUntil: LocalDateTime? = null,

    var failedLoginAttempts: Int = 0,

    @Column(nullable = false, updatable = false)
    var createdAt: LocalDateTime = LocalDateTime.now(),

    var lastLoginAt: LocalDateTime? = null,

    var lastLoginIp: String? = null,

    var provider: String? = null,

    var providerId: String? = null,
) : UserDetails {

    fun updatePassword(encoded: String) {
        passwordHash = encoded
    }

    override fun getAuthorities(): Collection<GrantedAuthority> =
        roles.map { SimpleGrantedAuthority("ROLE_${it.name}") }

    override fun getPassword(): String = passwordHash

    override fun getUsername(): String = email

    override fun isAccountNonExpired(): Boolean = true

    override fun isAccountNonLocked(): Boolean {
        if (!accountLocked) return true
        return lockedUntil != null && LocalDateTime.now().isAfter(lockedUntil)
    }

    override fun isCredentialsNonExpired(): Boolean = true

    override fun isEnabled(): Boolean = enabled
}
