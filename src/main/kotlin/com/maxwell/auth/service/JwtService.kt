package com.maxwell.auth.service

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service
import java.util.Date
import javax.crypto.SecretKey

@Service
class JwtService(
    @Value("\${app.jwt.secret}") private val secretString: String,
    @Value("\${app.jwt.access-token-expiration}") private val accessTokenExpiration: Long,
) {
    private val signingKey: SecretKey by lazy {
        Keys.hmacShaKeyFor(secretString.toByteArray())
    }

    fun generateAccessToken(userDetails: UserDetails, extraClaims: Map<String, Any> = emptyMap()): String =
        Jwts.builder()
            .claims(extraClaims)
            .subject(userDetails.username)
            .claim("roles", userDetails.authorities.map { it.authority })
            .issuedAt(Date())
            .expiration(Date(System.currentTimeMillis() + accessTokenExpiration))
            .signWith(signingKey)
            .compact()

    fun extractUsername(token: String): String =
        extractClaim(token) { it.subject }

    fun isTokenValid(token: String, userDetails: UserDetails): Boolean {
        val username = extractUsername(token)
        return username == userDetails.username && !isTokenExpired(token)
    }

    fun isTokenExpired(token: String): Boolean = try {
        extractClaim(token) { it.expiration }.before(Date())
    } catch (ex: io.jsonwebtoken.ExpiredJwtException) {
        true
    }

    fun getAccessTokenExpiration(): Long = accessTokenExpiration

    private fun <T> extractClaim(token: String, resolver: (Claims) -> T): T =
        resolver(parseAllClaims(token))

    private fun parseAllClaims(token: String): Claims =
        Jwts.parser()
            .verifyWith(signingKey)
            .build()
            .parseSignedClaims(token)
            .payload
}
