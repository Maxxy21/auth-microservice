package com.maxwell.auth.service

import com.maxwell.auth.entity.User
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class JwtServiceTest {

    private lateinit var jwtService: JwtService

    private val secret = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970"
    private val expiration = 900_000L

    @BeforeEach
    fun setup() {
        jwtService = JwtService(secret, expiration)
    }

    private fun user(email: String = "test@example.com") = User(
        id = 1L, email = email, firstName = "Test", lastName = "User", enabled = true,
    )

    @Test
    fun `generateAccessToken produces non-blank token`() {
        val token = jwtService.generateAccessToken(user())
        assertTrue(token.isNotBlank())
    }

    @Test
    fun `extractUsername returns the subject email`() {
        val token = jwtService.generateAccessToken(user("jane@example.com"))
        assertEquals("jane@example.com", jwtService.extractUsername(token))
    }

    @Test
    fun `isTokenValid returns true for matching user and fresh token`() {
        val u = user()
        val token = jwtService.generateAccessToken(u)
        assertTrue(jwtService.isTokenValid(token, u))
    }

    @Test
    fun `isTokenValid returns false when user email does not match`() {
        val token = jwtService.generateAccessToken(user("a@example.com"))
        assertFalse(jwtService.isTokenValid(token, user("b@example.com")))
    }

    @Test
    fun `isTokenExpired returns false for a just-issued token`() {
        val token = jwtService.generateAccessToken(user())
        assertFalse(jwtService.isTokenExpired(token))
    }

    @Test
    fun `expired token is detected correctly`() {
        val shortLivedService = JwtService(secret, -1000L)
        val token = shortLivedService.generateAccessToken(user())
        assertTrue(shortLivedService.isTokenExpired(token))
    }
}
