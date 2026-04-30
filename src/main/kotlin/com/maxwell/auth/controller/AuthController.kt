package com.maxwell.auth.controller

import com.maxwell.auth.dto.*
import com.maxwell.auth.entity.User
import com.maxwell.auth.service.AuthService
import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/auth")
class AuthController(private val authService: AuthService) {

    @PostMapping("/register")
    fun register(
        @Valid @RequestBody request: RegisterRequest,
    ): ResponseEntity<ApiResponse> =
        ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request))

    @PostMapping("/login")
    fun login(
        @Valid @RequestBody request: LoginRequest,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<AuthResponse> {
        val ip = resolveClientIp(httpRequest)
        val userAgent = httpRequest.getHeader("User-Agent")
        return ResponseEntity.ok(authService.login(request, ip, userAgent))
    }

    @PostMapping("/refresh")
    fun refresh(
        @Valid @RequestBody request: RefreshTokenRequest,
    ): ResponseEntity<AuthResponse> =
        ResponseEntity.ok(authService.refresh(request))

    @PostMapping("/logout")
    fun logout(
        @AuthenticationPrincipal user: User,
    ): ResponseEntity<ApiResponse> {
        authService.logout(user.id)
        return ResponseEntity.ok(ApiResponse(true, "Logged out successfully"))
    }

    private fun resolveClientIp(request: HttpServletRequest): String {
        val forwarded = request.getHeader("X-Forwarded-For")
        return if (!forwarded.isNullOrBlank()) forwarded.split(",").first().trim()
        else request.remoteAddr ?: "unknown"
    }
}
