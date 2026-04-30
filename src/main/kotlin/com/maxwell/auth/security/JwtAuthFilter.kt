package com.maxwell.auth.security

import com.maxwell.auth.service.JwtService
import com.maxwell.auth.service.UserService
import io.jsonwebtoken.JwtException
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JwtAuthFilter(
    private val jwtService: JwtService,
    private val userService: UserService,
) : OncePerRequestFilter() {

    private val log = LoggerFactory.getLogger(javaClass)

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        chain: FilterChain,
    ) {
        val authHeader = request.getHeader("Authorization")
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response)
            return
        }

        val token = authHeader.removePrefix("Bearer ")
        try {
            val username = jwtService.extractUsername(token)
            if (username.isNotEmpty() && SecurityContextHolder.getContext().authentication == null) {
                val userDetails = userService.loadUserByUsername(username)
                if (jwtService.isTokenValid(token, userDetails)) {
                    val auth = UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.authorities,
                    )
                    auth.details = WebAuthenticationDetailsSource().buildDetails(request)
                    SecurityContextHolder.getContext().authentication = auth
                }
            }
        } catch (ex: JwtException) {
            log.debug("Invalid JWT token: {}", ex.message)
        }

        chain.doFilter(request, response)
    }
}
