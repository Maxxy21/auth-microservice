package com.maxwell.auth.security

import com.maxwell.auth.entity.RefreshToken
import com.maxwell.auth.entity.User
import com.maxwell.auth.repository.RefreshTokenRepository
import com.maxwell.auth.repository.UserRepository
import com.maxwell.auth.service.JwtService
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken
import org.springframework.security.oauth2.core.user.OAuth2User
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler
import org.springframework.stereotype.Component
import org.springframework.transaction.annotation.Transactional
import java.time.LocalDateTime
import java.util.UUID

@Component
class OAuth2AuthenticationSuccessHandler(
    private val userRepository: UserRepository,
    private val refreshTokenRepository: RefreshTokenRepository,
    private val jwtService: JwtService,
) : SimpleUrlAuthenticationSuccessHandler() {

    @Transactional
    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication,
    ) {
        val oauthToken = authentication as OAuth2AuthenticationToken
        val provider = oauthToken.authorizedClientRegistrationId
        val oauthUser = authentication.principal as OAuth2User

        val (email, firstName, lastName, providerId) = extractUserInfo(oauthUser, provider)

        val user = userRepository.findByEmail(email).orElseGet {
            userRepository.save(
                User(
                    email = email,
                    firstName = firstName,
                    lastName = lastName,
                    provider = provider,
                    providerId = providerId,
                    enabled = true,
                )
            )
        }

        val accessToken = jwtService.generateAccessToken(user)
        val refreshToken = refreshTokenRepository.save(
            RefreshToken(
                token = UUID.randomUUID().toString(),
                user = user,
                expiresAt = LocalDateTime.now().plusDays(7),
            )
        )

        val redirectUrl = "http://localhost:3000/oauth2/callback" +
            "?token=$accessToken&refresh=${refreshToken.token}"
        redirectStrategy.sendRedirect(request, response, redirectUrl)
    }

    private data class OAuthUserInfo(
        val email: String,
        val firstName: String,
        val lastName: String,
        val providerId: String,
    )

    private fun extractUserInfo(oauthUser: OAuth2User, provider: String): OAuthUserInfo =
        when (provider) {
            "google" -> OAuthUserInfo(
                email = oauthUser.getAttribute<String>("email") ?: "",
                firstName = oauthUser.getAttribute<String>("given_name") ?: "",
                lastName = oauthUser.getAttribute<String>("family_name") ?: "",
                providerId = oauthUser.getAttribute<String>("sub") ?: "",
            )
            "github" -> OAuthUserInfo(
                email = oauthUser.getAttribute<String>("email") ?: "",
                firstName = oauthUser.getAttribute<String>("login") ?: "",
                lastName = "",
                providerId = oauthUser.getAttribute<Int>("id")?.toString() ?: "",
            )
            else -> throw IllegalArgumentException("Unsupported OAuth2 provider: $provider")
        }
}
