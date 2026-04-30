package com.maxwell.auth.exception

import com.maxwell.auth.dto.ApiResponse
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice

@RestControllerAdvice
class GlobalExceptionHandler {

    private val log = LoggerFactory.getLogger(javaClass)

    @ExceptionHandler(AccountLockedException::class)
    fun handleAccountLocked(ex: AccountLockedException): ResponseEntity<ApiResponse> =
        ResponseEntity.status(HttpStatus.LOCKED)
            .body(ApiResponse(false, ex.message ?: "Account is locked"))

    @ExceptionHandler(IpBlockedException::class)
    fun handleIpBlocked(ex: IpBlockedException): ResponseEntity<ApiResponse> =
        ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(ApiResponse(false, ex.message ?: "IP address is blocked"))

    @ExceptionHandler(RateLimitExceededException::class)
    fun handleRateLimit(ex: RateLimitExceededException): ResponseEntity<ApiResponse> =
        ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
            .body(ApiResponse(false, ex.message ?: "Too many requests"))

    @ExceptionHandler(UserAlreadyExistsException::class)
    fun handleUserAlreadyExists(ex: UserAlreadyExistsException): ResponseEntity<ApiResponse> =
        ResponseEntity.status(HttpStatus.CONFLICT)
            .body(ApiResponse(false, ex.message ?: "User already exists"))

    @ExceptionHandler(InvalidTokenException::class)
    fun handleInvalidToken(ex: InvalidTokenException): ResponseEntity<ApiResponse> =
        ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(ApiResponse(false, ex.message ?: "Invalid or expired token"))

    @ExceptionHandler(UserNotFoundException::class)
    fun handleUserNotFound(ex: UserNotFoundException): ResponseEntity<ApiResponse> =
        ResponseEntity.status(HttpStatus.NOT_FOUND)
            .body(ApiResponse(false, ex.message ?: "User not found"))

    @ExceptionHandler(AccountNotEnabledException::class)
    fun handleAccountNotEnabled(ex: AccountNotEnabledException): ResponseEntity<ApiResponse> =
        ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(ApiResponse(false, ex.message ?: "Account not verified"))

    @ExceptionHandler(BadCredentialsException::class)
    fun handleBadCredentials(ex: BadCredentialsException): ResponseEntity<ApiResponse> =
        ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(ApiResponse(false, "Invalid email or password"))

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidation(ex: MethodArgumentNotValidException): ResponseEntity<ApiResponse> {
        val errors = ex.bindingResult.fieldErrors.map { "${it.field}: ${it.defaultMessage}" }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(ApiResponse(false, errors.joinToString(", ")))
    }

    @ExceptionHandler(Exception::class)
    fun handleGeneral(ex: Exception): ResponseEntity<ApiResponse> {
        log.error("Unhandled exception", ex)
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(ApiResponse(false, "An unexpected error occurred"))
    }
}
