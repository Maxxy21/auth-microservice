package com.maxwell.auth.controller

import com.maxwell.auth.dto.ApiResponse
import com.maxwell.auth.dto.UserResponse
import com.maxwell.auth.entity.User
import com.maxwell.auth.service.UserService
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/users")
class UserController(private val userService: UserService) {

    @GetMapping("/me")
    fun getCurrentUser(
        @AuthenticationPrincipal user: User,
    ): ResponseEntity<UserResponse> {
        with(userService) { return ResponseEntity.ok(user.toResponse()) }
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    fun getAllUsers(): ResponseEntity<List<UserResponse>> =
        ResponseEntity.ok(userService.getAllUsers())

    @PostMapping("/{id}/promote")
    @PreAuthorize("hasRole('ADMIN')")
    fun promoteToAdmin(@PathVariable id: Long): ResponseEntity<ApiResponse> {
        userService.promoteToAdmin(id)
        return ResponseEntity.ok(ApiResponse(true, "User $id promoted to ADMIN"))
    }
}
