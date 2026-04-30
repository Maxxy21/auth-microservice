package com.maxwell.auth.service

import com.maxwell.auth.dto.UserResponse
import com.maxwell.auth.entity.Role
import com.maxwell.auth.entity.User
import com.maxwell.auth.exception.UserNotFoundException
import com.maxwell.auth.repository.UserRepository
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class UserService(private val userRepository: UserRepository) : UserDetailsService {

    override fun loadUserByUsername(email: String): UserDetails =
        userRepository.findByEmail(email)
            .orElseThrow { UsernameNotFoundException("User not found: $email") }

    fun findByEmail(email: String): User =
        userRepository.findByEmail(email)
            .orElseThrow { UserNotFoundException("User not found: $email") }

    fun findById(id: Long): User =
        userRepository.findById(id)
            .orElseThrow { UserNotFoundException("User not found with id: $id") }

    fun save(user: User): User = userRepository.save(user)

    fun existsByEmail(email: String): Boolean = userRepository.existsByEmail(email)

    @Transactional
    fun promoteToAdmin(userId: Long): User {
        val user = findById(userId)
        user.roles.add(Role.ADMIN)
        return userRepository.save(user)
    }

    fun getAllUsers(): List<UserResponse> =
        userRepository.findAll().map { it.toResponse() }

    fun User.toResponse() = UserResponse(
        id = id,
        email = email,
        firstName = firstName,
        lastName = lastName,
        roles = roles.map { "ROLE_${it.name}" }.toSet(),
    )
}
