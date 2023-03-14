package com.example.demoauth.auth

import com.example.demoauth.config.JwtService
import com.example.demoauth.user.Role
import com.example.demoauth.user.User
import com.example.demoauth.user.UserRepository
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class AuthenticationService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val jwtService: JwtService,
    private val authenticationManager: AuthenticationManager
    ) {
    fun register(request: RegisterRequest): AuthenticationResponse {
        val user = User(
            firstname = request.firstName,
            lastname = request.lastName,
            email = request.email,
            password = passwordEncoder.encode(request.password),
            role = Role.USER
        )
        userRepository.save(user)
        val jwtToken = jwtService.generateToken(user)
        return AuthenticationResponse(token = jwtToken)
    }

    fun authenticate(request: AuthenticationRequest): AuthenticationResponse? {
        authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken(request.email, request.password)
        )
        val user = userRepository.findByEmail(request.email)
        val jwtToken = user?.let { jwtService.generateToken(it) }
        return jwtToken?.let { AuthenticationResponse(token = it) }
    }
}