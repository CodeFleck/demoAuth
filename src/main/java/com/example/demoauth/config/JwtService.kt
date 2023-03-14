package com.example.demoauth.config

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service
import java.security.Key
import java.util.Date

@Service
class JwtService {

    private val secretKey = "703273357638792F423F4528482B4B6250655368566D597133743677397A2443"

    fun extractUsername(token: String): String? {
        return extractClaim(this, token, Claims::getSubject)
    }

    fun generateToken(userDetails: UserDetails): String {
        return generateToken(mapOf(), userDetails)
    }

    private fun generateToken(extraClaims: Map<String, Any>, userDetails: UserDetails): String {
        return Jwts
            .builder()
            .setClaims(extraClaims)
            .setSubject(userDetails.username)
            .setIssuedAt(Date(System.currentTimeMillis()))
            .setExpiration(Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
            .signWith(getSignInKey(), io.jsonwebtoken.SignatureAlgorithm.HS256)
            .compact()
    }

    fun isTokenValid(token: String, userDetails: UserDetails): Boolean {
        val username = extractUsername(token)
        return username == userDetails.username && !isTokenExpired(token)
    }

    private fun isTokenExpired(token: String): Boolean {
        return extractExpiration(token)?.before(Date()) ?: false
    }

    private fun extractExpiration(token: String): Date? {
        return formatStringToDate(extractClaim(this, token, Claims::getExpiration))
    }

    private fun formatStringToDate(extractClaim: String?): Date? {
        return try {
            Date(extractClaim?.toLong() ?: 0)
        } catch (e: Exception) {
            null
        }
    }

    private fun extractAllClaims(token: String): Claims? {
        return Jwts
            .parserBuilder()
            .setSigningKey(getSignInKey())
            .build()
            .parseClaimsJws(token)
            .body
    }

    private fun getSignInKey(): Key {
        val keyBytes = Decoders.BASE64.decode(secretKey)
        return Keys.hmacShaKeyFor(keyBytes)
    }

    companion object {
        private fun extractClaim(jwtService: JwtService, token: String, claimsResolver: (Claims) -> Any): String? {
            val claims = jwtService.extractAllClaims(token)
            return claims?.let { claimsResolver(it).toString() }
        }
    }

}
