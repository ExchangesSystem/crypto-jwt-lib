package com.crp.system.libs.jwt.service

import com.crp.system.libs.jwt.GrpcJwtProperties
import com.crp.system.libs.jwt.data.JWTTokenData
import com.crp.system.libs.jwt.data.toJWTTokenData
import com.crp.system.libs.jwt.data.toTokenData
import com.crp.system.libs.jwt.interceptor.AuthServerInterceptor
import com.crp.system.libs.jwt.service.dto.JwtData
import com.crp.system.libs.jwt.service.dto.JwtMetadata
import com.crp.system.libs.jwt.service.dto.JwtToken
import com.crp.system.libs.jwt.utils.extensions.isNull
import com.google.common.collect.Lists
import com.google.common.collect.Sets
import com.google.gson.Gson
import io.jsonwebtoken.*
import org.apache.commons.codec.digest.DigestUtils
import org.springframework.core.env.Environment
import java.security.SignatureException
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.*
import java.util.stream.Collectors
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

val gson = Gson()

class JwtService(
    val env: Environment,
    properties: GrpcJwtProperties
) {

    companion object {
        @JvmStatic
        val TOKEN_ENV = "token_env"
        @JvmStatic
        val JWT_ROLES = "jwt_roles"
        @JvmStatic
        val INTERNAL_ACCOUNT = "internal_account"
        @JvmStatic
        val REFRESH_TIME_THRESHOLD = 0.2
    }

    private var properties: GrpcJwtProperties? = null

    private var metadata: JwtMetadata? = null
    private var internal: JwtToken? = null
    private val secret = generateKey(properties.secret, properties.algorithm)

    init {
        this.properties = properties
        metadata = JwtMetadata(properties.expirationSec,
            secret,
            Arrays.stream(env.activeProfiles).collect(Collectors.toList()))
        internal = generateInternalToken(properties.expirationSec, metadata)
    }

    /**
     * Generate fresh JWT token with specified roles and userId.
     * @param data JwtData with data needed for JWT token generation.
     * @return String version of your new JWT token
     */
    fun generate(data: JwtData): String {
        return generateJwt(data, metadata)
    }

    /**
     * Get the internal JWT token and automatically refresh the token if it's expired.
     * This token is used for inter-service communication.
     * @return String version of your internal JWT token.
     */
    fun getInternal(): String {
        val refreshThresholdValue = properties!!.expirationSec * REFRESH_TIME_THRESHOLD
        if (LocalDateTime.now().plusSeconds(refreshThresholdValue.toLong()).isAfter(internal!!.expiration)) {
            refreshInternalToken()
        }
        return internal!!.token
    }

    /**
     * Get the key used for JWT token generation.
     * @return generated SecretKey with configuration from application.properties.
     */
    fun getKey(): SecretKey {
        return metadata!!.key
    }

    private fun generateKey(signingSecret: String, signAlgorithm: String): SecretKeySpec {
        val sha256hex = DigestUtils.sha256Hex(signingSecret)
        val decodedKey = Base64.getDecoder().decode(sha256hex)
        return SecretKeySpec(decodedKey, 0, decodedKey.size, signAlgorithm)
    }

    private fun generateJwt(data: JwtData, metadata: JwtMetadata?): String {
        val future = LocalDateTime.now().plusSeconds(metadata!!.expirationSec)
        val ourClaimsBuilder = Jwts.claims()
        ourClaimsBuilder.add(JWT_ROLES, Lists.newArrayList(data.roles))
        ourClaimsBuilder.add(TOKEN_ENV, metadata.env)
        val ourClaims = ourClaimsBuilder.build()
        return Jwts.builder()
            .setClaims(ourClaims)
            .setSubject(data.tokenData)
            .setIssuedAt(Date.from(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant()))
            .setExpiration(Date.from(future.atZone(ZoneId.systemDefault()).toInstant()))
            .signWith(metadata.key).compact()
    }

    private fun refreshInternalToken() {
        internal = generateInternalToken(properties!!.expirationSec, metadata)
    }

    private fun generateInternalToken(expirationSec: Long, jwtMetadata: JwtMetadata?): JwtToken {
        return JwtToken(
            generateJwt(JwtData(INTERNAL_ACCOUNT, Sets.newHashSet(GrpcRole.INTERNAL)), jwtMetadata),
            LocalDateTime.now().plusSeconds(expirationSec)
        )
    }


    /**
     * Extracts data from a JWT token without requiring an additional secret parameter
     *
     * @param token The JWT token to extract data from
     * @return A Claims object containing the JWT payload data
     * @throws SecurityException if the token is invalid or expired
     */
    fun extractAllClaims(token: String): Claims? {
        try {
            val claims = Jwts.parser()
                .setSigningKey(secret)
                .build()
                .parseClaimsJws(token)
                .payload

            return claims
        } catch (e: ExpiredJwtException) {
            throw JwtException("Token expired", e)
        } catch (e: UnsupportedJwtException) {
            throw JwtException("Unsupported token", e)
        } catch (e: MalformedJwtException) {
            throw JwtException("Malformed token", e)
        } catch (e: SignatureException) {
            throw JwtException("Invalid signature", e)
        } catch (e: Exception) {
            throw JwtException("Invalid token", e)
        }
    }

    fun extractJWTTokenData(token: String): JWTTokenData? {
        try {
            // Parse the JWT token to get the payload
            val jwtBody = extractAllClaims(token)

            // Get the subject which contains the JWT token data
            val tokenDataJson = jwtBody?.subject

            // Convert the JSON string to JWTTokenData object
            return tokenDataJson?.toJWTTokenData()
        } catch (e: Exception) {
            return null
        }
    }

    fun extractJwtData(authHeader: String?): JWTTokenData? {
        if (authHeader.isNull() || !authHeader!!.startsWith("${AuthServerInterceptor.BEARER} ")) {
            return null
        }

        try {
            val token = authHeader.split("${AuthServerInterceptor.BEARER} ") // Remove "Bearer " prefix
            if (token.size < 2) {
                return null
            }
            // Parse the JWT token to get the payload
            return extractJWTTokenData(token[1])
        } catch (e: Exception) {
            return null
        }
    }

    inline fun <reified T> extractCustomData(token: String): T? {
        try {
            // Parse the JWT token to get the payload
            val jwtBody = extractAllClaims(token)

            // Get the subject which contains the JWT token data
            val tokenDataJson = jwtBody?.subject

            // Convert the JSON string to JWTTokenData object
            return tokenDataJson?.toTokenData()
        } catch (e: Exception) {
            return null
        }
    }

    inline fun <reified T> extractCustomData(authHeader: String?): T? {
        if (authHeader.isNull() || !authHeader!!.startsWith("${AuthServerInterceptor.BEARER} ")) {
            return null
        }

        try {
            val token = authHeader.split("${AuthServerInterceptor.BEARER} ") // Remove "Bearer " prefix
            if (token.size < 2) {
                return null
            }
            // Parse the JWT token to get the payload
            return extractCustomData(token[1])
        } catch (e: Exception) {
            return null
        }
    }

}