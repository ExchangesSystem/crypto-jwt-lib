package com.crp.system.libs.jwt.data

import io.jsonwebtoken.Claims

data class JwtContextData (
    val jwt: String? = null,
    @JvmField
    val tokenData: String? = null,
    val roles: Set<String>? = null,
    val jwtClaims: Claims? = null
)