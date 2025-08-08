package com.crp.system.libs.jwt.data

import com.crp.system.libs.jwt.utils.gson

data class JWTTokenData(val userId: String, val tokenId: String, val deviceId: String?, val email: String)

fun String.toJWTTokenData(): JWTTokenData? {
    return try {
        gson.fromJson(this, JWTTokenData::class.java)
    } catch (e: Exception) {
        null
    }
}