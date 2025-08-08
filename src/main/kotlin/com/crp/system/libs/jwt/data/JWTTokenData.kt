package com.crp.system.libs.jwt.data

import com.google.gson.Gson

data class JWTTokenData(val userId: String, val tokenId: String, val deviceId: String?, val email: String)

private val gson = Gson()

fun String.toJWTTokenData(): JWTTokenData? {
    return try {
        gson.fromJson(this, JWTTokenData::class.java)
    } catch (e: Exception) {
        null
    }
}