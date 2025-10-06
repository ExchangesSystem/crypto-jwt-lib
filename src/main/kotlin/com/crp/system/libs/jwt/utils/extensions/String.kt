package com.crp.system.libs.jwt.utils.extensions

import com.crp.system.libs.jwt.service.gson

inline fun String.toLongSafe(): Long? {
    try {
       return java.lang.Long.parseLong(this)
    } catch (e: Exception) {
        return null
    }
}

inline fun <reified A> A?.isNull(): Boolean {
    return this == null
}

inline fun <reified T> String.toTokenData(): T? {
    return try {
        gson.fromJson(this, T::class.java)
    } catch (e: Exception) {
        null
    }
}