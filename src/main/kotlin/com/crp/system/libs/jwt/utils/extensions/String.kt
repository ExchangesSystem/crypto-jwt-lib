package com.crp.system.libs.jwt.utils.extensions

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