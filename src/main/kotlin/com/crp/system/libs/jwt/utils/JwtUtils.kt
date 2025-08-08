package com.crp.system.libs.jwt.utils

import com.google.gson.Gson

val gson = Gson()

inline fun <reified A> A?.isNull(): Boolean {
    return this == null
}