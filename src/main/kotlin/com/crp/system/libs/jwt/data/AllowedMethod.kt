package com.crp.system.libs.jwt.data

import java.util.*

class AllowedMethod(method: String, ownerField: String, roles: Set<String>) {
    val method: String
    @JvmField
    val ownerField: String
    @JvmField
    val roles: Set<String>

    init {
        this.method = Objects.requireNonNull(method)
        this.ownerField = Objects.requireNonNull(ownerField)
        this.roles = Objects.requireNonNull(roles)
    }
}