package com.crp.system.libs.jwt.service.dto

import com.google.common.collect.Sets
import java.util.*

class JwtData(tokenData: String?, roles: Set<String>) {
    val tokenData: String?
    val roles: Set<String>

    constructor(tokenData: String?, role: String) : this(tokenData, Sets.newHashSet<String>(Objects.requireNonNull<String>(role)))

    init {
        this.tokenData = Objects.requireNonNull(tokenData)
        this.roles = Objects.requireNonNull(roles)
    }
}