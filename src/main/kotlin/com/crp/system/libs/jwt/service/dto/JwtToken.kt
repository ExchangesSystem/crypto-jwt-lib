package com.crp.system.libs.jwt.service.dto

import java.time.LocalDateTime

class JwtToken(@JvmField val token: String, @JvmField val expiration: LocalDateTime)