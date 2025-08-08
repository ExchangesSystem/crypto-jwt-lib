package com.crp.system.libs.jwt.service.dto

import javax.crypto.SecretKey

class JwtMetadata(@JvmField val expirationSec: Long, @JvmField val key: SecretKey, @JvmField val env: List<String>)