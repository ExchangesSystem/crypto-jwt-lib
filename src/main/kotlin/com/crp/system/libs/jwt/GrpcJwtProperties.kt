package com.crp.system.libs.jwt

import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration

@Configuration
data class GrpcJwtProperties(
    @Value("\${grpc.jwt.secret}")
    var secret: String,
    @Value("\${grpc.jwt.algorithm}")
    var algorithm: String,
    @Value("\${grpc.jwt.expirationSec}")
    var expirationSec: Long
)