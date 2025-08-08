package com.crp.system.libs.jwt

import com.crp.system.libs.jwt.interceptor.AllowedCollector
import com.crp.system.libs.jwt.service.JwtService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.core.env.Environment

@AutoConfiguration
class GrpcJwtAutoConfiguration(@Autowired
                              private val environment: Environment,
                               @Autowired
                               private val grpcJwtProperties: GrpcJwtProperties,
                               @Autowired
                               private val allowedCollector: AllowedCollector) {

    private val log = org.slf4j.LoggerFactory.getLogger(GrpcJwtAutoConfiguration::class.java)

    @Bean
    fun jwtService(): JwtService {
        return JwtService(environment, grpcJwtProperties)
    }
}

