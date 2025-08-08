package com.crp.system.libs.jwt.data

import io.grpc.Metadata

object GrpcHeader {
    private const val AUTHORIZATION_KEY = "Authorization"
    @JvmField
    val AUTHORIZATION = Metadata.Key.of(AUTHORIZATION_KEY, Metadata.ASCII_STRING_MARSHALLER)
}