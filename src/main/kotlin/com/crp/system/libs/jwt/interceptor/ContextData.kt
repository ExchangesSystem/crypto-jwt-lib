package com.crp.system.libs.jwt.interceptor

import com.crp.system.libs.jwt.data.JwtContextData
import io.grpc.Attributes
import io.grpc.Context
import io.grpc.Metadata

object ContextData {
    val metaData: Context.Key<Metadata> = Context.key("MetaData")
    val attributes: Context.Key<Attributes> = Context.key("Attributes")
    val jwtContextData: Context.Key<JwtContextData> = Context.key("JwtContextData")
    val authorizationMetadata = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER)
}