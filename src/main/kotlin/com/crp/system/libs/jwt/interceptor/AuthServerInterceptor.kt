package com.crp.system.libs.jwt.interceptor

import com.crp.system.libs.jwt.data.AllowedMethod
import com.crp.system.libs.jwt.data.GrpcHeader
import com.crp.system.libs.jwt.data.JwtContextData
import com.crp.system.libs.jwt.exception.AuthException
import com.crp.system.libs.jwt.exception.UnauthenticatedException
import com.crp.system.libs.jwt.service.JwtService
import com.crp.system.libs.jwt.service.JwtService.Companion.JWT_ROLES
import com.crp.system.libs.jwt.service.JwtService.Companion.TOKEN_ENV
import com.crp.system.libs.jwt.service.dto.JwtData
import com.crp.system.libs.jwt.utils.extensions.isNull
import com.google.common.collect.Sets
import io.grpc.*
import io.jsonwebtoken.JwtException
import io.jsonwebtoken.Jwts
import net.devh.boot.grpc.server.interceptor.GrpcGlobalServerInterceptor
import org.springframework.core.env.Environment
import java.lang.reflect.Field
import java.util.*

@GrpcGlobalServerInterceptor
class AuthServerInterceptor(
    private val allowedCollector: AllowedCollector,
    private val jwtService: JwtService,
    private val environment: Environment
) : ServerInterceptor {

    companion object {
        private const val GRPC_FIELD_MODIFIER = "_"
        const val BEARER = "Bearer"
        private val NO_OP_LISTENER: ServerCall.Listener<*> = object : ServerCall.Listener<Any?>() {}
    }

    override fun <ReqT, RespT> interceptCall(
        call: ServerCall<ReqT, RespT>, metadata: Metadata, next: ServerCallHandler<ReqT, RespT>
    ): ServerCall.Listener<ReqT> {
        return try {
            var contextData: JwtContextData? = null
            val methodName = call.methodDescriptor.fullMethodName.lowercase(Locale.getDefault())
            if (isExposed(methodName).not()) {
                contextData = parseAuthContextData(metadata)
            }
            buildListener(call, metadata, next, contextData)
        } catch (e: UnauthenticatedException) {
            call.close(Status.UNAUTHENTICATED.withDescription(e.message).withCause(e.cause), metadata)
            NO_OP_LISTENER as ServerCall.Listener<ReqT>
        }
    }

    private fun <ReqT, RespT> buildListener(call: ServerCall<ReqT, RespT>, metadata: Metadata,
        next: ServerCallHandler<ReqT, RespT>, contextData: JwtContextData?
    ): ForwardingServerCallListener<ReqT> {
        //Extract Context params
        val newContext: Context = Context.current().withValue(ContextData.metaData, metadata)
        val newContextAttributes = newContext.withValue(ContextData.attributes, call.attributes)
        val newContextJwtContextData = newContextAttributes.withValue(ContextData.jwtContextData, contextData)
        val customDelegate = Contexts.interceptCall(newContextJwtContextData, call, metadata, next)

        var delegate: ServerCall.Listener<*> = NO_OP_LISTENER

        val forwardingServerCallListener = object : ForwardingServerCallListener<ReqT>() {

            override fun delegate(): ServerCall.Listener<ReqT> {
                return delegate as ServerCall.Listener<ReqT>
            }

            override fun onMessage(request: ReqT) {
                try {
                    if (delegate === NO_OP_LISTENER) {
                        val methodName = call.methodDescriptor.fullMethodName.lowercase(Locale.getDefault())
                        validateAnnotatedMethods(request, contextData, methodName)
                        delegate = customDelegate
                    }
                } catch (e: AuthException) {
                    call.close(Status.PERMISSION_DENIED
                        .withDescription(e.message)
                        .withCause(e.cause), metadata)
                }
                super.onMessage(request)
            }
        }
        return forwardingServerCallListener
    }

    private fun <ReqT> validateAnnotatedMethods(request: ReqT, contextData: JwtContextData?, methodName: String) {
        if (validateExposedAnnotation(contextData, methodName)) return
        validateAllowedAnnotation(request, contextData, methodName)
    }

    private fun isExposed(methodName: String): Boolean {
        return allowedCollector.getExposedEnv(methodName).isNull().not()
    }

    private fun validateExposedAnnotation(contextData: JwtContextData?, methodName: String): Boolean {
        val exposedToEnvironments = allowedCollector.getExposedEnv(methodName) ?: Sets.newHashSet()
        val methodIsExposed = environment.activeProfiles.any { exposedToEnvironments.contains(it) }
        if (methodIsExposed) {
            if (contextData == null) throw AuthException("Invalid JWT data.")
            val rawEnvironments = contextData.jwtClaims?.get(TOKEN_ENV, List::class.java)
            val environments = rawEnvironments?.toSet()
            return exposedToEnvironments.any { environments?.contains(it) == true }
        }
        return false
    }

    private fun <ReqT> validateAllowedAnnotation(request: ReqT, contextData: JwtContextData?, methodName: String) {
        val allowedAuth = allowedCollector.getAllowedAuth(methodName)
        if (allowedAuth.isNull()) return
        authorizeOwnerOrRoles(request, contextData, allowedAuth!!)
    }

    private fun <ReqT> authorizeOwnerOrRoles(request: ReqT, contextData: JwtContextData?, allowedMethod: AllowedMethod) {
        if (contextData == null) throw AuthException("Invalid JWT data.")
        if (allowedMethod.ownerField.isEmpty()) {
            contextData.roles?.let { validateRoles(HashSet(allowedMethod.roles), it) }
        } else {
            authorizeOwner(request, contextData, allowedMethod)
        }
    }

    private fun <ReqT> parseOwner(request: ReqT, fieldName: String): String {
        return try {
            val field: Field = request!!::class.java.getDeclaredField(fieldName + GRPC_FIELD_MODIFIER)
            field.setAccessible(true)
            field[request].toString()
        } catch (e: NoSuchFieldException) {
            throw AuthException("Missing owner field.")
        } catch (e: IllegalAccessException) {
            throw AuthException("Missing owner field.")
        }
    }

    private fun <ReqT> authorizeOwner(request: ReqT, jwtContext: JwtContextData, allowedMethod: AllowedMethod) {
        val uid = parseOwner(request, allowedMethod.ownerField)
        if (jwtContext.tokenData != uid) jwtContext.roles?.let { validateRoles(HashSet(allowedMethod.roles), it) }
    }

    private fun validateRoles(requiredRoles: MutableSet<String>, userRoles: Set<String>) {
        if (requiredRoles.isEmpty()) {
            throw AuthException("Endpoint does not have specified roles.")
        }
        requiredRoles.retainAll(Objects.requireNonNull(userRoles))
        if (requiredRoles.isEmpty()) {
            throw AuthException("Missing required permission roles.")
        }
    }

    private fun parseAuthContextData(metadata: Metadata): JwtContextData? {
        return try {
            val authHeaderData = metadata.get(GrpcHeader.AUTHORIZATION) ?: return null
            val token = authHeaderData.replace(BEARER, "").trim { it <= ' ' }
            val jwtBody = Jwts.parser()
                .verifyWith(jwtService.getKey())
                .build()
                .parseSignedClaims(token)
                .payload
            val roles = jwtBody.get(JWT_ROLES, List::class.java) as List<String>
            JwtContextData(token, jwtBody.subject, Sets.newHashSet(roles), jwtBody)
        } catch (e: JwtException) {
            throw UnauthenticatedException(e.message)
        } catch (e: IllegalArgumentException) {
            throw UnauthenticatedException(e.message)
        }
    }
}