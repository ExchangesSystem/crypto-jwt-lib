package com.crp.system.libs.jwt.interceptor

import com.crp.system.libs.jwt.annotation.Allow
import com.crp.system.libs.jwt.annotation.Exposed
import com.crp.system.libs.jwt.data.AllowedMethod
import com.google.common.collect.Sets
import net.devh.boot.grpc.server.service.GrpcService
import org.springframework.beans.factory.config.BeanPostProcessor
import org.springframework.stereotype.Component
import java.lang.reflect.Method
import java.util.*
import java.util.function.Function
import java.util.stream.Collectors

@Component
class AllowedCollector : BeanPostProcessor {
    private var allowedMethods: Map<String, AllowedMethod>? = null
    private var exposedMethods: Map<String, Set<String>>? = null

    companion object {
        private const val GRPC_BASE_CLASS_NAME_EXT = "ImplBase"
        private const val PACKAGE_CLASS_DELIMITER = "."
        private const val CLASS_METHOD_DELIMITER = "/"
        private const val EMPTY_STRING = ""
    }

    override fun postProcessBeforeInitialization(bean: Any, beanName: String): Any? {
        processGrpcServices(bean.javaClass)
        return bean
    }

    override fun postProcessAfterInitialization(bean: Any, beanName: String): Any? {
        return bean
    }

    fun getAllowedAuth(methodName: String): AllowedMethod? {
        return allowedMethods!![methodName]
    }

    fun getExposedEnv(methodName: String): Set<String>? {
        return exposedMethods!![methodName]
    }

    private fun processGrpcServices(beanClass: Class<*>) {
        if (beanClass.isAnnotationPresent(GrpcService::class.java)) {
            allowedMethods = findAllowedMethods(beanClass)
            exposedMethods = findExposedMethods(beanClass)
        }
    }

    private fun findAllowedMethods(beanClass: Class<*>): Map<String, AllowedMethod> {
        return Arrays.stream(beanClass.getMethods())
            .filter { method: Method -> method.isAnnotationPresent(Allow::class.java) }
            .map { method: Method -> buildAllowed(beanClass, method) }
            .collect(Collectors.toMap(Function { obj: AllowedMethod -> obj.method }, Function { allowedMethod: AllowedMethod -> allowedMethod }))
    }

    private fun findExposedMethods(beanClass: Class<*>): Map<String, Set<String>> {
        return Arrays.stream(beanClass.getMethods())
            .filter { method: Method -> method.isAnnotationPresent(Exposed::class.java) }
            .collect(Collectors.toMap(
                Function { method: Method -> getGrpcServiceDescriptor(beanClass, method) }, Function { method: Method -> buildEnv(method) }))
    }

    private fun buildEnv(method: Method): Set<String> {
        val annotation = method.getAnnotation(Exposed::class.java)
        return Arrays.stream(annotation.environments).collect(Collectors.toSet())
    }

    private fun buildAllowed(gRpcServiceClass: Class<*>, method: Method): AllowedMethod {
        val annotation = method.getAnnotation(Allow::class.java)
        val roles: Set<String> = Sets.newHashSet(Arrays.asList(*annotation.roles))
        return AllowedMethod(getGrpcServiceDescriptor(gRpcServiceClass, method), annotation.ownerField, roles)
    }

    private fun getGrpcServiceDescriptor(gRpcServiceClass: Class<*>, method: Method): String {
        val superClass = gRpcServiceClass.superclass
        return (superClass.getPackage().name +
                PACKAGE_CLASS_DELIMITER +
                superClass.getSimpleName().replace(GRPC_BASE_CLASS_NAME_EXT, EMPTY_STRING) +
                CLASS_METHOD_DELIMITER +
                method.name).lowercase(Locale.getDefault())
    }
}