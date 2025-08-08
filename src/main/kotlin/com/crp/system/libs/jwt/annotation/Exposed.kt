package com.crp.system.libs.jwt.annotation

@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.FUNCTION, AnnotationTarget.PROPERTY_GETTER, AnnotationTarget.PROPERTY_SETTER)
annotation class Exposed(
    /**
     * List of environments where you can access the endpoint without role or owner authorization.
     */
    val environments: Array<String> = [])