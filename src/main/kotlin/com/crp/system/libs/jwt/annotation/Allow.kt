package com.crp.system.libs.jwt.annotation

@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.FUNCTION, AnnotationTarget.PROPERTY_GETTER, AnnotationTarget.PROPERTY_SETTER)
annotation class Allow(
    /**
     * List of roles that will by checked. One of the roles must be presented in JWT token.
     */
    val roles: Array<String> = [],
    /**
     * Optional field. Ownership of entity will be checked first by getting owners id from payload by
     * field specified in annotation. If the id does not match and data are owned by other authority,
     * specified roles will be checked then.
     */
    val ownerField: String = "")