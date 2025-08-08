# Crypto JWT Library

A JWT authentication and authorization library for Spring Boot applications with gRPC support.

## Features

- JWT token generation and validation
- gRPC server interceptors for authentication
- Role-based access control
- Spring Boot auto-configuration
- Annotation-based endpoint protection

## Usage

### Gradle

```gradle
dependencies {
    implementation 'com.github.YourUsername:crypto-jwt-lib:1.0.0'
}
```

### Maven

```xml
<dependency>
    <groupId>com.github.YourUsername</groupId>
    <artifactId>crypto-jwt-lib</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Configuration

Add to your `application.properties`:

```properties
grpc.jwt.algorithm=HmacSHA256
grpc.jwt.secret=your-secret-key
grpc.jwt.expirationSec=3600
```

## Annotations

- `@Allow` - Allow access to specific roles
- `@Exposed` - Mark endpoints as public (no authentication required)