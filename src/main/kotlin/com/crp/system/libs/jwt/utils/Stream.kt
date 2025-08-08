package com.crp.system.libs.jwt.utils

import io.grpc.stub.StreamObserver

fun <V> StreamObserver<V>.onSend(value: V) {
    this.onNext(value)
    this.onCompleted()
}