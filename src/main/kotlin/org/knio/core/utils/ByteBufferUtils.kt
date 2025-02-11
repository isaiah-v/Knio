package org.knio.core.utils

import org.knio.core.context.ByteBufferPool
import org.knio.core.context.ReleasableBuffer
import java.nio.Buffer
import java.nio.ByteBuffer

/**
 * Compacts the buffer if it has remaining bytes, otherwise increases the buffer size by the specified amount.
 *
 * @param increaseSize The amount to increase the buffer size by if it is full.
 * @param pool The pool to release the buffer to if it is increased in size.
 * @return The buffer compacted or increased in size.
 */
/*
internal fun ByteBuffer.compactOrIncreaseSize(increaseSize: Int, pool: ByteBufferPool?=null): ByteBuffer {
    if (hasRemaining() || limit()!=capacity()) {
        compact()
    } else {
        val size = capacity() + increaseSize

        val newBuffer = pool?.acquire(size) ?:  ByteBuffer.allocate(size)
        newBuffer.put(this)
        pool?.release(this)
        return newBuffer
    }
    return this
}
 */

internal fun ReleasableBuffer<ByteBuffer>.compactOrIncreaseSize(increaseSize: Int) {
    val buffer = this.value
    if (buffer.hasRemaining() || buffer.limit()!=buffer.capacity()) {
        buffer.compact()
    } else {
        this.resize(buffer.capacity() + increaseSize)
    }
}

/**
 * Transfers as many bytes as possible from this buffer to the destination buffer.
 *
 * If this buffer is smaller than the destination buffer, the remaining bytes in
 * this buffer are transferred. If the destination buffer is smaller, the number
 * of bytes that can be transferred are transferred.
 *
 * The position of both buffers are updated to reflect the transfer.
 *
 * @throws java.nio.ReadOnlyBufferException if the destination buffer is read-only
 */
internal fun ByteBuffer.transferTo(dest: ByteBuffer): Int {
    val read = minOf(this.remaining(), dest.remaining())
    if(read == 0) return -1

    dest.put(dest.position(), this, this.position(), read)

    this.position(this.position() + read)
    dest.position(dest.position() + read)

    return read
}