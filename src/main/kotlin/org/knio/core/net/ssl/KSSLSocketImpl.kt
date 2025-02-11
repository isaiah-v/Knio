package org.knio.core.net.ssl

import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.withLock
import org.knio.core.nio.readSuspend
import org.knio.core.nio.writeSuspend
import org.knio.core.utils.compactOrIncreaseSize
import org.knio.core.context.KnioContext
import org.knio.core.context.ReleasableBuffer
import org.knio.core.context.acquireReleasableByteBuffer
import org.knio.core.io.KInputStream
import org.knio.core.io.KOutputStream
import java.io.IOException
import java.net.SocketException
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousSocketChannel
import java.nio.channels.ClosedChannelException
import javax.net.ssl.*
import kotlin.math.min

internal class KSSLSocketImpl (
    channel: AsynchronousSocketChannel,
    sslEngine: SSLEngine,
    useClientMode: Boolean,
    private val context: KnioContext
): KSSLSocketAbstract(
    channel,
    sslEngine,
    useClientMode
) {

    private var isHandshakeCompleted = false

    private var isInputShutdown = false
    private val networkRead: ReleasableBuffer<ByteBuffer> = context.byteBufferPool.acquireReleasableByteBuffer(sslEngine.session.packetBufferSize)
    private var applicationRead: ReleasableBuffer<ByteBuffer> = context.byteBufferPool.acquireReleasableByteBuffer(sslEngine.session.applicationBufferSize)

    private var isOutputShutdown = false
    private var networkWrite: ReleasableBuffer<ByteBuffer> = context.byteBufferPool.acquireReleasableByteBuffer(sslEngine.session.packetBufferSize)

    private val inputStream = object : KInputStream(context) {

        override suspend fun read(b: ByteBuffer): Int {
            return this@KSSLSocketImpl.read(b)
        }

        override suspend fun close() {
            this@KSSLSocketImpl.close()
        }
    }

    private val outputStream = object : KOutputStream() {
        override suspend fun write(b: ByteBuffer) {
            this@KSSLSocketImpl.write(b)
        }

        override suspend fun close() {
            this@KSSLSocketImpl.close()
        }
    }

    override suspend fun getInputStream(): KInputStream = lock.withLock {
        if(!ch.isOpen) {
            throw SocketException("Socket is closed")
        }
        if(isInputShutdown) {
            throw SocketException("Socket input is shutdown")
        }
        return inputStream
    }
    override suspend fun getOutputStream(): KOutputStream = lock.withLock {
        if(isOutputShutdown) {
            throw SocketException("Socket output is shutdown")
        }
        return outputStream
    }

    override suspend fun startHandshake() = lock.withLock {
        // initiates or renegotiates the SSL handshake
        startHandshake0()
    }

    /**
     * Same as [KSSLSocket.startHandshake]. This is an internal function that executes without
     * acquiring the lock.
     *
     * @see [KSSLSocket.startHandshake]
     */
    override suspend fun startHandshake0() {
        @Suppress("BlockingMethodInNonBlockingContext")
        sslEngine.beginHandshake()
        handleHandshake()
    }

    /**
     * Handles the handshake process.
     */
    private suspend fun handleHandshake() {
        if(!sslEngine.isHandshaking) {
            return
        }

        var handshakeSession: SSLSession? = null

        while (sslEngine.isHandshaking) {
            if(handshakeSession == null) {
                val session = sslEngine.handshakeSession
                if(session != null) {
                    handshakeSession = session
                    initBuffersForHandshake(session)
                }
            }

            handshakeIteration0()
        }

        // clear buffers
        //networkRead?.clear()
        networkWrite.value.clear()

        isHandshakeCompleted = true
    }

    private suspend fun initBuffersForHandshake(session: SSLSession) {
        if(networkRead.value.capacity()<session.packetBufferSize) {
            networkRead.resize(session.packetBufferSize)
        }
        if(networkWrite.value.capacity()<session.packetBufferSize) {
            networkWrite.resize(session.packetBufferSize)
        }
        if(applicationRead.value.capacity()<session.applicationBufferSize) {
            applicationRead.resize(session.applicationBufferSize)
        }
    }

    private suspend fun handshakeIteration0() {
        when(sslEngine.handshakeStatus!!) {
            SSLEngineResult.HandshakeStatus.NEED_TASK -> {
                runHandshakeTasks()
            }
            SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                wrapHandshake()
            }
            SSLEngineResult.HandshakeStatus.NEED_UNWRAP,
            SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN-> {
                unwrapHandshake()
            }
            SSLEngineResult.HandshakeStatus.FINISHED,
            SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING -> {
                // DONE!
            }
        }
    }

    private fun runHandshakeTasks() {
        while (true) {
            val task = sslEngine.delegatedTask ?: break
            task.run()
        }
    }

    private suspend fun wrapHandshake() {

        while (true) {
            networkWrite.value.clear()

            @Suppress("BlockingMethodInNonBlockingContext")
            val result = sslEngine.wrap(ByteBuffer.wrap(ByteArray(0)), networkWrite.value)

            when (result.status!!) {
                SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                    //
                    throw SSLException("Buffer underflow while wrapping in handshake")
                }

                SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                    // Increase network buffer size. This shouldn't typically happen during handshake.
                    // The network buffer is clear and the size should be the same as the packet buffer size.
                    networkWrite.compactOrIncreaseSize(sslEngine.session.packetBufferSize)
                }

                SSLEngineResult.Status.OK -> {
                    // Unwrap was successful. Write the data to the channel.
                    networkWrite.value.flip()
                    while (networkWrite.value.hasRemaining()) {
                        val read = ch.writeSuspend(networkWrite.value, getWriteTimeout())
                        if (read == -1) {
                            throw SSLException("Connection closed during handshake")
                        }
                        if (read == 0) {
                            // TODO
                            throw SSLException("?? no data written during handshake. try again or error ??")
                        }
                    }
                    break
                }

                SSLEngineResult.Status.CLOSED -> {
                    // closed
                    throw SSLException("Connection closed during handshake")
                }
            }
        }
    }

    private suspend fun unwrapHandshake() {
        while (true) {
            // try to unwrap data from the network buffer
            @Suppress("BlockingMethodInNonBlockingContext")
            val result = sslEngine.unwrap(networkRead.value, applicationRead.value)

            when (result.status!!) {
                SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                    // An underflow implies there wasn't enough information in the network buffer to unwrap

                    // increase the available network buffer size
                    networkRead.compactOrIncreaseSize(
                        sslEngine.session.packetBufferSize
                    )

                    // read more data from the channel
                    val count = ch.readSuspend(networkRead.value)
                    if(count == -1) {
                        throw SSLException("Connection closed during handshake")
                    }
                    if(count == 0) {
                        // TODO
                        throw SSLException("?? no data read during handshake. try again or error ??")
                    }

                    // flip the buffer to prepare for unwrapping
                    networkRead.value.flip()
                }

                SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                    applicationRead.compactOrIncreaseSize(
                        sslEngine.session.applicationBufferSize
                    )
                }

                SSLEngineResult.Status.OK -> {
                    // unwrap was successful. leave the data in the network buffer for the next unwrap
                    applicationRead.value.flip()
                    break
                }

                SSLEngineResult.Status.CLOSED -> {
                    // closed
                    throw SSLException("Connection closed during handshake")
                }
            }
        }
    }

    override suspend fun isInputShutdown(): Boolean = lock.withLock {
        return isInputShutdown
    }

    override suspend fun isOutputShutdown(): Boolean = lock.withLock {
        return isOutputShutdown
    }

    override suspend fun shutdownInput() = lock.withLock {
        shutdownInput0()
    }

    private suspend fun shutdownInput0() {
        try {
            try {
                @Suppress("BlockingMethodInNonBlockingContext")
                sslEngine.closeInbound()
            } catch (e: SSLException) {
                // ignore
            }

            // Clear buffer for reuse or release
            networkRead.value.clear()
        } finally {
            isInputShutdown = true
            networkRead.release()
        }
    }

    override suspend fun shutdownOutput() = lock.withLock {
        shutdownOutput0()
    }

    private suspend fun shutdownOutput0() {
        try {
            sslEngine.closeOutbound()

            networkWrite.value.clear()
            out@ while (true) {
                @Suppress("BlockingMethodInNonBlockingContext")
                val result = sslEngine.wrap(ByteBuffer.allocate(0), networkWrite.value)

                when (result.status!!) {

                    SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                        // increase network buffer size
                        networkWrite.compactOrIncreaseSize(
                            sslEngine.session.packetBufferSize
                        )
                    }

                    SSLEngineResult.Status.OK -> {
                        try {
                            networkWrite.value.flip()
                            while (networkWrite.value.hasRemaining()) {
                                var written = 0;
                                repeat(3) { attempt ->
                                    written = ch.writeSuspend(networkWrite.value)
                                    if (written > 0) return@repeat
                                    delay(100L * attempt) // Backoff delay
                                }

                                if (written <= 0) {
                                    break@out
                                }
                            }
                            networkWrite.value.clear()
                            break
                        } catch (e: ClosedChannelException) {
                            // ignore
                        } catch (e: IOException) {
                            throw e
                        }
                    }

                    SSLEngineResult.Status.CLOSED -> {
                        // closed
                        break@out
                    }

                    else -> {
                        throw SSLException("Unexpected SSL wrap status: ${result.status}")
                    }
                }
            }

            try {
                @Suppress("BlockingMethodInNonBlockingContext")
                ch.shutdownOutput()
            } catch (e: ClosedChannelException) {
                // ignore
            } catch (e: IOException) {
                throw e
            }
        } finally {
            isOutputShutdown = true
            networkWrite.release()
        }
    }

    private suspend fun read(b: ByteBuffer): Int  = lock.withLock {
        read0(b)
    }

    private suspend fun read0(b: ByteBuffer): Int {
        if(isInputShutdown && !applicationRead.value.hasRemaining()) {
            return -1
        }

        if(!isHandshakeCompleted && isInputShutdown) {
            return -1
        }

        val app = this@KSSLSocketImpl.applicationRead
        val net = this@KSSLSocketImpl.networkRead

        val start = b.position()

        input@ while(b.hasRemaining()) {

            // Add remaining application data to the buffer
            if(app.value.hasRemaining()) {
                val count = min(app.value.remaining(), b.remaining())
                b.put(b.position(), app.value, app.value.position(), count)

                app.value.position(app.value.position() + count)
                b.position(b.position() + count)

                continue
            }

            // Check if we're handshaking (could be initiated at any time, any number of times)
            if(sslEngine.isHandshaking) {
                handleHandshake()
                continue@input
            }

            if(net.value.hasRemaining()) {
                app.value.clear()
                while(true) {

                    @Suppress("BlockingMethodInNonBlockingContext")
                    val result = sslEngine.unwrap(net.value, app.value)

                    when (result.status!!) {
                        SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                            net.compactOrIncreaseSize(sslEngine.session.packetBufferSize)
                        }
                        SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                            app.compactOrIncreaseSize(sslEngine.session.applicationBufferSize)
                        }
                        SSLEngineResult.Status.OK -> {
                            app.value.flip()
                            break
                        }
                        SSLEngineResult.Status.CLOSED -> {
                            shutdownInput()
                            break@input
                        }
                    }
                }
            } else {
                net.value.clear()
                val count = ch.readSuspend(net.value, getReadTimeout())
                if(count == -1) {
                    shutdownInput()
                    break@input
                }
                if (count == 0) {
                    // return if no data read
                    break@input
                }
                net.value.flip()
            }
        }

        return if(b.position() == start) {
            if(isInputShutdown) -1 else 0
        } else {
            b.position() - start
        }
    }

    private suspend fun write(b: ByteBuffer) = lock.withLock {
        write0(b)
    }

    private suspend fun write0(b: ByteBuffer) {
        if(!sslEngine.session.isValid) {
            startHandshake0()
        }

        while(b.hasRemaining()) {

            // Check if we're handshaking (could be initiated at any time, any number of times)
            if(sslEngine.isHandshaking) {
                handleHandshake()
                continue
            }

            @Suppress("BlockingMethodInNonBlockingContext")
            val result = sslEngine.wrap(b, networkWrite.value)

            when (result.status!!) {
                SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                    // increase network buffer size
                    throw SSLException("Buffer underflow while wrapping")
                }

                SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                    // increase network buffer size
                    networkWrite.compactOrIncreaseSize(
                        sslEngine.session.packetBufferSize,
                    )
                }

                SSLEngineResult.Status.OK -> {
                    networkWrite.value.flip()
                    while (networkWrite.value.hasRemaining()) {
                        val written = ch.writeSuspend(networkWrite.value, getWriteTimeout())
                        if (written == -1) {
                            throw SSLException("Connection closed during handshake")
                        }
                        if (written == 0) {
                            // TODO
                            throw SSLException("?? no data written during handshake. try again or error ??")
                        }
                    }
                    networkWrite.value.clear()
                    continue
                }

                SSLEngineResult.Status.CLOSED -> {
                    // closed
                    throw SocketException("connection closed")
                }
            }
        }
    }

    /**
     * Returns true if the SSLEngine is handshaking.
     */
    private val SSLEngine.isHandshaking: Boolean
        get() = this.handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED
                && this.handshakeStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
}