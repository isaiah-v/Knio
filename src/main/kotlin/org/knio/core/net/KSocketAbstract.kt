package org.knio.core.net

import org.knio.core.annotations.NotSuspended
import org.knio.core.utils.asCompletionHandler
import org.knio.core.utils.timeout
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.net.SocketTimeoutException
import java.nio.channels.AsynchronousSocketChannel
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

internal val ANY_LOCAL_ADDRESS = InetAddress.getByAddress(byteArrayOf(0, 0, 0, 0))
internal const val UNDEFINED_PORT = 0
internal const val UNDEFINED_LOCAL_PORT = -1

internal abstract class KSocketAbstract(
    protected val ch: AsynchronousSocketChannel
): KSocket {



    /** The read timeout in milliseconds. */
    private var rTimeout: Long? = null

    /** The write timeout in milliseconds. */
    private var wTimeout: Long? = null

    /** Remote Address */
    private var remoteAddress: InetSocketAddress? = null

    /** Local Address */
    private var localAddress: InetSocketAddress? = null

    init {
        @OptIn(NotSuspended::class)
        setProperties()
    }

    @NotSuspended
    private fun setProperties() {
        // not suspended so the properties can be set in the init block, if ready

        if(ch.isOpen) {
            if(this.remoteAddress==null) {
                this.remoteAddress = getRemoteInetSocketAddress()
            }

            if(this.localAddress==null) {
                this.localAddress = getLocalInetSocketAddress()
            }
        }
    }


    override suspend fun bind(local: SocketAddress?) {
        @Suppress("BlockingMethodInNonBlockingContext")
        ch.bind(local)

        @OptIn(NotSuspended::class)
        setProperties()
    }


    override suspend fun close() {
        if (!ch.isOpen) return

        if(isConnected()) {
            @Suppress("BlockingMethodInNonBlockingContext")
            ch.shutdownInput()
            @Suppress("BlockingMethodInNonBlockingContext")
            ch.shutdownOutput()
        }

        @Suppress("BlockingMethodInNonBlockingContext")
        ch.close()
    }


    override suspend fun connect(endpoint: SocketAddress, timeout: Long) {
        connect0(endpoint, timeout)

        @OptIn(NotSuspended::class)
        setProperties()
    }

    private suspend fun connect0(endpoint: SocketAddress, timeout: Long) = suspendCoroutine {
        try {
            val timoutJob = if (timeout > 0) {
                it.timeout(timeout) { SocketTimeoutException("Connection timed out") }
            } else if (timeout<0) {
                throw IllegalArgumentException("Timeout must be greater than or equal to 0")
            } else {
                null
            }
            // returns "this" upon completion
            ch.connect(endpoint, it, Unit.asCompletionHandler (timoutJob))
        } catch (e: Throwable) {
            it.resumeWithException(e)
        }
    }


    override suspend fun getInetAddress(): java.net.InetAddress {
        return this.remoteAddress?.address ?: ANY_LOCAL_ADDRESS
    }

    @NotSuspended
    private fun getRemoteInetSocketAddress(): InetSocketAddress? {
        val address = ch.remoteAddress ?: return null
        return if(address is java.net.InetSocketAddress) {
            address
        } else {
            null
        }
    }


    override suspend fun getKeepAlive(): Boolean {
        @Suppress("BlockingMethodInNonBlockingContext")
        return ch.getOption(java.net.StandardSocketOptions.SO_KEEPALIVE)
    }


    override suspend fun getLocalAddress(): InetAddress {
        if(!ch.isOpen) {
            return ANY_LOCAL_ADDRESS
        }
        return this.localAddress?.address ?: InetAddress.getLoopbackAddress()
    }

    @NotSuspended
    private fun getLocalInetSocketAddress(): InetSocketAddress? {
        val address = ch.localAddress ?: null
        return if(address is InetSocketAddress) {
            address
        } else {
            null
        }
    }


    override suspend fun getLocalPort(): Int {
        return this.localAddress?.port ?: UNDEFINED_LOCAL_PORT
    }


    override suspend fun getLocalSocketAddress(): SocketAddress? {
        if(!ch.isOpen) {
            assert(ANY_LOCAL_ADDRESS.isAnyLocalAddress)
            return InetSocketAddress(getLocalAddress(), getLocalPort())
        }
        return this.localAddress
    }


    override suspend fun getPort(): Int {
        return this.remoteAddress?.port ?: UNDEFINED_PORT
    }


    override suspend fun getReceiveBufferSize(): Int {
        @Suppress("BlockingMethodInNonBlockingContext")
        return ch.getOption(java.net.StandardSocketOptions.SO_RCVBUF)
    }


    override suspend fun getRemoteSocketAddress(): SocketAddress? = this.remoteAddress


    override suspend fun getReuseAddress(): Boolean {
        @Suppress("BlockingMethodInNonBlockingContext")
        return ch.getOption(java.net.StandardSocketOptions.SO_REUSEADDR)
    }

    override suspend fun getSendBufferSize(): Int{
        @Suppress("BlockingMethodInNonBlockingContext")
        return ch.getOption(java.net.StandardSocketOptions.SO_SNDBUF)
    }

    override suspend fun getReadTimeout(): Long =
        this.rTimeout ?: 0


    override suspend fun getWriteTimeout(): Long =
        this.wTimeout ?: 0


    override suspend fun getTcpNoDelay(): Boolean {
        @Suppress("BlockingMethodInNonBlockingContext")
        return ch.getOption(java.net.StandardSocketOptions.TCP_NODELAY)
    }

    override suspend fun isBound(): Boolean {
        return if(ch.isOpen) {
            ch.localAddress != null
        } else {
            localAddress != null
        }
    }


    override suspend fun isClosed(): Boolean =
        !ch.isOpen


    override suspend fun isConnected(): Boolean {
        return if(ch.isOpen) {
            ch.remoteAddress != null
        } else {
            remoteAddress != null
        }
    }


    override suspend fun setKeepAlive(keepAlive: Boolean) {
        @Suppress("BlockingMethodInNonBlockingContext")
        ch.setOption(java.net.StandardSocketOptions.SO_KEEPALIVE, keepAlive)
    }


    override suspend fun setReceiveBufferSize(size: Int) {
        @Suppress("BlockingMethodInNonBlockingContext")
        ch.setOption(java.net.StandardSocketOptions.SO_RCVBUF, size)
    }


    override suspend fun setReuseAddress(reuse: Boolean) {
        @Suppress("BlockingMethodInNonBlockingContext")
        ch.setOption(java.net.StandardSocketOptions.SO_REUSEADDR, reuse)
    }


    override suspend fun setSendBufferSize(size: Int) {
        @Suppress("BlockingMethodInNonBlockingContext")
        ch.setOption(java.net.StandardSocketOptions.SO_SNDBUF, size)
    }


    override suspend fun setReadTimeout(timeout: Long?) {
        if(timeout==null || timeout==0L) {
            this.rTimeout = null
        } else if(timeout<0) {
            throw IllegalArgumentException("Timeout must be greater than or equal to 0")
        } else {
            this.rTimeout = timeout
        }
    }


    override suspend fun setWriteTimeout(timeout: Long?) {
        if(timeout==null || timeout==0L) {
            this.wTimeout = null
        } else if(timeout<0) {
            throw IllegalArgumentException("Timeout must be greater than or equal to 0")
        } else {
            this.wTimeout = timeout
        }
    }


    override suspend fun setTcpNoDelay(on: Boolean) {
        @Suppress("BlockingMethodInNonBlockingContext")
        ch.setOption(java.net.StandardSocketOptions.TCP_NODELAY, on)
    }
}