package org.knio.core.net.ssl

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.knio.core.net.KSocketAbstract
import java.nio.channels.AsynchronousSocketChannel
import java.util.function.BiFunction
import javax.net.ssl.*
import kotlin.coroutines.coroutineContext

internal abstract class KSSLSocketAbstract(
    channel: AsynchronousSocketChannel,
    protected val sslEngine: SSLEngine,
    useClientMode: Boolean,
): KSSLSocket, KSocketAbstract(channel) {

    protected val lock: Mutex = Mutex()

    private val handshakeListeners: MutableSet<KHandshakeCompletedListener> = mutableSetOf()

    init {
        sslEngine.useClientMode = useClientMode
    }

    override suspend fun getSupportedCipherSuites(): Array<String> = lock.withLock {
        return sslEngine.supportedCipherSuites
    }

    override suspend fun getEnabledCipherSuites(): Array<String> = lock.withLock {
        return sslEngine.enabledCipherSuites
    }

    override suspend fun setEnabledCipherSuites(suites: Array<String>) = lock.withLock {
        sslEngine.enabledCipherSuites = suites
    }

    override suspend fun getSupportedProtocols(): Array<String> = lock.withLock {
        return sslEngine.supportedProtocols
    }

    override suspend fun getEnabledProtocols(): Array<String> = lock.withLock {
        return sslEngine.enabledProtocols
    }

    override suspend fun setEnabledProtocols(protocols: Array<String>) = lock.withLock {
        sslEngine.enabledProtocols = protocols
    }

    override suspend fun getSession(): SSLSession = lock.withLock {
        startHandshake0() // lock is already acquired
        return sslEngine.session
    }

    override suspend fun getHandshakeSession(): SSLSession? = lock.withLock {
        return sslEngine.handshakeSession
    }

    override suspend fun addHandshakeCompletedListener(listener: KHandshakeCompletedListener): Unit = lock.withLock {
        handshakeListeners.add(listener)
    }

    override suspend fun removeHandshakeCompletedListener(listener: KHandshakeCompletedListener): Unit = lock.withLock {
        handshakeListeners.remove(listener)
    }

    override suspend fun setUseClientMode(mode: Boolean) = lock.withLock {
        sslEngine.useClientMode = mode
    }

    override suspend fun getUseClientMode(): Boolean = lock.withLock {
        return sslEngine.useClientMode
    }

    override suspend fun setNeedClientAuth(need: Boolean) = lock.withLock {
        sslEngine.needClientAuth = need
    }

    override suspend fun getNeedClientAuth(): Boolean = lock.withLock {
        return sslEngine.needClientAuth
    }

    override suspend fun setWantClientAuth(want: Boolean) = lock.withLock {
        sslEngine.wantClientAuth = want
    }

    override suspend fun getWantClientAuth(): Boolean = lock.withLock {
        return sslEngine.wantClientAuth
    }

    override suspend fun setEnableSessionCreation(flag: Boolean) = lock.withLock {
        sslEngine.enableSessionCreation = flag
    }

    override suspend fun getEnableSessionCreation(): Boolean = lock.withLock {
        return sslEngine.enableSessionCreation
    }

    override suspend fun getApplicationProtocol(): String? = lock.withLock {
        return sslEngine.applicationProtocol
    }

    override suspend fun getHandshakeApplicationProtocol(): String = lock.withLock {
        return sslEngine.handshakeApplicationProtocol
    }

    override suspend fun setHandshakeApplicationProtocolSelector(
        selector: BiFunction<KSSLSocket, List<String>, String?>?
    ) = lock.withLock {
        if(selector == null) {
            sslEngine.handshakeApplicationProtocolSelector = null
        } else {
            sslEngine.handshakeApplicationProtocolSelector = HandshakeApplicationProtocolSelector(selector)
        }
    }

    override suspend fun getHandshakeApplicationProtocolSelector(): BiFunction<KSSLSocket, List<String>, String?>? = lock.withLock {
        return sslEngine.handshakeApplicationProtocolSelector?.let {
            if(it is HandshakeApplicationProtocolSelector) {
                it.selector
            } else {
                null
            }
        }
    }

    override suspend fun getSSLParameters(): SSLParameters = lock.withLock {
        return sslEngine.sslParameters
    }

    override suspend fun setSSLParameters(params: SSLParameters) = lock.withLock {
        sslEngine.sslParameters = params
    }

    /**
     * Starts the handshake process without acquiring the lock.
     */
    protected abstract suspend fun startHandshake0();

    /**
     * Must be called after the handshake is complete.
     */
    protected suspend fun triggerHandshakeCompletion(session: SSLSession) {
        // get the listeners and close it so no more can be added
        if(handshakeListeners.isEmpty()) {
            return
        }

        // run the listeners in a separate coroutine
        CoroutineScope(coroutineContext).launch {
            handshakeListeners.forEach {
                runHandshakeCompletedListener(it)
            }
        }
    }

    private suspend fun runHandshakeCompletedListener(listener: KHandshakeCompletedListener) {
        try {
            listener.handshakeCompleted(
                KHandshakeCompletedEvent(
                    this,
                    sslEngine.session
                )
            )
        } catch (th: Throwable) {
            // nothing left to do. print the stack trace and move on
            th.printStackTrace()
        }
    }

    /**
     * A wrapper for the application protocol selector function to work with the SSLEngine.
     *
     * @see SSLEngine.getHandshakeApplicationProtocolSelector
     * @see SSLEngine.setHandshakeApplicationProtocolSelector
     */
    private class HandshakeApplicationProtocolSelector (
        val selector: BiFunction<KSSLSocket, List<String>, String?>
    ): BiFunction<SSLEngine, List<String>, String?> {
        override fun apply(t: SSLEngine, u: List<String>): String? {
            return selector.apply(t as KSSLSocket, u)
        }
    }
}