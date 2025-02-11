package org.knio.core.net.ssl

import org.knio.core.net.KSocket
import java.io.IOException
import java.net.SocketException
import java.util.function.BiFunction
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSession

/**
 * An interface for secure socket connections.
 *
 * A non-blocking equivalent of [javax.net.ssl.SSLSocket]
 */
interface KSSLSocket: KSocket {

    /**
     * Registers an event listener to receive notifications that an SSL handshake has completed on this connection.
     *
     * @param listener The listener to register.
     * @throws IllegalArgumentException If the listener is null.
     *
     * @implNote TODO tests
     *  - test listener is null
     */
    @Throws(IllegalArgumentException::class)
    suspend fun addHandshakeCompletedListener(listener: KHandshakeCompletedListener)

    /**
     * Returns the most recent application protocol value negotiated for this connection.
     *
     * If supported by the underlying SSL/TLS/DTLS implementation, application name negotiation mechanisms such as
     * [RFC 7301](https://www.ietf.org/rfc/rfc7301.txt) , the Application-Layer Protocol Negotiation (ALPN), can
     * negotiate application-level values between peers.
     *
     * @return The application protocol, or null if no protocol was selected.
     */
    suspend fun getApplicationProtocol(): String?

    /**
     * Returns the names of the SSL cipher suites which are currently enabled for use on this connection. When an
     * SSLSocket is first created, all enabled cipher suites support a minimum quality of service. Thus, in some
     * environments this value might be empty.
     *
     * Note that even if a suite is enabled, it may never be used. This can occur if the peer does not support it, or
     * its use is restricted, or the requisite certificates (and private keys) for the suite are not available, or an
     * anonymous suite is enabled but authentication is required.
     *
     * The returned array includes cipher suites from the list of standard cipher suite names in the JSSE Cipher Suite
     * Names section of the Java Security Standard Algorithm Names Specification, and may also include other cipher
     * suites that the provider supports.
     *
     * @return an array of cipher suite names
     */
    suspend fun getEnabledCipherSuites(): Array<String>

    /**
     * Returns the names of the protocol versions which are currently enabled for use on this connection.
     *
     * Note that even if a protocol is enabled, it may never be used. This can occur if the peer does not support the
     * protocol, or its use is restricted, or there are no enabled cipher suites supported by the protocol.
     *
     * @return an array of protocol names
     */
    suspend fun getEnabledProtocols(): Array<String>

    /**
     * Returns `true` if new SSL sessions may be established by this socket.
     *
     * @return `true` indicates that sessions may be created; this is the default. `false` indicates that an existing
     * session must be resumed
     */
    suspend fun getEnableSessionCreation(): Boolean

    /**
     * Returns the application protocol value negotiated on an SSL/TLS handshake currently in progress.
     *
     * Like [getHandshakeSession], a connection may be in the middle of a handshake. The application protocol may or
     * may not yet be available.
     *
     * @return `null` if it has not yet been determined if application protocols might be used for this handshake, an
     * empty `String` if application protocols values will not be used, or a non-empty application protocol String if a
     * value was successfully negotiated.
     *
     * @implNote TODO tests
     *  - returns null if the handshake has not yet started
     *  - returns an empty string if the handshake has started but no application protocol has been selected
     */
    suspend fun getHandshakeApplicationProtocol(): String?

    /**
     * Retrieves the callback function that selects an application protocol value during as SSL/TLS/DTLS handshake. See
     * [setHandshakeApplicationProtocolSelector] for the function's type parameters.
     *
     * @returns the callback function, or null if none has been set.
     */
    suspend fun getHandshakeApplicationProtocolSelector(): BiFunction<KSSLSocket, List<String>, String?>?

    /**
     * Returns the SSLSession being constructed during an SSL/TLS handshake.
     *
     * TLS protocols may negotiate parameters that are needed when using an instance of this class, but before the
     * `SSLSession` has been completely initialized and made available via `getSession`. For example, the list of valid
     * signature algorithms may restrict the type of certificates that can be used during `TrustManager` decisions, or
     * the maximum TLS fragment packet sizes can be resized to better support the network environment.
     *
     * This method provides early access to the `SSLSession` being constructed. Depending on how far the handshake has
     * progressed, some data may not yet be available for use. For example, if a remote server will be sending a
     * Certificate chain, but that chain has yet not been processed, the getPeerCertificates method of SSLSession will
     * throw a SSLPeerUnverifiedException. Once that chain has been processed, getPeerCertificates will return the
     * proper value.
     *
     * Unlike getSession(), this method does not initiate the initial handshake and does not suspend until handshaking
     * is complete.
     *
     * @return `null` if this instance is not currently handshaking, or if the current handshake has not progressed far
     * enough to create a basic `SSLSession`. Otherwise, this method returns the SSLSession currently being negotiated.
     *
     * @implNote TODO tests lots of test
     */
    suspend fun getHandshakeSession(): SSLSession?

    /**
     * Returns true if the socket will _require_ client authentication. This option is only useful to sockets in the
     * server mode.
     *
     * @return `true` if client authentication is required, or `false` if no client authentication is desired.
     */
    suspend fun getNeedClientAuth(): Boolean

    /**
     * Returns the SSL Session in use by this connection. These can be long-lived, and frequently correspond to an
     * entire login session for some user. The session specifies a particular cipher suite which is being actively used
     * by all connections in that session, as well as the identities of the session's client and server.
     *
     * This method will initiate the initial handshake if necessary and then block until the handshake has been
     * established.
     *
     * If an error occurs during the initial handshake, this method returns an invalid session object which reports an
     * invalid cipher suite of "SSL_NULL_WITH_NULL_NULL".
     *
     * @return the SSLSession
     */
    suspend fun getSession(): SSLSession

    /**
     * Returns the names of the cipher suites which could be enabled for use on this connection. Normally, only a subset
     * of these will actually be enabled by default, since this list may include cipher suites which do not meet quality
     * of service requirements for those defaults. Such cipher suites might be useful in specialized applications.
     *
     * The returned array includes cipher suites from the list of standard cipher suite names in the JSSE Cipher Suite
     * Names section of the Java Security Standard Algorithm Names Specification, and may also include other cipher
     * suites that the provider supports.
     *
     * @return an array of cipher suite names
     */
    suspend fun getSupportedCipherSuites(): Array<String>

    /**
     * Returns the names of the protocols which could be enabled for use on an SSL connection.
     *
     * @return an array of protocol names
     */
    suspend fun getSupportedProtocols(): Array<String>

    /**
     * Returns `true` if the socket is set to use client mode when handshaking.
     *
     * @return `true` if the socket should do handshaking in "client" mode
     */
    suspend fun getUseClientMode(): Boolean

    /**
     * Returns `true` if the socket will _request_ client authentication. This option is only useful for sockets in the
     * server mode.
     */
    suspend fun getWantClientAuth(): Boolean

    /**
     * Removes a previously registered handshake completion listener.
     *
     * @param listener the HandShake Completed event listener
     * @throws IllegalArgumentException if the listener is not registered, or the argument is `null`.
     *
     * @implNote TODO tests
     * - test listener is null
     * - test listener is not registered
     */
    @Throws(IllegalArgumentException::class)
    suspend fun removeHandshakeCompletedListener(listener: KHandshakeCompletedListener)


    /**
     * Sets the cipher suites enabled for use on this connection.
     *
     * Each cipher suite in the suites parameter must have been listed by [getSupportedCipherSuites], or the method will
     * fail. Following a successful call to this method, only suites listed in the suites parameter are enabled for use.
     *
     * Note that the standard list of cipher suite names may be found in the JSSE Cipher Suite Names section of the Java
     * Security Standard Algorithm Names Specification. Providers may support cipher suite names not found in this list
     * or might not use the recommended name for a certain cipher suite.
     *
     * See [getEnabledCipherSuites] for more information on why a specific ciphersuite may never be used on a
     * connection.
     *
     * @param suites Names of all the cipher suites to enable.
     *
     * @throws IllegalArgumentException when one or more of the ciphers named by the parameter is not supported, or when
     * the parameter is null.
     *
     * @implNote TODO tests
     * - test null suites
     * - test unsupported suites
     */
    @Throws(IllegalArgumentException::class)
    suspend fun setEnabledCipherSuites(suites: Array<String>)

    /**
     * Sets the protocol versions enabled for use on this connection.
     *
     * The protocols must have been listed by [getSupportedProtocols] as being supported. Following a successful call to
     * this method, only protocols listed in the protocols parameter are enabled for use.
     *
     * @param protocols Names of all the protocols to enable.
     *
     * @throws IllegalArgumentException  when one or more of the protocols named by the parameter is not supported or
     * when the protocols parameter is null.
     *
     * @implNote TODO tests
     *  - test null protocols
     *  - test unsupported protocols
     */
    @Throws(IllegalArgumentException::class)
    suspend fun setEnabledProtocols(protocols: Array<String>)

    /**
     * Controls whether new SSL sessions may be established by this socket. If session creations are not allowed, and
     * there are no existing sessions to resume, there will be no successful handshaking.
     *
     * @param flag `true` indicates that sessions may be created; this is the default. `false` indicates that an
     * existing session must be resumed.
     */
    suspend fun setEnableSessionCreation(flag: Boolean)

    /**
     * Registers a callback function that selects an application protocol value for an SSL/TLS/DTLS handshake. The
     * supports the following type parameters:
     *
     *  - `SSLSocket`
     *        The function's first argument allows the current SSLSocket to be inspected, including the handshake
     *        session and configuration settings.
     *
     *  - `List<String>`
     *        The function's second argument lists the application protocol names advertised by the TLS peer.
     *
     *  - `String`
     *        The function's result is an application protocol name, or null to indicate that none of the advertised
     *        names are acceptable. If the return value is an empty String then application protocol indications will
     *        not be used. If the return value is null (no value chosen) or is a value that was not advertised by the
     *        peer, the underlying protocol will determine what action to take. (For example, ALPN will send a
     *        "no_application_protocol" alert and terminate the connection.)
     *
     * For example, the following call registers a callback function that examines the TLS handshake parameters and
     * selects an application protocol name:
     * ```java
     *      serverSocket.setHandshakeApplicationProtocolSelector(
     *          (serverSocket, clientProtocols) -> {
     *              SSLSession session = serverSocket.getHandshakeSession();
     *              return chooseApplicationProtocol(
     *                  serverSocket,
     *                  clientProtocols,
     *                  session.getProtocol(),
     *                  session.getCipherSuite());
     *          });
     *```
     * ##### API Note:
     * This method should be called by TLS server applications before the TLS handshake begins. Also, this [KSSLSocket]
     * should be configured with parameters that are compatible with the application protocol selected by the callback
     * function. For example, enabling a poor choice of cipher suites could result in no suitable application protocol.
     *
     * @param selector - the callback function, or null to de-register.
     *
     */
    suspend fun setHandshakeApplicationProtocolSelector(selector: BiFunction<KSSLSocket, List<String>, String?>?)

    /**
     * Configures the socket to _require_ client authentication. This option is only useful for sockets in the server
     * mode.
     *
     * A socket's client authentication setting is one of the following:
     *  - client authentication required
     *  - client authentication requested
     *  - no client authentication desired
     *
     * Unlike [setWantClientAuth], if this option is set and the client chooses not to provide authentication
     * information about itself, the negotiations will stop and the connection will be dropped.
     *
     * Calling this method overrides any previous setting made by this method or [setWantClientAuth].
     *
     * @param need - set to `true` if client authentication is required, or `false` if no client authentication is
     * desired.
     */
    suspend fun setNeedClientAuth(need: Boolean)

    /**
     * Configures the socket to use client (or server) mode when handshaking.
     *
     * This method must be called before any handshaking occurs. Once handshaking has begun, the mode can not be reset
     * for the life of this socket.
     *
     * Servers normally authenticate themselves, and clients are not required to do so.
     *
     * @param mode - `true` if the socket should start its handshaking in "client" mode
     *
     * @throws IllegalArgumentException if a mode change is attempted after the initial handshake has begun.
     */
    @Throws(IllegalArgumentException::class)
    suspend fun setUseClientMode(mode: Boolean)

    /**
     * Configures the socket to _request_ client authentication. This option is only useful for sockets in the server
     * mode.
     *
     * A socket's client authentication setting is one of the following:
     *  - client authentication required
     *  - client authentication requested
     *  - no client authentication desired
     *
     * Unlike [setNeedClientAuth], if this option is set and the client chooses not to provide authentication
     * information about itself, the negotiations will continue.
     *
     * Calling this method overrides any previous setting made by this method or [setNeedClientAuth].
     */
    suspend fun setWantClientAuth(want: Boolean)

    /**
     * Starts an SSL handshake on this connection. Common reasons include a need to use new encryption keys, to change
     * cipher suites, or to initiate a new session. To force complete re-authentication, the current session could be
     * invalidated before starting this handshake.
     *
     * If data has already been sent on the connection, it continues to flow during this handshake. When the handshake
     * completes, this will be signaled with an event. This method is synchronous for the initial handshake on a
     * connection and returns when the negotiated handshake is complete. Some protocols may not support multiple
     * handshakes on an existing socket and may throw an [IOException].
     *
     * @throws IOException  on a network level error
     */
    @Throws(IOException::class)
    suspend fun startHandshake()

    /**
     * Returns the SSLParameters in effect for this SSLSocket. The cipher-suites and protocols of the returned
     * SSLParameters are always non-null.
     */
    suspend fun getSSLParameters(): SSLParameters

    /**
     * Applies SSLParameters to this socket.
     *
     * This means:
     *  - If [SSLParameters.getCipherSuites] is non-null, setEnabledCipherSuites() is called with that value.
     *  - If [SSLParameters.getProtocols] is non-null, setEnabledProtocols() is called with that value.
     *  - If [SSLParameters.getNeedClientAuth] or params.getWantClientAuth() return true, setNeedClientAuth(true) and setWantClientAuth(true) are called, respectively; otherwise setWantClientAuth(false) is called.
     *  - If [SSLParameters.getServerNames] is non-null, the socket will configure its server names with that value.
     *  - If [SSLParameters.getSNIMatchers] is non-null, the socket will configure its SNI matchers with that value.
     *
     *  @throws IllegalArgumentException if the setEnabledCipherSuites() or the setEnabledProtocols() call fails
     */
    @Throws(IllegalArgumentException::class)
    suspend fun setSSLParameters(params: SSLParameters)
}