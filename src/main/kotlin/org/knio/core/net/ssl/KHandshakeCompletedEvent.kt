package org.knio.core.net.ssl

import java.security.Principal
import java.security.cert.Certificate
import java.util.*
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSession

/**
 * Equivalent to [javax.net.ssl.HandshakeCompletedEvent].
 */
class KHandshakeCompletedEvent(
    sock: KSSLSocket,
    private val session: SSLSession
): EventObject(sock) {

    /**
     * Returns the session that triggered this event.
     *
     * @return the `SSLSession` for this handshake
     */
    fun getSession(): SSLSession {
        return session
    }


    /**
     * Returns the cipher suite in use by the session which was produced
     * by the handshake.  (This is a convenience method for
     * getting the ciphersuite from the SSLsession.)
     *
     * @return the name of the cipher suite negotiated during this session.
     */
    fun getCipherSuite(): String {
        return session.cipherSuite
    }


    /**
     * Returns the certificate(s) that were sent to the peer during
     * handshaking.
     * Note: This method is useful only when using certificate-based
     * cipher suites.
     *
     * When multiple certificates are available for use in a
     * handshake, the implementation chooses what it considers the
     * "best" certificate chain available, and transmits that to
     * the other side.  This method allows the caller to know
     * which certificate chain was actually used.
     *
     * @return an ordered array of certificates, with the local
     * certificate first followed by any
     * certificate authorities.  If no certificates were sent,
     * then null is returned.
     * @see .getLocalPrincipal
     */
    fun getLocalCertificates(): Array<Certificate> {
        return session.localCertificates
    }


    /**
     * Returns the identity of the peer which was established as part
     * of defining the session.
     * Note: This method can be used only when using certificate-based
     * cipher suites; using it with non-certificate-based cipher suites,
     * such as Kerberos, will throw an SSLPeerUnverifiedException.
     * <P>
     * Note: The returned value may not be a valid certificate chain
     * and should not be relied on for trust decisions.
     *
     * @return an ordered array of the peer certificates,
     * with the peer's own certificate first followed by
     * any certificate authorities.
     * @exception SSLPeerUnverifiedException if the peer is not verified.
     * @see .getPeerPrincipal
    </P> */
    @Throws(SSLPeerUnverifiedException::class)
    fun getPeerCertificates(): Array<Certificate> {
        return session.peerCertificates
    }


    /**
     * Returns the identity of the peer which was established as part of
     * defining the session.
     *
     * @return the peer's principal. Returns an X500Principal of the
     * end-entity certificate for X509-based cipher suites, and
     * KerberosPrincipal for Kerberos cipher suites.
     *
     * @throws SSLPeerUnverifiedException if the peer's identity has not
     * been verified
     *
     * @see .getPeerCertificates
     * @see .getLocalPrincipal
     * @since 1.5
     */
    @Throws(SSLPeerUnverifiedException::class)
    fun getPeerPrincipal(): Principal {
        var principal: Principal
        try {
            principal = session.peerPrincipal
        } catch (e: AbstractMethodError) {
            // if the provider does not support it, fallback to peer certs.
            // return the X500Principal of the end-entity cert.
            val certs = getPeerCertificates()
            principal = (certs[0] as java.security.cert.X509Certificate).subjectX500Principal
        }
        return principal
    }

    /**
     * Returns the principal that was sent to the peer during handshaking.
     *
     * @return the principal sent to the peer. Returns an X500Principal
     * of the end-entity certificate for X509-based cipher suites, and
     * KerberosPrincipal for Kerberos cipher suites. If no principal was
     * sent, then null is returned.
     *
     * @see .getLocalCertificates
     * @see .getPeerPrincipal
     * @since 1.5
     */
    fun getLocalPrincipal(): Principal? {
        var principal: Principal?
        try {
            principal = session.localPrincipal
        } catch (e: AbstractMethodError) {
            // if the provider does not support it, fallback to local certs.
            // return the X500Principal of the end-entity cert.
            val certs = getLocalCertificates()
            principal =
                (certs[0] as java.security.cert.X509Certificate).subjectX500Principal
        }
        return principal
    }

    /**
     * Returns the socket which is the source of this event.
     * (This is a convenience function, to let applications
     * write code without type casts.)
     *
     * @return the socket on which the connection was made.
     */
    fun getSocket(): KSSLSocket {
        return getSource() as KSSLSocket
    }
}