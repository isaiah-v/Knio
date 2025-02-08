package org.knio.core.net.ssl

import java.util.*
import javax.net.ssl.HandshakeCompletedEvent

/**
 * This interface is implemented by any class which wants to receive
 * notifications about the completion of an SSL protocol handshake
 * on a given SSL connection.
 *
 * When an SSL handshake completes, new security parameters will
 * have been established. Those parameters always include the security
 * keys used to protect messages. They may also include parameters
 * associated with a new _session_ such as authenticated
 * peer identity and a new SSL cipher suite.
 */
fun interface KHandshakeCompletedListener: EventListener {

    /**
     * This method is invoked on registered objects
     * when a SSL handshake is completed.
     *
     * @param event the event identifying when the SSL Handshake
     *          completed on a given SSL connection
     */
    suspend fun handshakeCompleted(event: KHandshakeCompletedEvent)
}
