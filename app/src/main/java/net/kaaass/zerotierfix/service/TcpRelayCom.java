package net.kaaass.zerotierfix.service;

import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import com.zerotier.sdk.Node;
import com.zerotier.sdk.PacketSender;
import com.zerotier.sdk.ResultCode;

import net.kaaass.zerotierfix.util.Constants;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Physical transport for the ZeroTier SDK that sends wire packets through a
 * ZeroTier TCP relay ("tcp-proxy"), optionally reached through a SOCKS5 or
 * HTTP CONNECT proxy.
 *
 * <p>The Android client talks to the SDK through {@link PacketSender} and
 * {@link Node#processWirePacket}, so the TCP relay protocol that lives in the
 * desktop service (OneService.cpp) has to be reimplemented here. The framing is
 * the same fake-TLS framing used by the official client:</p>
 *
 * <pre>
 * client -> relay: 17 03 03 &lt;len&gt; 04 &lt;ip4&gt; &lt;port&gt; &lt;data&gt;
 * relay -> client: 17 03 03 &lt;len&gt; 04 &lt;ip4&gt; &lt;port&gt; &lt;data&gt;
 * </pre>
 *
 * <p>On connect the client sends a 9 byte hello (a fake TLS record containing
 * the ZeroTier version) which the relay ignores.</p>
 */
public class TcpRelayCom implements PacketSender, Runnable {

    private static final String TAG = "TcpRelayCom";
    private static final int CONNECT_TIMEOUT_MS = 15000;
    private static final int RECONNECT_DELAY_MS = 3000;
    private static final int QUEUE_LIMIT = 512;
    private static final int MAX_FRAME = 65535;

    /** Fake TLS 1.2 hello with a ZeroTier version payload, ignored by the relay. */
    private static final byte[] HELLO = new byte[] {
            0x17, 0x03, 0x03, 0x00, 0x04, 0x01, 0x0e, 0x00, 0x00
    };

    private final ZeroTierOneService ztService;
    private final String relayHost;
    private final int relayPort;
    private final ProxyConfig proxy;
    private final LinkedBlockingQueue<byte[]> sendQueue = new LinkedBlockingQueue<>(QUEUE_LIMIT);

    private volatile Node node;
    private volatile boolean running;
    private volatile Socket socket;
    private volatile OutputStream output;

    private TcpRelayCom(ZeroTierOneService service, String relayHost, int relayPort, ProxyConfig proxy) {
        this.ztService = service;
        this.relayHost = relayHost;
        this.relayPort = relayPort;
        this.proxy = proxy;
        this.running = true;
    }

    /**
     * Build a transport from the app preferences, or return {@code null} when
     * the configured relay address is invalid (the caller should fall back to
     * plain UDP in that case).
     */
    public static TcpRelayCom fromPreferences(ZeroTierOneService service, SharedPreferences preferences) {
        String relay = preferences.getString(Constants.PREF_TCP_RELAY_ADDRESS, Constants.DEFAULT_TCP_RELAY_ADDRESS);
        String[] relayParts = splitHostPort(relay);
        if (relayParts == null) {
            Log.e(TAG, "Invalid TCP relay address: " + relay);
            return null;
        }
        int relayPort = parsePort(relayParts[1]);
        if (relayPort <= 0) {
            Log.e(TAG, "Invalid TCP relay port: " + relay);
            return null;
        }

        ProxyConfig proxy = null;
        if (preferences.getBoolean(Constants.PREF_PROXY_ENABLED, false)) {
            String address = preferences.getString(Constants.PREF_PROXY_ADDRESS, "");
            String[] proxyParts = splitHostPort(address);
            int proxyPort = (proxyParts == null) ? -1 : parsePort(proxyParts[1]);
            if (proxyParts == null || proxyPort <= 0) {
                Log.e(TAG, "Invalid proxy address: " + address);
                return null;
            }
            String type = preferences.getString(Constants.PREF_PROXY_TYPE, Constants.PROXY_TYPE_SOCKS5);
            proxy = new ProxyConfig(
                    proxyParts[0],
                    proxyPort,
                    Constants.PROXY_TYPE_HTTP.equalsIgnoreCase(type),
                    preferences.getString(Constants.PREF_PROXY_USERNAME, ""),
                    preferences.getString(Constants.PREF_PROXY_PASSWORD, ""));
        }

        return new TcpRelayCom(service, relayParts[0], relayPort, proxy);
    }

    public void setNode(Node node) {
        this.node = node;
    }

    public void stop() {
        this.running = false;
        closeQuietly(this.socket);
        this.sendQueue.clear();
    }

    @Override
    public int onSendPacketRequested(long localSocket, InetSocketAddress remoteAddr, byte[] packetData, int ttl) {
        if (!this.running || remoteAddr == null || packetData == null) {
            return -1;
        }
        byte[] frame = buildFrame(remoteAddr, packetData);
        if (frame == null) {
            return -1;
        }
        return this.sendQueue.offer(frame) ? 0 : -1;
    }

    @Override
    public void run() {
        Log.d(TAG, "TCP relay thread started");
        while (this.running) {
            Socket current = null;
            try {
                Conn conn = connect();
                current = conn.socket;
                this.socket = current;
                this.output = conn.out;

                // Fake TLS hello, sent once per connection before any frame.
                conn.out.write(HELLO);
                conn.out.flush();

                Thread reader = new Thread(() -> readLoop(conn.socket, conn.in), "TCP Relay Reader");
                reader.setDaemon(true);
                reader.start();

                while (this.running) {
                    if (current.isClosed()) {
                        throw new IOException("relay connection closed");
                    }
                    byte[] frame = this.sendQueue.poll(1, TimeUnit.SECONDS);
                    if (frame == null) {
                        continue;
                    }
                    conn.out.write(frame);
                    byte[] next;
                    while ((next = this.sendQueue.poll()) != null) {
                        conn.out.write(next);
                    }
                    conn.out.flush();
                }
            } catch (InterruptedException e) {
                break;
            } catch (Exception e) {
                if (this.running) {
                    Log.e(TAG, "TCP relay connection error: " + e, e);
                }
            } finally {
                this.output = null;
                this.socket = null;
                closeQuietly(current);
            }
            if (this.running) {
                try {
                    Thread.sleep(RECONNECT_DELAY_MS);
                } catch (InterruptedException e) {
                    break;
                }
            }
        }
        Log.d(TAG, "TCP relay thread ended");
    }

    private Conn connect() throws IOException {
        String host = (this.proxy != null) ? this.proxy.host : this.relayHost;
        int port = (this.proxy != null) ? this.proxy.port : this.relayPort;

        Socket s = new Socket();
        // Publish the socket early so stop() can interrupt a slow connect().
        this.socket = s;
        try {
            // Bind first so that the socket has a file descriptor: on Android
            // VpnService.protect(Socket) needs it, and the socket must be
            // protected before connect() so the SYN does not loop back into
            // the ZeroTier VPN interface.
            s.bind(new InetSocketAddress(0));
            if (!this.ztService.protect(s)) {
                Log.w(TAG, "VpnService.protect() returned false for relay socket");
            }
            s.setTcpNoDelay(true);
            s.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            s.setSoTimeout(CONNECT_TIMEOUT_MS);

            InputStream in = new BufferedInputStream(s.getInputStream());
            OutputStream out = s.getOutputStream();

            if (this.proxy != null) {
                if (this.proxy.http) {
                    httpConnect(in, out);
                } else {
                    socks5Connect(in, out);
                }
            }

            s.setSoTimeout(0);
            return new Conn(s, in, out);
        } catch (IOException | RuntimeException e) {
            closeQuietly(s);
            throw e;
        }
    }

    private void socks5Connect(InputStream in, OutputStream out) throws IOException {
        boolean withAuth = this.proxy.username != null && !this.proxy.username.isEmpty();

        out.write(withAuth ? new byte[] {5, 2, 0, 2} : new byte[] {5, 1, 0});
        out.flush();

        byte[] greeting = readFully(in, 2);
        if ((greeting[0] & 0xff) != 5) {
            throw new IOException("not a SOCKS5 proxy");
        }
        int method = greeting[1] & 0xff;
        if (method == 0x02) {
            if (!withAuth) {
                throw new IOException("SOCKS5 proxy requires authentication");
            }
            byte[] user = this.proxy.username.getBytes(StandardCharsets.UTF_8);
            byte[] pass = this.proxy.password.getBytes(StandardCharsets.UTF_8);
            if (user.length > 255 || pass.length > 255) {
                throw new IOException("SOCKS5 credentials too long");
            }
            byte[] auth = new byte[3 + user.length + pass.length];
            auth[0] = 0x01;
            auth[1] = (byte) user.length;
            System.arraycopy(user, 0, auth, 2, user.length);
            auth[2 + user.length] = (byte) pass.length;
            System.arraycopy(pass, 0, auth, 3 + user.length, pass.length);
            out.write(auth);
            out.flush();

            byte[] authReply = readFully(in, 2);
            if ((authReply[1] & 0xff) != 0) {
                throw new IOException("SOCKS5 authentication failed");
            }
        } else if (method != 0x00) {
            throw new IOException("SOCKS5 proxy rejected auth methods: 0x" + Integer.toHexString(method));
        }

        ByteArrayOutputStream request = new ByteArrayOutputStream();
        request.write(0x05);
        request.write(0x01);
        request.write(0x00);
        if (isIpLiteral(this.relayHost)) {
            InetAddress address = InetAddress.getByName(this.relayHost);
            byte[] raw = address.getAddress();
            if (raw.length == 4) {
                request.write(0x01);
            } else {
                request.write(0x04);
            }
            request.write(raw);
        } else {
            byte[] host = this.relayHost.getBytes(StandardCharsets.US_ASCII);
            if (host.length > 255) {
                throw new IOException("relay host name too long");
            }
            request.write(0x03);
            request.write(host.length);
            request.write(host);
        }
        request.write((this.relayPort >> 8) & 0xff);
        request.write(this.relayPort & 0xff);
        out.write(request.toByteArray());
        out.flush();

        byte[] reply = readFully(in, 4);
        if ((reply[1] & 0xff) != 0) {
            throw new IOException("SOCKS5 CONNECT failed: " + (reply[1] & 0xff));
        }
        switch (reply[3] & 0xff) {
            case 0x01:
                readFully(in, 4 + 2);
                break;
            case 0x04:
                readFully(in, 16 + 2);
                break;
            case 0x03: {
                int length = readFully(in, 1)[0] & 0xff;
                readFully(in, length + 2);
                break;
            }
            default:
                throw new IOException("bad SOCKS5 reply address type");
        }
    }

    private void httpConnect(InputStream in, OutputStream out) throws IOException {
        String authority = this.relayHost + ":" + this.relayPort;
        StringBuilder request = new StringBuilder();
        request.append("CONNECT ").append(authority).append(" HTTP/1.1\r\n");
        request.append("Host: ").append(authority).append("\r\n");
        if (this.proxy.username != null && !this.proxy.username.isEmpty()) {
            String credentials = this.proxy.username + ":" + this.proxy.password;
            String encoded = Base64.encodeToString(credentials.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
            request.append("Proxy-Authorization: Basic ").append(encoded).append("\r\n");
        }
        request.append("Proxy-Connection: keep-alive\r\n\r\n");
        out.write(request.toString().getBytes(StandardCharsets.US_ASCII));
        out.flush();

        String status = readLine(in);
        if (status == null || !status.matches("HTTP/\\d(\\.\\d)?\\s+2\\d\\d.*")) {
            throw new IOException("HTTP CONNECT failed: " + status);
        }
        String line;
        while ((line = readLine(in)) != null && !line.isEmpty()) {
            // Skip response headers.
        }
    }

    private void readLoop(Socket owner, InputStream in) {
        long[] deadline = new long[1];
        try {
            while (this.running && !owner.isClosed()) {
                byte[] header = readFully(in, 5);
                int length = ((header[3] & 0xff) << 8) | (header[4] & 0xff);
                if (length == 4) {
                    // Hello/ack, not a real packet.
                    readFully(in, 4);
                    continue;
                }
                if (length < 1 || length > MAX_FRAME) {
                    throw new IOException("invalid relay frame length: " + length);
                }
                byte[] payload = readFully(in, length);
                dispatch(payload, deadline);
            }
        } catch (IOException e) {
            if (this.running) {
                Log.d(TAG, "TCP relay reader stopped: " + e.getMessage());
            }
        } finally {
            // Wake up the writer loop, which is blocked in queue.poll().
            closeQuietly(owner);
        }
    }

    private void dispatch(byte[] payload, long[] deadline) {
        Node currentNode = this.node;
        if (currentNode == null || payload.length < 1) {
            return;
        }
        int type = payload[0] & 0xff;
        InetAddress address;
        int port;
        int offset;
        try {
            if (type == 4) {
                if (payload.length < 7) {
                    return;
                }
                byte[] raw = new byte[4];
                System.arraycopy(payload, 1, raw, 0, 4);
                address = InetAddress.getByAddress(raw);
                port = ((payload[5] & 0xff) << 8) | (payload[6] & 0xff);
                offset = 7;
            } else if (type == 6) {
                if (payload.length < 19) {
                    return;
                }
                byte[] raw = new byte[16];
                System.arraycopy(payload, 1, raw, 0, 16);
                address = InetAddress.getByAddress(raw);
                port = ((payload[17] & 0xff) << 8) | (payload[18] & 0xff);
                offset = 19;
            } else {
                return;
            }
        } catch (Exception e) {
            return;
        }

        byte[] data = new byte[payload.length - offset];
        System.arraycopy(payload, offset, data, 0, data.length);
        InetSocketAddress from = new InetSocketAddress(address, port);
        deadline[0] = 0;
        ResultCode result = currentNode.processWirePacket(
                System.currentTimeMillis(), -1, from, data, deadline);
        if (result.isFatal()) {
            Log.e(TAG, "Fatal error from processWirePacket: " + result);
            this.ztService.shutdown();
            stop();
            return;
        }
        this.ztService.setNextBackgroundTaskDeadline(deadline[0]);
    }

    private static byte[] buildFrame(InetSocketAddress destination, byte[] data) {
        InetAddress address = destination.getAddress();
        if (!(address instanceof Inet4Address)) {
            // The TCP relay protocol used by ZeroTier is IPv4 only.
            return null;
        }
        int length = data.length + 7;
        if (length > MAX_FRAME) {
            return null;
        }
        byte[] frame = new byte[length + 5];
        frame[0] = 0x17;
        frame[1] = 0x03;
        frame[2] = 0x03;
        frame[3] = (byte) ((length >> 8) & 0xff);
        frame[4] = (byte) (length & 0xff);
        frame[5] = 0x04;
        byte[] raw = address.getAddress();
        System.arraycopy(raw, 0, frame, 6, 4);
        int port = destination.getPort();
        frame[10] = (byte) ((port >> 8) & 0xff);
        frame[11] = (byte) (port & 0xff);
        System.arraycopy(data, 0, frame, 12, data.length);
        return frame;
    }

    private static byte[] readFully(InputStream in, int length) throws IOException {
        byte[] buffer = new byte[length];
        int offset = 0;
        while (offset < length) {
            int read = in.read(buffer, offset, length - offset);
            if (read < 0) {
                throw new EOFException();
            }
            offset += read;
        }
        return buffer;
    }

    private static String readLine(InputStream in) throws IOException {
        StringBuilder line = new StringBuilder();
        int c;
        while ((c = in.read()) >= 0) {
            if (c == '\n') {
                return line.toString();
            }
            if (c != '\r') {
                line.append((char) c);
            }
            if (line.length() > 4096) {
                throw new IOException("proxy header line too long");
            }
        }
        return line.length() == 0 ? null : line.toString();
    }

    private static boolean isIpLiteral(String host) {
        if (host == null || host.isEmpty()) {
            return false;
        }
        if (host.indexOf(':') >= 0) {
            return true;
        }
        return host.matches("\\d{1,3}(\\.\\d{1,3}){3}");
    }

    /**
     * Split "host:port", "[v6]:port" or "v4:port". Returns {@code null} when no
     * port is present or the host is empty.
     */
    private static String[] splitHostPort(String value) {
        if (value == null) {
            return null;
        }
        value = value.trim();
        if (value.isEmpty()) {
            return null;
        }
        if (value.charAt(0) == '[') {
            int end = value.indexOf(']');
            if (end <= 1 || end + 2 > value.length() || value.charAt(end + 1) != ':') {
                return null;
            }
            return new String[] {value.substring(1, end), value.substring(end + 2)};
        }
        int colon = value.lastIndexOf(':');
        if (colon <= 0 || colon == value.length() - 1) {
            return null;
        }
        // More than one colon without brackets is a bare IPv6 address, which we
        // do not accept because the port is ambiguous.
        if (value.indexOf(':') != colon) {
            return null;
        }
        return new String[] {value.substring(0, colon), value.substring(colon + 1)};
    }

    private static int parsePort(String value) {
        try {
            int port = Integer.parseInt(value.trim());
            return (port > 0 && port <= 65535) ? port : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static void closeQuietly(Socket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }

    private static final class Conn {
        final Socket socket;
        final InputStream in;
        final OutputStream out;

        Conn(Socket socket, InputStream in, OutputStream out) {
            this.socket = socket;
            this.in = in;
            this.out = out;
        }
    }

    private static final class ProxyConfig {
        final String host;
        final int port;
        final boolean http;
        final String username;
        final String password;

        ProxyConfig(String host, int port, boolean http, String username, String password) {
            this.host = host;
            this.port = port;
            this.http = http;
            this.username = username;
            this.password = password;
        }
    }
}
