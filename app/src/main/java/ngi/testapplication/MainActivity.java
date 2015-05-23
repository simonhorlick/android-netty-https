package ngi.testapplication;

import android.app.Activity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.oio.OioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.oio.OioSocketChannel;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.ssl.JdkSslClientContext;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.stream.ChunkedWriteHandler;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;
import io.netty.util.internal.logging.InternalLoggerFactory;
import io.netty.util.internal.logging.Slf4JLoggerFactory;

public class MainActivity extends Activity {

    private static final Logger log = LoggerFactory.getLogger(MainActivity.class);

    private void subscribe() {
        try {
            InternalLoggerFactory.setDefaultFactory(new Slf4JLoggerFactory());

            OioEventLoopGroup customEventLoop = new OioEventLoopGroup();

            String uri = "https://google.com:443";

//            File caCertificate = new File("/data/local/tmp/ca.crt");
//
//            // The certificate here just needs to be signed by the CA.
//            File clientCertificate = new File("/data/local/tmp/client.crt");
//            File clientKey = new File("/data/local/tmp/client.pkcs8.insecure");
//
//            final AndroidSslClientContext ctx = new AndroidSslClientContext(
//                    caCertificate,
//                    clientCertificate, clientKey);

            KeyStore trustStore = KeyStore.getInstance("AndroidCAStore");
            trustStore.load(null);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
            tmf.init(trustStore);

            final SslContext ctx = SslContext.newClientContext(tmf);
            final SSLContext underlyingCtx = ((JdkSslClientContext)ctx).context();

            Bootstrap bootstrap = new Bootstrap()
                    .group(customEventLoop)
                    .channel(OioSocketChannel.class)
                    .option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
                    .option(ChannelOption.TCP_NODELAY, true)
                    .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
                    .handler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        public void initChannel(SocketChannel ch) throws Exception {
                            ChannelPipeline p = ch.pipeline();
                            p.addLast(ctx.newHandler(ch.alloc()));
                            p.addLast("codec", new HttpClientCodec());
                            p.addLast("chunkedWriter", new ChunkedWriteHandler());
                            p.addLast("aggregate", new HttpObjectAggregator(1024 * 100));
                        }
                    });

            URI resource = URI.create(uri);
            final ChannelFuture connectFuture = bootstrap.clone().connect(resource.getHost(), resource.getPort());

            final Channel channel = connectFuture.sync().channel();

            connectFuture.addListener(new GenericFutureListener<ChannelFuture>() {
                @Override
                public void operationComplete(final ChannelFuture f) throws Exception {
                    if (!f.isSuccess()) {
                        log.info("Connection failed");
                        return;
                    }

                    log.info("Connected to " + channel.remoteAddress().toString());

                    SslHandler sslHandler = f.channel().pipeline().get(SslHandler.class);
                    sslHandler.handshakeFuture().addListener(new GenericFutureListener<Future<? super Channel>>() {
                        @Override
                        public void operationComplete(Future<? super Channel> future) throws Exception {
                            if (future.isSuccess()) {
                                log.info("handshake complete - success");
                            } else {
                                log.info("handshake complete - failure", future.cause());
                            }

                            f.channel().pipeline().addLast(new SimpleChannelInboundHandler<FullHttpResponse>() {
                                @Override
                                protected void channelRead0(
                                        ChannelHandlerContext ctx,
                                        FullHttpResponse msg) throws Exception {
                                    log.info("HTTP response: " + msg.toString() + "\n\n" + msg.content().toString(Charset.forName("UTF8")));
                                }
                            });

                            createAndSendHttpRequest("/", channel).addListener(new ChannelFutureListener() {
                                @Override
                                public void operationComplete(ChannelFuture future) throws Exception {
                                    if (!future.isSuccess()) {
                                        log.info("failed", future.cause());
                                        f.channel().close();
                                    } else {
                                        log.info("successfully sent GET request");
                                    }
                                }
                            });
                        }
                    });

                    channel.closeFuture().addListener(new ChannelFutureListener() {
                        @Override
                        public void operationComplete(ChannelFuture future) throws Exception {
                            log.info("Connection closed for request ");
                        }
                    });
                }
            });

            String data = "<none>";
            try {
                log.info("Attempting GET on HttpsURLConnection");

                URL url = new URL(uri);
                HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
                connection.setSSLSocketFactory(underlyingCtx.getSocketFactory());

                InputStream is = connection.getInputStream();
                BufferedReader rd = new BufferedReader(new InputStreamReader(is));
                StringBuilder buf = new StringBuilder();
                String line;
                while ((line = rd.readLine()) != null) {
                    buf.append(line);
                    buf.append('\r');
                }
                rd.close();
                data = buf.toString();
            } catch(Throwable e) {
                log.error("Failed to GET HTTP endpoint " + e.getMessage());
            }

            log.info("Got response \"" + data + "\"");

        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Get HttpRequest belonging to etcdRequest
     *
     * @param uri         to send request to
     * @param channel     to send request on
     * @return HttpRequest
     * @throws Exception when creating or sending HTTP request fails
     */
    private ChannelFuture createAndSendHttpRequest(String uri, Channel channel) throws Exception {
        HttpRequest httpRequest = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, uri);
        httpRequest.headers().add("Connection", "keep-alive");
        httpRequest.headers().add("Host", "localhost");

        ChannelFuture future = channel.write(httpRequest);
        channel.flush();
        return future;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Executor executor = Executors.newSingleThreadExecutor();
        executor.execute(new Runnable(){
            @Override
            public void run() {
                subscribe();
            }
        });

    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
