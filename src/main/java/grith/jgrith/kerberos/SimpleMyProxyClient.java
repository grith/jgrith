package grith.jgrith.kerberos;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ProtocolException;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.security.sasl.AuthenticationException;
import javax.security.sasl.SaslClient;

import org.apache.commons.lang.ArrayUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.globus.gsi.GlobusCredential;
import org.globus.gsi.gssapi.GlobusGSSCredentialImpl;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SimpleMyProxyClient {
	
	private String hostname;
	private int port;
	private Socket socket;
	
	public final static int SUCCESS = 0;
	public final static int FAILURE = 1;
	public final static int AUTH_REQUIRED = 2; 
	
	public final static String VERSION = "MYPROXYv2";
	
	public final static byte[] START_SASL =  new byte[] { 3, 0, 0, 0, 0, 0 };
	public final static byte[] CONTINUE_SASL = new byte[] { 3, 0, 0, 0 };
	public final static byte[] START_SESSION = new byte[] {0x30};
	
	
	static final Logger myLogger = LoggerFactory
			.getLogger(SimpleMyProxyClient.class.getName());

	
	public static SimpleMyProxyClient create(String hostname, int port){
		SimpleMyProxyClient c = new SimpleMyProxyClient(hostname,port);
		return c;
	}

	private SimpleMyProxyClient(String hostname, int port){
		this.hostname = hostname;
		this.port = port;
	}
	
	public void connect() throws IOException {
		this.socket = MyProxySSLFactoryUtil.getFactory().createSocket(this.hostname, this.port);
		OutputStream out = socket.getOutputStream();
		
		out.write(START_SESSION);
		out.flush();
	}
	
	public void disconnect() {
		try {
			if (this.socket != null) {
				socket.close();
			}
		} catch (IOException io) {
			myLogger.error("myproxy client could not disconnect ",io);
		}
	}
	
	private Socket getSocket() throws IOException {
		if (socket == null ) {
			throw new IOException("myproxy client not connected. use .connect() method ");
		}
		return this.socket;
	}
	
	public int sendGetCommand(String username, long lifetime) throws IOException {
		Map<String,String> request = new HashMap<String,String>();
		request.put("VERSION", VERSION);
		request.put("COMMAND", "0");
		request.put("USERNAME", username);
		request.put("PASSPHRASE", "");
		request.put("LIFETIME", "" + lifetime);
		
		OutputStream out = getSocket().getOutputStream();
		InputStream in = getSocket().getInputStream();
		
		
		out.write(packMyProxy(request));
		Map<String,String> reply = unpackMyProxy(readReply());
		
		return getResponse(reply);

		
	}
	
	public  void doSasl(SaslClient client) throws IOException,
			AuthenticationException, ProtocolException {
		OutputStream out = getSocket().getOutputStream();
		InputStream in = getSocket().getInputStream();

		out.write(START_SASL);
		out.flush();

		byte[] buffer = new byte[2048];
		int length = in.read(buffer);
		Map<String, String> reply = unpackMyProxy(Arrays.copyOfRange(buffer, 0,
				length));

		try {
			int response = Integer.parseInt(reply.get("RESPONSE"));
			if (!reply.get("AUTHORIZATION_DATA").startsWith("SASL")) {
				throw new ProtocolException("SASL not supported");
			}
			System.out.println("got response");
			byte[] challenge = client.hasInitialResponse() ? client
					.evaluateChallenge(new byte[] {}) : null;
			byte[] saslRequest = ArrayUtils.addAll(
					ArrayUtils.add("GSSAPI".getBytes(), (byte) 0), challenge);

			while (true) {

				sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
				sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();

				String inputEncodedString = encoder.encode(saslRequest);
				byte[] inputEncoded = inputEncodedString.replace("\n", "")
						.getBytes();
				byte[] completeSasl = ArrayUtils.addAll(CONTINUE_SASL, inputEncoded);

				out.write(completeSasl);
				out.flush();
				
				reply = unpackMyProxy(readReply());
				response = Integer.parseInt(reply.get("RESPONSE"));

				if (response != AUTH_REQUIRED) {
					break;
				}
				String challengeString = reply.get("AUTHORIZATION_DATA")
						.substring(5);
				byte[] decodedChallenge = decoder.decodeBuffer(challengeString);
				challenge = client.evaluateChallenge(decodedChallenge);
				saslRequest = challenge;

			}

			if (response == SUCCESS) {
				return; // success
			} else {
				throw new AuthenticationException("SASL auth failed");
			}

		} catch (NumberFormatException nx) {
			throw new ProtocolException("Cannot parse myproxy RESPONSE status ");
		} catch (NullPointerException ex) {
			ex.printStackTrace();
			throw new ProtocolException(
					"Cannot parse myproxy output. Are you sure "
							+ getSocket().getInetAddress().getHostName()
							+ " is myproxy server?");
		}

	}
	
	private void sendBytes(byte[] bs) throws IOException {
		getSocket().getOutputStream().write(bs);
	}
	
	private X509Certificate readCertificate() throws IOException, CertificateException {
		InputStream in = getSocket().getInputStream();
		in.skip(1);
		CertificateFactory cf = CertificateFactory.getInstance("X.509",new BouncyCastleProvider());
		X509Certificate cert = (X509Certificate)cf.generateCertificate(in);
		return cert;
	}
	
	
	
	private static byte[] packMyProxy(Map<String,String> request){
		StringBuffer result = new StringBuffer("");
		for (String key: request.keySet()){
			result.append(key + "=" + request.get(key) + "\n");
		}
		result.append('\00');
		
		return result.toString().getBytes();
	}
	
	private static Map<String,String> unpackMyProxy(byte[] response){
		final Map<String,String> result = new HashMap<String,String>();
		final String responseString = new String(response);
		
		for (String line: responseString.split("\n")){
			String[] props = line.split("=");
			if (props.length == 2){
				result.put(props[0], props[1]);
			}
		}
		return result;
	}
	
	private int getResponse(Map<String,String> reply) throws IOException {
		try {
			return Integer.parseInt(reply.get("RESPONSE"));
		} catch (Exception n) {
			throw new IOException("cannot parse output",n);
		}
	}
	
	private byte[] readReply() throws IOException {
		InputStream in = getSocket().getInputStream();
		
		ArrayList<Byte> v = new ArrayList<Byte>();
		byte b = 0;
		do {
			b = (byte) in.read();
			v.add(b);
		} while (b != 0);
		
		return ArrayUtils.toPrimitive(v.toArray(new Byte[] {}));
	}
	
	public GSSCredential getCredential() throws IOException, CertificateException, GSSException {
		KeyPair kp = MyProxySSLFactoryUtil.generateKeyPair();
		byte[] request = MyProxySSLFactoryUtil.generateRequest(kp).getDEREncoded();
		sendBytes(ArrayUtils.add(request, (byte) 0));
		X509Certificate cert = readCertificate();
		
		GlobusCredential cred = new GlobusCredential(
				kp.getPrivate(), new X509Certificate[] { cert });
		GSSCredential gssCred = new GlobusGSSCredentialImpl(cred,
				GSSCredential.INITIATE_AND_ACCEPT);
		
		return gssCred;
	}
}
