package grith.jgrith.kerberos;

// thrown when library cannot parse output from MyProxy CA
public class MyProxyProtocolException extends Exception {
	private static final long serialVersionUID = 8573410994590112652L;
	
	public MyProxyProtocolException(Exception e){
		super(e);
	}

}
