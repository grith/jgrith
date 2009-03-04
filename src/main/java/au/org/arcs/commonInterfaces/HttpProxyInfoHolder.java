package au.org.arcs.commonInterfaces;

public interface HttpProxyInfoHolder {
	
	public String getProxyServer();
	public int getProxyPort();
	public String getUsername();
	public char[] getPassword();

}
