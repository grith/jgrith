package grith.jgrith.cred;

import grith.jgrith.credential.Credential.PROPERTY;

import java.util.Map;

public interface Cred {

	public abstract void destroy();

	public abstract String getDN();

	public abstract String getMyProxyHost();

	public abstract char[] getMyProxyPassword();

	public abstract int getMyProxyPort();

	public abstract String getMyProxyUsername();

	public abstract int getRemainingLifetime();

	public abstract void init(Map<PROPERTY, Object> config);

	public abstract boolean isValid();

	public abstract boolean refresh();

	public abstract void setMinimumLifetime(int lifetimeInSeconds);

	public abstract void setMyProxyHost(String myProxyServer);

	public abstract void setMyProxyPort(int parseInt);

	public abstract void uploadMyProxy();

}