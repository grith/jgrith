package grith.jgrith.cred;

import grisu.model.info.dto.VO;
import grith.jgrith.cred.AbstractCred.PROPERTY;

import java.util.Map;

import org.ietf.jgss.GSSCredential;

public interface Cred {

	public abstract void destroy();

	public abstract String getDN();

	public abstract String getMyProxyHost();

	public abstract char[] getMyProxyPassword();

	public abstract int getMyProxyPort();

	public abstract String getMyProxyUsername();
	
	public abstract String getProxyPath();

	public abstract int getRemainingLifetime();

	public abstract void init(Map<PROPERTY, Object> config);

	public abstract boolean isRenewable();

	public abstract boolean isValid();

	public abstract boolean refresh();

	public String saveProxy();

	public String saveProxy(String path);

	public abstract void setMinimumLifetime(int lifetimeInSeconds);

	public abstract void setMyProxyHost(String myProxyServer);

	public abstract void setMyProxyPort(int parseInt);

	public abstract void uploadMyProxy();

	public abstract GSSCredential getGSSCredential();

	public abstract String getFqan();

	public abstract Cred getGroupCredential(String fqan);

	public abstract Map<String, VO> getAvailableFqans();
	
	public abstract void setSaveProxyOnCreation(boolean save);
	
	public abstract boolean getSaveProxyOnCreation();

}