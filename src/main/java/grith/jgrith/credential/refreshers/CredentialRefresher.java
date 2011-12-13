package grith.jgrith.credential.refreshers;

import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.credential.Credential;
import grith.jgrith.credential.Credential.PROPERTY;

import java.util.Map;

public abstract class CredentialRefresher {

	public abstract Map<PROPERTY, Object> getConfig(Credential t);


	public void refresh(Credential c) throws CredentialException {
		Map<PROPERTY, Object> refreshConfig = getConfig(c);
		c.createGssCredential(refreshConfig);
	}

}
