package grith.jgrith;

import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.Credential.PROPERTY;

import java.util.Map;

public abstract class CredentialRefresher {

	public abstract Map<PROPERTY, Object> getConfig(Credential t);


	public void refresh(Credential c) throws CredentialException {
		Map<PROPERTY, Object> refreshConfig = getConfig(c);
		c.createGssCredential(refreshConfig);
	}

}
