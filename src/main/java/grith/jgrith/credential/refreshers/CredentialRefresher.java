package grith.jgrith.credential.refreshers;

import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.credential.Credential;
import grith.jgrith.credential.Credential.PROPERTY;

import java.util.Map;

public abstract class CredentialRefresher {

	private boolean enabled = true;

	public abstract Map<PROPERTY, Object> getConfig(Credential t);

	public void refresh(Credential c) throws CredentialException {
		if (enabled) {
			Map<PROPERTY, Object> refreshConfig = getConfig(c);
			c.createGssCredential(refreshConfig);
		} else {
			throw new CredentialException("Refresher not enabled.");
		}
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

}
