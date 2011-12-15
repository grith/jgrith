package grith.jgrith.credential.refreshers;

import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.credential.Credential;
import grith.jgrith.credential.Credential.PROPERTY;

import java.util.Map;

public abstract class CredentialRefresher {

	private boolean enabled = true;

	protected abstract Map<PROPERTY, Object> getConfig(Credential t);

	public boolean refresh(Credential c) throws CredentialException {
		if (enabled) {
			Map<PROPERTY, Object> refreshConfig = getConfig(c);
			return c.recreateGssCredential(refreshConfig);
		} else {
			throw new CredentialException("Refresher not enabled.");
		}
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

}
