package grith.jgrith.cred.callbacks;

import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.cred.details.CredDetail;


public class NoCallback extends AbstractCallback {

	@Override
	public void displayError(String msg) {

		throw new CredentialException(msg);

	}

	@Override
	public char[] getPasswordValue(CredDetail d) {
		throw new CredentialException("No callback set for password detail "
				+ d.getName());
	}

	@Override
	public String getStringValue(CredDetail d) {
		throw new CredentialException("No callback set for detail "
				+ d.getName());
	}

}
