package grith.jgrith.cred.callbacks;

import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.cred.details.CredDetail;


public class StaticCallback extends AbstractCallback {

	private final String stringValue;
	private final char[] charArrayValue;

	public StaticCallback(char[] charArrayValue) {
		this.stringValue = null;
		this.charArrayValue = charArrayValue;
	}

	public StaticCallback(int intValue) {
		this.stringValue = null;
		this.charArrayValue = null;

	}

	public StaticCallback(String stringValue) {
		this.stringValue = stringValue;
		this.charArrayValue = null;
	}


	@Override
	public void displayError(String msg) {
		System.err.println(msg);
	}

	@Override
	public char[] getPasswordValue(CredDetail d) {
		if (charArrayValue == null) {
			throw new CredentialException("Value for " + d.getName()
					+ " not set");
		}
		return charArrayValue;
	}

	@Override
	public String getStringValue(CredDetail d) {
		if (stringValue == null) {
			throw new CredentialException("Value for " + d.getName()
					+ " not set");
		}

		return stringValue;

	}

}
