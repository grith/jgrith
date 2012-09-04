package grith.jgrith.cred.callbacks;

import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.cred.details.CredDetail;

import java.lang.reflect.Type;

public abstract class AbstractCallback {

	public abstract void displayError(String msg);

	final public void fill(CredDetail d) {

		try {
			Type returnType = d.getClass().getDeclaredMethod("getValue")
					.getGenericReturnType();

			if (char[].class.equals(returnType)) {
				char[] input = getPasswordValue(d);
				d.set(input);
			} else if (String.class.equals(returnType)) {
				String input = getStringValue(d);
				d.set(input);
			} else if (Integer.class.equals(returnType)) {
				try {
					Integer input = Integer.parseInt(getStringValue(d));
					d.set(input);
				} catch (NumberFormatException nfe) {
					throw new CredentialException(
							"Can't parse input to integer for " + d.getName());
				}
			} else {
				throw new CredentialException(
						"Callback does not implement input type "
								+ returnType.toString());
			}

		} catch (Exception e) {
			throw new CredentialException("Can't fill details for credential.",
					e);
		}

	}

	public abstract char[] getPasswordValue(CredDetail d);

	public abstract String getStringValue(CredDetail d);

}
