package grith.jgrith.cred.details;

import java.util.List;

public class PasswordDetail extends CredDetail<char[]> {

	private char[] password;

	public PasswordDetail() {
		this("password", "Please enter password");
	}

	public PasswordDetail(String name) {
		this(name, "Please enter password for '" + name + "'");
	}

	public PasswordDetail(String name, String msg) {
		super(name, msg);
	}


	@Override
	public List<String> getChoices() {
		return null;
	}


	@Override
	public char[] getValue() {
		return password;
	}

	@Override
	protected void setValue(char[] value) {
		this.password = value;
	}

	@Override
	protected boolean storeLastValue() {
		// we never want to store this value
		return false;
	}

}
