package grith.jgrith.cred.details;

import java.util.List;

public class FileDetail extends CredDetail<String> {

	private String path;
	private boolean store = false;

	public FileDetail(String name) {
		this(name, "Please enter path for '" + name + "'");
	}

	public FileDetail(String name, String msg) {
		super(name, msg);
	}


	@Override
	public List<String> getChoices() {
		// not necessary here
		return null;
	}


	@Override
	public String getValue() {
		return path;
	}

	@Override
	protected void setValue(String path) {
		this.path = path;
	}

	@Override
	protected boolean storeLastValue() {
		return store;
	}

}
