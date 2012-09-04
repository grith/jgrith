package grith.jgrith.cred.details;

import java.util.List;

public class StringDetail extends CredDetail<String> {

	private List<String> choices = null;

	protected String value = null;


	private boolean store = true;

	public StringDetail(String name, String msg) {
		this(name, msg, true, null);
	}

	public StringDetail(String name, String msg, boolean store) {
		this(name, msg, store, null);
	}

	public StringDetail(String name, String msg, boolean store, List<String> choices) {
		super(name, msg);
		this.store = store;
		this.choices = choices;
	}

	@Override
	public List<String> getChoices() {
		return choices;
	}

	@Override
	public String getValue() {
		return value;
	}

	public void setChoices(List<String> choices) {
		this.choices = choices;
	}

	@Override
	protected void setValue(String value) {
		this.value = value;
	}


	@Override
	protected boolean storeLastValue() {
		return store;
	}

}
