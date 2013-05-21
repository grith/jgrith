package grith.jgrith.cred.details;

import grisu.jcommons.configuration.CommonGridProperties;
import grisu.jcommons.configuration.CommonGridProperties.Property;

import java.util.List;



public abstract class CredDetail<T> {

	private String msg;
	private boolean isSet = false;

	private String name;

	private String storeKey = null;
	
	private boolean saveToPropertiesFile = true;

	public boolean isSaveToPropertiesFile() {
		return saveToPropertiesFile;
	}

	public void setSaveToPropertiesFile(boolean saveToPropertiesFile) {
		this.saveToPropertiesFile = saveToPropertiesFile;
	}

	private CommonGridProperties.Property gridProperty = null;

	public CredDetail(String name, String msg) {
		this.name = name;
		this.msg = msg;
		this.storeKey = name.replaceAll("\\s", "_").toUpperCase();
	}

	public void assignGridProperty(Property prop) {
		this.gridProperty = prop;
	}

	public abstract List<String> getChoices();

	public String getDefaultValue() {

		if ( gridProperty != null ) {
			return CommonGridProperties.getDefault().getGridProperty(gridProperty);
		} else {
			return CommonGridProperties.getDefault().getOtherGridProperty(storeKey);
		}

	}

	public String getName() {
		return name;
	}

	public String getUserPrompt() {
		return msg;
	}

	public abstract T getValue();

	public boolean isSet() {
		return isSet;
	}

	public void set(T value) {
		setValue(value);
		if (saveToPropertiesFile && storeLastValue() && (value != null)) {
			if (gridProperty != null) {

				CommonGridProperties.getDefault().setGridProperty(gridProperty,
						value.toString());
			} else {
				CommonGridProperties.getDefault().setOtherGridProperty(storeKey,
						value.toString());
			}
		}
		if (value != null) {
			isSet = true;
		}
	}

	protected abstract void setValue(T value);

	protected abstract boolean storeLastValue();

	@Override
	public String toString() {
		return name;
	}

}
