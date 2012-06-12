package grith.jgrith.credential.refreshers;

import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.credential.Credential;
import grith.jgrith.credential.Credential.PROPERTY;

import java.util.Map;

import com.google.common.collect.Maps;

public class StaticCredentialRefresher extends CredentialRefresher {

	private final Map<PROPERTY, Object> config = Maps.newLinkedHashMap();

	public StaticCredentialRefresher() {
		this(true);
	}

	public StaticCredentialRefresher(boolean enabled) {
		setEnabled(enabled);
	}

	public void addProperty(PROPERTY key, Object value) {
		Class expectedClass = key.getValueClass();
		Class valueClass = value.getClass();

		if (!expectedClass.equals(valueClass)) {
			throw new CredentialException("Value needs to be of class "
					+ expectedClass.getName());
		}

		this.config.put(key, value);
	}

	@Override
	protected Map<PROPERTY, Object> getConfig(Credential t) {
		return config;
	}
}
