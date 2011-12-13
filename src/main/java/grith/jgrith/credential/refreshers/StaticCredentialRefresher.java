package grith.jgrith.credential.refreshers;

import grith.jgrith.credential.Credential;
import grith.jgrith.credential.Credential.PROPERTY;

import java.util.Map;

import org.python.google.common.collect.Maps;

public class StaticCredentialRefresher extends CredentialRefresher {

	private final Map<PROPERTY, Object> config = Maps.newLinkedHashMap();

	public StaticCredentialRefresher(boolean enabled) {
		setEnabled(enabled);
	}

	public void addProperty(PROPERTY key, Object value) {
		this.config.put(key, value);
	}

	@Override
	public Map<PROPERTY, Object> getConfig(Credential t) {
		return config;
	}
}
