package grith.jgrith.credential;

import grith.jgrith.Credential;
import grith.jgrith.Credential.PROPERTY;
import grith.jgrith.CredentialRefresher;

import java.util.Map;

import org.python.google.common.collect.Maps;

public class StaticCredentialRefresher extends CredentialRefresher {

	private final Map<PROPERTY, Object> config = Maps.newLinkedHashMap();

	public void addProperty(PROPERTY key, Object value) {
		this.config.put(key, value);
	}

	@Override
	public Map<PROPERTY, Object> getConfig(Credential t) {
		return config;
	}
}
