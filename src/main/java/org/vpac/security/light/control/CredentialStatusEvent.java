package org.vpac.security.light.control;

import java.util.EventObject;

import org.globus.gsi.GlobusCredential;
import org.globus.gsi.GlobusCredentialException;

public class CredentialStatusEvent extends EventObject {

	public static final String CREDENTIAL_EXPIRED_STRING = "Credential expired";

	public static final int CREDENTIAL_EXPIRED = 0;
	public static final int CREDENTIAL_TIME_REMAINING_CHANGED = 1;

	private int type = -1;

	public CredentialStatusEvent(GlobusCredential source, int type) {
		super(source);
		this.type = type;
	}

	public String getFormatedTime(long timeLeft) {

		String time = getHoursLeft(timeLeft) + "h, " + getMinutesLeft(timeLeft)
				+ "min, " + getSecondsLeft(timeLeft) + "sec";
		return time;
	}

	public String getFormatedTimeWithoutSeconds(long timeLeft) {
		String time = getHoursLeft(timeLeft) + "h, " + getMinutesLeft(timeLeft)
				+ "m";
		return time;
	}

	public long getHoursLeft(long timeLeft) {

		return timeLeft / (60 * 60);
	}

	public long getMinutesLeft(long timeLeft) {
		return (timeLeft - getHoursLeft(timeLeft) * 60 * 60) / (60);
	}

	public long getSecondsLeft(long timeLeft) {
		return (timeLeft - getHoursLeft(timeLeft) * 60 * 60 - getMinutesLeft(timeLeft) * 60);
	}

	public GlobusCredential getSource() {
		return (GlobusCredential) source;
	}

	public String getStatus() {

		if (this.type == CREDENTIAL_EXPIRED) {
			return CREDENTIAL_EXPIRED_STRING;
		}

		try {
			((GlobusCredential) source).verify();
		} catch (GlobusCredentialException e) {
			return CREDENTIAL_EXPIRED_STRING;
		}

		long timeLeft = ((GlobusCredential) source).getTimeLeft();
		return getFormatedTime(timeLeft);
	}

	public int getType() {
		return type;
	}

	public String toString() {
		return getStatus();
	}

}
