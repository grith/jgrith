package org.vpac.security.light.utils;

public class HelperMethods {

	public static String getFormatedTime(long timeLeft) {

		String time = getHoursLeft(timeLeft) + "h, " + getMinutesLeft(timeLeft)
				+ "min, " + getSecondsLeft(timeLeft) + "sec";
		return time;
	}

	public static String getFormatedTimeWithoutSeconds(long timeLeft) {
		String time = getHoursLeft(timeLeft) + "h, " + getMinutesLeft(timeLeft)
				+ "m";
		return time;
	}

	public static long getHoursLeft(long timeLeft) {

		return timeLeft / (60 * 60);
	}

	public static long getMinutesLeft(long timeLeft) {
		return (timeLeft - getHoursLeft(timeLeft) * 60 * 60) / (60);
	}

	public static long getSecondsLeft(long timeLeft) {
		return (timeLeft - getHoursLeft(timeLeft) * 60 * 60 - getMinutesLeft(timeLeft) * 60);
	}

}
