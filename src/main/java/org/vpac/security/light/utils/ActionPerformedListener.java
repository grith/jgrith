package org.vpac.security.light.utils;

public interface ActionPerformedListener {

	/**
	 * Is activated when the child object successfully (or not) performed it's intended task.
	 * @param success true - if successfully; false - if not
	 * @param objects to pass to the listener (the listener has to know what to expect)
	 */
	public void success( String actionName, boolean success, Object[] params);
	
}
