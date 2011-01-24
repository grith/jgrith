package grith.jgrith.utils;

public interface ActionPerformedListener {

	/**
	 * Is activated when the child object successfully (or not) performed it's
	 * intended task.
	 * 
	 * @param actionName
	 *            the name of the action
	 * @param success
	 *            true - if successfully; false - if not
	 * @param params
	 *            to pass to the listener (the listener has to know what to
	 *            expect)
	 */
	public void success(String actionName, boolean success, Object[] params);

}
