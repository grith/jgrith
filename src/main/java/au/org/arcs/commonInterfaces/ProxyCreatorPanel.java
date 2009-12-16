package au.org.arcs.commonInterfaces;

import java.util.Map;

import javax.swing.JPanel;

public interface ProxyCreatorPanel {

	public static final String CURRENT_IDP_KEY = "currentIdp";

	/**
	 * To get current settings like IDP, username.
	 * 
	 * @return the map with the settings
	 */
	public Map<String, String> getCurrentSettings();

	public JPanel getPanel();

	public void setHttpProxyInfoHolder(HttpProxyInfoHolder holder);

	public void setProxyCreatorHolder(ProxyCreatorHolder holder);

}
