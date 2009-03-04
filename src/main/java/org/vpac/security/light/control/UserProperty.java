/* Copyright 2006 VPAC
 * 
 * This file is part of Grix.
 * Grix is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * any later version.

 * Grix is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with Grix; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

package org.vpac.security.light.control;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;
import org.vpac.security.light.certificate.CertificateHelper;

/**
 * This class manages the properties file which is located in the .globus
 * directory. It enables getting and setting of properties. If a property is not
 * set, it returns "no".
 * 
 * @author Markus Binsteiner
 * 
 */
public class UserProperty {
	
	public static final String LAST_MYPROXY_USERNAME_KEY = "MYPROXY_USERNAME_TEXTFIELD";

	
	// let's use the same properties file as grix
	public static final String PROPERTIES_FILE_NAME = "grix.properties";

	static final Logger myLogger = Logger.getLogger(UserProperty.class
			.getName());

	private static final File prop_file = new File(CertificateHelper.getGlobusDir(), PROPERTIES_FILE_NAME);

	private static Properties proxyLightProperties = getProxyLightProperties();

	private static Properties getProxyLightProperties() {

		Properties properties = null;

		properties = new Properties();
		try {
			properties.load(new FileInputStream(prop_file));
		} catch (FileNotFoundException fnfe) {
			myLogger
					.debug("Property file not found. Does not matter, it will be created later on.");
		} catch (IOException ioe) {
			myLogger
					.debug("Could not read property file. Most likely due to permission issues. Hmm.");
		}

		return properties;
	}

	/**
	 * Appends a value to the end of the list of values for that key (separated
	 * by ",", so "," are not allowed
	 * 
	 * @param key
	 *            the key to which the value is added
	 * @param value
	 *            the value to add
	 * @return true if everything went fine, false if the value already exists
	 */
	public static boolean addToList(String key, String value) {

		// TODO test for ","
		StringTokenizer oldvalues = null;
		try {
			oldvalues = new StringTokenizer(proxyLightProperties.getProperty(key),
					",");
		} catch (NullPointerException npe) {
			try {
				setProperty(key, value);
			} catch (Exception e) {
				return false;
			}
			myLogger.debug("Put \"" + value
					+ "\" in front of the list (only element).");
			return true;
		}
		StringBuffer newvalues = new StringBuffer();
		while (oldvalues.hasMoreTokens()) {
			String oldvalue = oldvalues.nextToken();
			if (oldvalue.equals(value))
				return false;
			newvalues.append(oldvalue + ",");
		}
		newvalues.append(value);
		try {
			setProperty(key, newvalues.toString());
		} catch (Exception e) {
			return false;
		}
		return true;
	}

	public static boolean removeFromList(String key, String value) {
		StringTokenizer oldvalues = null;
		try {
			oldvalues = new StringTokenizer(proxyLightProperties.getProperty(key),
					",");
		} catch (NullPointerException npe) {
			myLogger.debug("Cannot remove element from empty list.");
			return false;
		}

		boolean omitted = false;
		boolean frontposition = true;
		StringBuffer newvalues = new StringBuffer();
		while (oldvalues.hasMoreTokens()) {
			String oldvalue = oldvalues.nextToken();
			if (!oldvalue.equals(value)) {
				if (frontposition) {
					newvalues.append(oldvalue);
					frontposition = false;
				} else
					newvalues.append("," + oldvalue);
			} else
				omitted = true;
		}

		if (omitted) {
			try {
				setProperty(key, newvalues.toString());
			} catch (Exception e) {
				// TODO Auto-generated catch block
				return false;
			}
			return true;
		} else
			return false;

	}

	/**
	 * Checks whether an element is in the according list of the key or not
	 * 
	 * @param key
	 *            the key
	 * @param value
	 *            the element
	 * @return true if element is in list, false if not
	 */
	public static boolean isInList(String key, String value) {
		StringTokenizer values = null;
		try {
			values = new StringTokenizer(proxyLightProperties.getProperty(key), ",");
		} catch (NullPointerException npe) {
			myLogger.debug("Cannot check element in empty list.");
			return false;
		}
		while (values.hasMoreTokens()) {
			if (values.nextToken().equals(value))
				return true;
		}

		return false;
	}

	/**
	 * Get the property for the specified key.
	 * 
	 * @param key
	 *            the key
	 * @return the property, if no property is found, it returns null
	 */
	public static String getProperty(String key) {

		String result = proxyLightProperties.getProperty(key);
		// if ( result == null ) result = "no";

		return result;
	}

	/**
	 * Get the properties in a list as String array
	 * 
	 * @param key
	 *            the key
	 * @return the property as a String array or null
	 */
	public static String[] getPropertyList(String key) {

		String result = getProperty(key);

		if (result != null) {
			return result.split(",");
		}

		return null;
	}

	/**
	 * Sets the property for the specified key
	 * 
	 * @param key
	 *            the key
	 * @param value
	 *            the value (use lowercase if possible)
	 * @throws Exception  if the property couldn't be stored
	 */
	public static void setProperty(String key, String value) throws Exception {

		proxyLightProperties.setProperty(key, value);

		if ( ! getPropFile().getParentFile().exists() ) {
			if ( ! getPropFile().getParentFile().mkdirs() ) {
				throw new Exception("Could not create parent directory for properties file.");
			}
		}
		proxyLightProperties.store(new FileOutputStream(prop_file), null);

	}

	/**
	 * Returns the file in which the properties are stored.
	 * 
	 * @return the prop_file
	 */
	public static File getPropFile() {

		return prop_file;
	}

}
