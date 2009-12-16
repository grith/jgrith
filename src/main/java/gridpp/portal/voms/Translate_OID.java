package gridpp.portal.voms;

// Gidon Moont
// Imperial College London
// Copyright (C) 2006

import java.util.Hashtable;

/* This class will be able to translate the following OIDs

 - Certificate Distinguised Name parts...

 Country. 
 Attribute name	C
 OID	2.5.4.6

 Location. 
 Attribute name	L
 OID	2.5.4.7

 Common name. 
 Attribute name	CN
 OID	2.5.4.3

 Organization. 
 Attribute name	O
 OID	2.5.4.10

 Organizational Unit. 
 Attribute name	OU
 OID	2.5.6.5

 Email address
 Attribute name	E
 OID 1.2.840.113549.1.9.1
 */

class Translate_OID {

	public static String getOID(String string) {

		Hashtable<String, String> OID = new Hashtable<String, String>(10);

		OID.put("CN", "2.5.4.3");
		OID.put("C", "2.5.4.6");
		OID.put("L", "2.5.4.7");
		OID.put("O", "2.5.4.10");
		OID.put("OU", "2.5.4.11");
		OID.put("E", "1.2.840.113549.1.9.1");

		if (OID.containsKey(string)) {
			return OID.get(string);
		} else {
			return new String("" + string);
		}

	}

	public static String getString(String oid) {

		Hashtable<String, String> OID = new Hashtable<String, String>(10);

		OID.put("2.5.4.3", "CN");
		OID.put("2.5.4.6", "C");
		OID.put("2.5.4.7", "L");
		OID.put("2.5.4.10", "O");
		OID.put("2.5.4.11", "OU");
		OID.put("1.2.840.113549.1.9.1", "E");
		OID.put("1.2.840.113549.1.1.4", "MD5 with RSA encryption");

		if (OID.containsKey(oid)) {
			return OID.get(oid);
		} else {
			return new String("" + oid);
		}

	}

	public Translate_OID() {
	}

}
