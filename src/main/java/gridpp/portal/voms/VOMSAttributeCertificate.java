package gridpp.portal.voms;

// Gidon Moont
// Imperial College London
// Copyright (C) 2006

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AttCertIssuer;
import org.bouncycastle.asn1.x509.AttCertValidityPeriod;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.Holder;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.V2Form;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.globus.gsi.OpenSSLKey;
import org.globus.gsi.bc.BouncyCastleOpenSSLKey;

//--------------------------------------------------------------------------------

public class VOMSAttributeCertificate {
	static final Logger myLogger = Logger
			.getLogger(VOMSAttributeCertificate.class.getName());

	AttributeCertificate ac = null;

	// ------------------------------------------------------------------------------
	// first level contains three parts

	AttributeCertificateInfo acinfo = null;
	AlgorithmIdentifier signatureAlgorithm = null;
	DERBitString signatureValue = null;

	// ------------------------------------------------------------------------------
	// second level is the acinfo - this has 9 subparts

	DERInteger version = null;
	Holder holder = null;
	AttCertIssuer issuer = null;
	AlgorithmIdentifier signature = null;
	DERInteger serialNumber = null;
	AttCertValidityPeriod attrCertValidityPeriod = null;
	ASN1Sequence attributes = null;
	DERBitString issuerUniqueID = null;
	X509Extensions extensions = null;

	// ------------------------------------------------------------------------------

	public VOMSAttributeCertificate(AttributeCertificate ac) {

		this.ac = ac;

		// ----------------------------------------------------------------------------
		// first level

		acinfo = ac.getAcinfo();
		signatureAlgorithm = ac.getSignatureAlgorithm();
		signatureValue = ac.getSignatureValue();

		// ----------------------------------------------------------------------------
		// second level therefore is the acinfo - this has 9 subparts

		version = acinfo.getVersion();
		holder = acinfo.getHolder();
		issuer = acinfo.getIssuer();
		signature = acinfo.getSignature();
		serialNumber = acinfo.getSerialNumber();
		attrCertValidityPeriod = acinfo.getAttrCertValidityPeriod();
		attributes = acinfo.getAttributes();
		issuerUniqueID = acinfo.getIssuerUniqueID(); // OPTIONAL
		extensions = acinfo.getExtensions(); // OPTIONAL

	}

	// ------------------------------------------------------------------------------

	public VOMSAttributeCertificate(String holderString,
			int holderSerialNumber, String issuerString, int productionSerial,
			long fromEpoch, long toEpoch, String[] fqans) throws Exception {

		try {

			DEREncodableVector infoVector = new DEREncodableVector();

			this.setVersion();
			this.setHolder(holderString, holderSerialNumber);
			this.setIssuer(issuerString);
			this.setAlgorithmIdentifier();
			this.setSerialNumber(productionSerial);
			this.setTimes(new Date(fromEpoch), new Date(toEpoch));
			this.setVOMSFQANs(fqans);
			this.setExtensions();

			infoVector.add(version);
			infoVector.add(holder);
			infoVector.add(issuer);
			infoVector.add(signature);
			infoVector.add(serialNumber);
			infoVector.add(attrCertValidityPeriod);
			infoVector.add(attributes);
			infoVector.add(extensions);

			ASN1Sequence infoSequence = ASN1Sequence
					.getInstance(new DERSequence(infoVector));

			this.acinfo = new AttributeCertificateInfo(infoSequence);

			// Do it this way to match Vincenzo as much as possible
			// - rather than this way... this.signatureAlgorithm = new
			// AlgorithmIdentifier( "1.2.840.113549.1.1.4" ) ;
			this.signatureAlgorithm = new AlgorithmIdentifier(
					new DERObjectIdentifier("1.2.840.113549.1.1.4"),
					(DEREncodable) null);

			this.signatureValue = new DERBitString(this.sign());

			this.ac = new AttributeCertificate(acinfo, signatureAlgorithm,
					signatureValue);

		} catch (Exception e) {
			throw e;
		}

	}

	// ------------------------------------------------------------------------------

	private String DERSequencetoDN(DERSequence this_sequence) throws Exception {

		String thisDN = "";

		try {

			for (Enumeration n = this_sequence.getObjects(); n
					.hasMoreElements();) {
				DERSet this_set = (DERSet) n.nextElement();
				DERSequence this_seq = (DERSequence) this_set.getObjectAt(0);
				try {
					DERPrintableString this_string = (DERPrintableString) this_seq
							.getObjectAt(1);
					thisDN = thisDN.concat("/"
							+ Translate_OID.getString(""
									+ this_seq.getObjectAt(0)) + "="
							+ this_string.getString());
				} catch (Exception notPS) {
					// email is encoded differently?
					DERIA5String this_string = (DERIA5String) this_seq
							.getObjectAt(1);
					thisDN = thisDN.concat("/"
							+ Translate_OID.getString(""
									+ this_seq.getObjectAt(0)) + "="
							+ this_string.getString());
				}
			}

		} catch (Exception e) {
			throw e;
		}

		return thisDN;

	}

	// ------------------------------------------------------------------------------

	private DERSequence DNtoDERSequence(String thisDN) throws Exception {

		DERSequence this_sequence = null;

		try {

			DEREncodableVector this_overall_vector = new DEREncodableVector();

			String[] parts = thisDN.split("/");

			for (int p = 1; p < parts.length; p++) {

				int equals_position = parts[p].indexOf("=");

				String oid_string = parts[p].substring(0, equals_position);
				String value_string = parts[p].substring(equals_position + 1);
				String oid = Translate_OID.getOID(oid_string);
				if (oid.equals(oid_string)) {
					throw new Exception("unrecognised OID string :: " + oid);
				}

				DEREncodableVector this_vector = new DEREncodableVector();
				DERObjectIdentifier this_oid = new DERObjectIdentifier(oid);

				this_vector.add(this_oid);

				if (oid_string.equals("E")) {
					DERIA5String this_string = new DERIA5String(value_string);
					this_vector.add(this_string);
				} else {
					DERPrintableString this_string = new DERPrintableString(
							value_string);
					this_vector.add(this_string);
				}

				DERSet this_single_object_set = new DERSet(new DERSequence(
						this_vector));

				this_overall_vector.add(this_single_object_set);

			}

			this_sequence = new DERSequence(this_overall_vector);

		} catch (Exception e) {
			throw e;
		}

		return this_sequence;

	}

	public String getAlgorithmIdentifier() {
		return Translate_OID.getString(this.signature.getObjectId().getId());
	}

	// ------------------------------------------------------------------------------

	public AttributeCertificate getAttributeCertificate() {

		return this.ac;

	}

	public String getHolder() throws Exception {

		// ----------------------------------------------------------------------------
		// return the holder's DN as a String

		String holderDN = "";

		try {

			IssuerSerial baseCertificateID = this.holder.getBaseCertificateID();

			if (baseCertificateID != null) {

				GeneralName[] holder_name_array = baseCertificateID.getIssuer()
						.getNames();
				DERSequence holder_name_sequence = (DERSequence) holder_name_array[0]
						.getName();

				holderDN = this.DERSequencetoDN(holder_name_sequence);

			}

		}

		catch (Exception e) {
			throw e;
		}

		return holderDN;

	}

	// ------------------------------------------------------------------------------

	public String getIssuer() throws Exception {

		// ----------------------------------------------------------------------------
		// return the issuer's DN as a String

		String issuerDN = "";

		try {

			V2Form v2form = (V2Form) this.issuer.getIssuer();

			if (v2form != null) {

				GeneralName[] issuer_name_array = v2form.getIssuerName()
						.getNames();
				DERSequence issuer_name_sequence = (DERSequence) issuer_name_array[0]
						.getName();

				issuerDN = this.DERSequencetoDN(issuer_name_sequence);

			}

		}

		catch (Exception e) {
			throw e;
		}

		return issuerDN;

	}

	public DERInteger getSerialNumber() {
		return this.serialNumber;
	}

	// ------------------------------------------------------------------------------

	public int getSerialNumberIntValue() {
		// the getValue() function of DERInteger returns a BigInteger - for
		// which we use intValue to get the int
		return this.serialNumber.getValue().intValue();
	}

	public long getTime() throws Exception {

		try {

			Date from = this.attrCertValidityPeriod.getNotBeforeTime()
					.getDate();
			Date to = this.attrCertValidityPeriod.getNotAfterTime().getDate();
			Date now = new Date();

			// TODO check this now.after( from ) thing. I always get a now which
			// is before the from date... ???
			// if( now.after( from ) )
			// {
			if (now.before(to)) {
				long milliseconds_left = to.getTime() - now.getTime();
				return milliseconds_left;
			} else {
				return -1;
			}
			// } else {
			// return -2 ;
			// }

		} catch (Exception e) {
			throw e;
		}

	}

	// ------------------------------------------------------------------------------

	public BigInteger getVersion() {
		return this.version.getValue();
	}

	public ArrayList<String> getVOMSFQANs() throws Exception {

		ArrayList<String> theseFQANs = new ArrayList<String>();

		try {

			// could have more than one AC in here...
			for (Enumeration a = this.attributes.getObjects(); a
					.hasMoreElements();) {

				ASN1Sequence sequence = (ASN1Sequence) a.nextElement();
				// sequence contains the OID [voms 4] (as a DERObjectIdentifier)
				// at address 0 , and an SET at address 1

				ASN1Set set = (ASN1Set) sequence.getObjectAt(1);
				// set contains only a SEQUENCE at address 0

				ASN1Sequence sequence2 = (ASN1Sequence) set.getObjectAt(0);
				// sequence2 contains a TAGGED OBJECT ad address 0 and another
				// SEQUENCE at address 1

				ASN1TaggedObject taggedObject = (ASN1TaggedObject) sequence2
						.getObjectAt(0);
				// dig down the tagged object... (undocumented?) - TagNumber
				// value is 0

				ASN1TaggedObject taggedObject2 = (ASN1TaggedObject) taggedObject
						.getObject();
				// this tagged object has TagNumber value of 6 (?)
				ASN1OctetString originOctetString = (ASN1OctetString) taggedObject2
						.getObject();
				String origin = (new DERGeneralString(
						originOctetString.getOctets())).getString();

				ASN1Sequence fqanSequence = (ASN1Sequence) sequence2
						.getObjectAt(1);
				// this is the actual sequence of FQANs

				for (int fqan = 0; fqan < fqanSequence.size(); fqan++) {
					ASN1OctetString fqanOctetString = (ASN1OctetString) fqanSequence
							.getObjectAt(fqan);
					String FQAN_Value = (new DERGeneralString(
							fqanOctetString.getOctets())).getString();
					theseFQANs.add(FQAN_Value);
				}

			}

		} catch (Exception e) {
			throw e;
		}

		return theseFQANs;

	}

	// ------------------------------------------------------------------------------

	// should always be "MD5 with RSA encryption"
	public void setAlgorithmIdentifier() {
		// Do it this way to match Vincenzo as much as possible
		// - rather than this way... this.signature = new AlgorithmIdentifier(
		// "1.2.840.113549.1.1.4" ) ;
		this.signature = new AlgorithmIdentifier(new DERObjectIdentifier(
				"1.2.840.113549.1.1.4"), (DEREncodable) null);
	}

	private void setExtensions() throws Exception {

		try {

			Vector<DERObjectIdentifier> myOIDs = new Vector<DERObjectIdentifier>();
			Hashtable<DERObjectIdentifier, X509Extension> myExtensions = new Hashtable<DERObjectIdentifier, X509Extension>();

			// --------------------------------------------------------------------------
			// id-ce-noRevAvail

			ByteArrayOutputStream a = new ByteArrayOutputStream();
			new DEROutputStream(a).writeObject((new DERNull()).toASN1Object());
			ASN1OctetString nraOctetString = ASN1OctetString
					.getInstance(new DEROctetString(a.toByteArray()));

			X509Extension nraExtension = new X509Extension(
					new DERBoolean(false), nraOctetString);
			DERObjectIdentifier nraOID = new DERObjectIdentifier("2.5.29.56");

			myOIDs.add(nraOID);
			myExtensions.put(nraOID, nraExtension);

			// --------------------------------------------------------------------------
			// AuthorityKeyIdentifier
			myLogger.warn("VOMSAttributeCertificate verification not implemented yet.");

			// String issuerDN = this.getIssuer() ;
			//
			// String serverName = "unknown" ;
			// //serverName = VirtualOrganisation.getServer( issuerDN ) ;
			//
			// if( ! serverName.equals( "unknown" ) )
			// {
			// String vomsServerCredentialLocation = new String(
			// System.getProperty( "user.home" ) +
			// "/gridsecurity/certificates/voms-server-certificates/" +
			// serverName ) ;
			//
			// X509Certificate vomsServerCredential = CertUtil.loadCertificate(
			// vomsServerCredentialLocation ) ;
			//
			// PublicKey pk = vomsServerCredential.getPublicKey() ;
			//
			// SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(
			// (ASN1Sequence) new ASN1InputStream( new ByteArrayInputStream(
			// pk.getEncoded() ) ).readObject() ) ;
			// AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier( spki ) ;
			//
			// // not clear why this does not work...
			// // DEROctetString akiOctetString = (DEROctetString)
			// DEROctetString.getInstance( akiSequence.getDERObject() ) ;
			//
			// // These three lines get to the desired result...
			// ByteArrayOutputStream b = new ByteArrayOutputStream() ;
			// new DEROutputStream( b ).writeObject( aki.toASN1Object() ) ;
			// ASN1OctetString akiOctetString = ASN1OctetString.getInstance( new
			// DEROctetString( b.toByteArray() ) ) ;
			//
			// X509Extension akiExtension = new X509Extension( new DERBoolean(
			// false ) , akiOctetString ) ;
			// DERObjectIdentifier akiOID = new DERObjectIdentifier( "2.5.29.35"
			// ) ;
			//
			// myOIDs.add( akiOID ) ;
			// myExtensions.put( akiOID , akiExtension ) ;
			//
			// this.extensions = new X509Extensions( myOIDs , myExtensions ) ;
			//
			// }

		} catch (Exception e) {
			myLogger.error(e);
			// e.printStackTrace() ;
		}

	}

	public void setHolder(String holderDN, int holderSerialNumber)
			throws Exception {

		try {

			DERSequence holder_name_sequence = DNtoDERSequence(holderDN);

			IssuerSerial baseCertificateID = new IssuerSerial(new GeneralNames(
					new GeneralName(4, holder_name_sequence)), new DERInteger(
					holderSerialNumber));

			this.holder = new Holder(baseCertificateID);

		}

		catch (Exception e) {
			throw e;
		}

	}

	// ------------------------------------------------------------------------------

	public void setIssuer(String issuerDN) throws Exception {

		try {

			DERSequence issuer_name_sequence = DNtoDERSequence(issuerDN);

			V2Form v2form = new V2Form(new GeneralNames(new GeneralName(4,
					issuer_name_sequence)));

			this.issuer = new AttCertIssuer(v2form);

		}

		catch (Exception e) {
			throw e;
		}

	}

	public void setSerialNumber(int serial) {
		serialNumber = new DERInteger(serial);
	}

	// ------------------------------------------------------------------------------

	public void setTimes(Date from, Date to) throws Exception {

		try {

			this.attrCertValidityPeriod = new AttCertValidityPeriod(
					new DERGeneralizedTime(from), new DERGeneralizedTime(to));

		} catch (Exception e) {
			throw e;
		}

	}

	// always value of 1 so do not provide an option...
	public void setVersion() {
		this.version = new DERInteger(BigInteger.valueOf(1));
	}

	// ------------------------------------------------------------------------------
	// Extensions

	// DOCUMENTATION REQUIRED!!
	/*
	 * Current (October 2006) VOMS ACs always have id-ce-noRevAvail and
	 * Authority Key Identifier Extensions
	 * 
	 * The id-ce-noRevAvail is set to NULL
	 * 
	 * The AuthorityKeyIdentifier object. id-ce-authorityKeyIdentifier OBJECT
	 * IDENTIFIER ::= { id-ce 35 }
	 * 
	 * AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT
	 * KeyIdentifier OPTIONAL, authorityCertIssuer [1] IMPLICIT GeneralNames
	 * OPTIONAL, authorityCertSerialNumber [2] IMPLICIT CertificateSerialNumber
	 * OPTIONAL }
	 * 
	 * KeyIdentifier ::= OCTET STRING
	 * 
	 * Vincenzo is using a 160-bit SHA-1 hash of the value of the BIT STRING
	 * subjectPublicKey (as described in 4.2.1.2 of RFC 2459)
	 */

	public void setVOMSFQANs(String[] fqans) throws Exception {
		try {

			// --------------------------------------------------------------------------
			// put the FQANs into the SEQUENCE

			DEREncodableVector fqanVector = new DEREncodableVector();

			for (int f = 0; f < fqans.length; f++) {
				DERGeneralString fqan = new DERGeneralString(fqans[f]);
				ASN1OctetString fqanOctetString = ASN1OctetString
						.getInstance(new DEROctetString(fqan.getOctets()));
				fqanVector.add(fqanOctetString);
			}

			ASN1Sequence fqanSequence = ASN1Sequence
					.getInstance(new DERSequence(fqanVector));

			// --------------------------------------------------------------------------
			// put something into the undocumented TaggedObject

			DERGeneralString origin = new DERGeneralString(
					"gridportal://newvoms:15000");

			ASN1OctetString originOctetString = ASN1OctetString
					.getInstance(new DEROctetString(origin.getOctets()));

			/*
			 * ASN1TaggedObject taggedObject2 = ASN1TaggedObject.getInstance(
			 * new DERTaggedObject( 6 , originOctetString ) , true ) ;
			 * 
			 * ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance( new
			 * DERTaggedObject( 0 , taggedObject2 ) , true ) ;
			 * 
			 * DEROctetString originOctetString = new DEROctetString(
			 * origin.getOctets() ) ;
			 */

			DERTaggedObject taggedObject2 = new DERTaggedObject(6,
					originOctetString);

			DERTaggedObject taggedObject = new DERTaggedObject(0, taggedObject2);

			// --------------------------------------------------------------------------
			// put the taggedObject and then the fqanSequence into sequence2

			DEREncodableVector sequence2Vector = new DEREncodableVector();
			sequence2Vector.add(taggedObject);
			sequence2Vector.add(fqanSequence);
			ASN1Sequence sequence2 = ASN1Sequence.getInstance(new DERSequence(
					sequence2Vector));

			// --------------------------------------------------------------------------
			// the SET has one member - sequence2

			ASN1Set set = ASN1Set.getInstance(new DERSet(sequence2));

			// --------------------------------------------------------------------------
			// SEQUENCE sequence has an OID and the set

			DERObjectIdentifier voms4oid = new DERObjectIdentifier(
					"1.3.6.1.4.1.8005.100.100.4");

			DEREncodableVector sequenceVector = new DEREncodableVector();
			sequenceVector.add(voms4oid);
			sequenceVector.add(set);
			ASN1Sequence sequence = ASN1Sequence.getInstance(new DERSequence(
					sequenceVector));

			// --------------------------------------------------------------------------

			this.attributes = ASN1Sequence
					.getInstance(new DERSequence(sequence));

		} catch (Exception e) {
			throw e;
		}

	}

	// ------------------------------------------------------------------------------

	public byte[] sign() throws Exception {

		try {

			ByteArrayOutputStream b = new ByteArrayOutputStream();
			new DEROutputStream(b).writeObject(acinfo);

			Signature sig = Signature.getInstance(signatureAlgorithm
					.getObjectId().getId());

			String hostPrivateKeyLocation = new String(
					System.getProperty("user.home")
							+ "/gridsecurity/hostkey.pem");

			OpenSSLKey key = new BouncyCastleOpenSSLKey(hostPrivateKeyLocation);

			PrivateKey pk = key.getPrivateKey();

			if (pk != null) {
				sig.initSign(pk);
				sig.update(b.toByteArray());
				byte[] sigBytes = sig.sign();
				return sigBytes;
			}

		}

		catch (Exception e) {
			throw e;
		}

		return new byte[0];

	}

	// ------------------------------------------------------------------------------

	public boolean verify() throws Exception {

		boolean checked = false;

		// ----------------------------------------------------------------------------
		// verify signature

		// String issuerDN = this.getIssuer() ;
		//
		// String serverName = "unknown" ;
		// serverName = VO.getServer( issuerDN ) ;
		//
		// if( ! serverName.equals( "unknown" ) )
		// {
		// try
		// {
		//
		// ByteArrayOutputStream b = new ByteArrayOutputStream() ;
		// new DEROutputStream( b ).writeObject( acinfo ) ;
		//
		// Signature sig = Signature.getInstance(
		// signatureAlgorithm.getObjectId().getId() ) ;
		//
		// String vomsServerCredentialLocation = new String( System.getProperty(
		// "user.home" ) +
		// "/gridsecurity/certificates/voms-server-certificates/" + serverName )
		// ;
		//
		// X509Certificate vomsServerCredential = CertUtil.loadCertificate(
		// vomsServerCredentialLocation ) ;
		//
		// PublicKey pk = vomsServerCredential.getPublicKey() ;
		//
		// if( pk != null )
		// {
		// sig.initVerify( pk ) ;
		// sig.update( b.toByteArray() ) ;
		// if( sig.verify( signatureValue.getBytes() ) )
		// {
		// checked = true ;
		// }
		// }
		//
		// }
		// catch( Exception e )
		// {
		// throw e ;
		// }
		//
		// }
		myLogger.warn("VOMESAttributeCertificate verification not implemented yet.");

		return checked;

	}

	// ------------------------------------------------------------------------------

}
