package grith.jgrith.cred.details;

import grisu.jcommons.configuration.CommonGridProperties.Property;
import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.control.SlcsLoginWrapper;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IdPDetail extends CredDetail<String> {

	static final Logger myLogger = LoggerFactory.getLogger(IdPDetail.class
			.getName());

	{
		final Thread t = new Thread() {
			@Override
			public void run() {
				try {
					myLogger.debug("Preloading idps...");
					SlcsLoginWrapper.getAllIdps();
				} catch (final Throwable e) {
					myLogger.error(e.getLocalizedMessage(), e);
				}
			}
		};
	}

	private String idp = null;

	public IdPDetail() {
		this("Institution", "Please select your institution");
	}

	public IdPDetail(String name, String msg) {
		super(name, msg);
		assignGridProperty(Property.SHIB_IDP);
	}

	@Override
	public List<String> getChoices() {
		try {
			return SlcsLoginWrapper.getAllIdps();
		} catch (Throwable e) {
			throw new CredentialException(
					"Could not load list of Institutions.", e);
		}
	}

	@Override
	public String getValue() {
		return idp;
	}

	@Override
	protected void setValue(String value) {
		this.idp = value;

	}

	@Override
	protected boolean storeLastValue() {
		return true;
	}

}
