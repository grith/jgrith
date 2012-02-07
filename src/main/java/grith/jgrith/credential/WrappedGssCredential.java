package grith.jgrith.credential;

import grisu.jcommons.constants.Enums.LoginType;
import grisu.jcommons.exceptions.CredentialException;
import grisu.jcommons.model.info.VO;
import grith.jgrith.utils.CredentialHelpers;
import grith.jgrith.voms.VOManagement.VOManagement;
import grith.jgrith.vomsProxy.VomsProxy;

import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.ietf.jgss.GSSCredential;

public class WrappedGssCredential extends Credential {

	public static GSSCredential createVomsCredential(GSSCredential base, VO vo,
			String fqan) throws CredentialException {
		try {
			VomsProxy vp = new VomsProxy(vo, fqan,
					CredentialHelpers.unwrapGlobusCredential(base), new Long(
							base.getRemainingLifetime()) * 1000);
			// CredentialHelpers.unwrapGlobusCredential(base), 7200 * 1000);
			return CredentialHelpers.wrapGlobusCredential(vp.getVomsProxyCredential());
		} catch (Exception e) {
			throw new CredentialException("Can't create VOMS proxy: "
					+ e.getLocalizedMessage(), e);
		}
	}

	private GSSCredential wrappedCred;

	public WrappedGssCredential(GSSCredential cred) {

		setGssCredential(cred);
		addProperty(PROPERTY.LoginType, LoginType.WRAPPED);
	}

	public WrappedGssCredential(GSSCredential cred, String fqan) {
		this(cred, VOManagement.getAllFqans(cred).get(fqan), fqan);
	}

	public WrappedGssCredential(GSSCredential cred, VO vo, String fqan) {


		setGssCredential(createVomsCredential(cred, vo, fqan));

		addProperty(PROPERTY.LoginType, LoginType.WRAPPED);
		addProperty(PROPERTY.FQAN, fqan);
		addProperty(PROPERTY.VO, vo);
	}

	@Override
	public Map<PROPERTY, Object> autorefreshConfig() {
		return null;
	}

	@Override
	public GSSCredential createGssCredential(Map<PROPERTY, Object> config)
			throws CredentialException {

		return wrappedCred;
	}

	@Override
	public void destroyCredential() {
		// nothing to do here. parent will call dispose
	}


	@Override
	public boolean isAutoRenewable() {
		return false;
	}

	@Override
	protected void setGssCredential(GSSCredential cred) {
		this.wrappedCred = cred;
		try {
			addProperty(PROPERTY.LifetimeInSeconds,
					this.wrappedCred.getRemainingLifetime());
			// 7200);
		} catch (Exception e) {
			throw new CredentialException(e);
		}

		String fqan = getFqan();
		if (StringUtils.isNotBlank(fqan)) {
			VO vo = VOManagement.getAllFqans(this.wrappedCred).get(fqan);
			addProperty(PROPERTY.VO, vo);
			addProperty(PROPERTY.FQAN, fqan);
		}

	}

}
