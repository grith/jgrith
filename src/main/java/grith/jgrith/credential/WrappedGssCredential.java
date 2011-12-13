package grith.jgrith.credential;

import grisu.jcommons.constants.Enums.LoginType;
import grisu.jcommons.exceptions.CredentialException;
import grith.jgrith.utils.CredentialHelpers;
import grith.jgrith.voms.VO;
import grith.jgrith.vomsProxy.VomsProxy;

import java.util.Map;

import org.ietf.jgss.GSSCredential;

public class WrappedGssCredential extends Credential {

	private GSSCredential cred;
	private final VO vo;

	public WrappedGssCredential(GSSCredential cred) {
		this.cred = cred;
		this.vo = null;

		addProperty(PROPERTY.LoginType, LoginType.WRAPPED);
	}

	public WrappedGssCredential(GSSCredential cred, VO vo, String fqan) {
		this.vo = vo;

		try {
			VomsProxy vp = new VomsProxy(vo, fqan,
					CredentialHelpers.unwrapGlobusCredential(cred), new Long(
							cred.getRemainingLifetime()) * 1000);

			this.cred = CredentialHelpers.wrapGlobusCredential(vp
					.getVomsProxyCredential());
		} catch (Exception e) {
			throw new CredentialException("Can't create voms credential.", e);
		}

		addProperty(PROPERTY.LoginType, LoginType.WRAPPED);
	}

	@Override
	public void createGssCredential(Map<PROPERTY, Object> config)
			throws CredentialException {

		// nothing to be done here...

	}

	@Override
	public void destroyCredential() {
		// nothing to do here. parent will call dispose
	}

	@Override
	public GSSCredential getGSSCredential() throws CredentialException {
		return cred;
	}

}
