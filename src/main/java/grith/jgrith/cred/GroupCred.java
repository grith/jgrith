package grith.jgrith.cred;

import grisu.jcommons.constants.Constants;
import grisu.jcommons.exceptions.CredentialException;
import grisu.model.info.dto.VO;
import grith.jgrith.utils.CredentialHelpers;
import grith.jgrith.vomsProxy.VomsProxy;

import java.util.Map;

import org.ietf.jgss.GSSCredential;

public class GroupCred extends AbstractCred {

	private AbstractCred baseCred;
	private final VO vo;
	private final String group;

	public GroupCred(AbstractCred cred) {
		super();
		this.baseCred = cred;
		this.vo = VO.NON_VO;
		this.group = Constants.NON_VO_FQAN;
	}

	public GroupCred(AbstractCred cred, VO vo, String group) {
		super();
		this.baseCred = cred;
		this.vo = vo;
		this.group = group;

		init();
	}

	@Override
	public GSSCredential createGSSCredentialInstance() {

		try {

			VomsProxy vp = new VomsProxy(vo, group,
					CredentialHelpers.unwrapGlobusCredential(baseCred
							.getGSSCredential()), new Long(
									baseCred.getRemainingLifetime()) * 1000);

			return CredentialHelpers.wrapGlobusCredential(vp
					.getVomsProxyCredential());
		} catch (Exception e) {
			throw new CredentialException("Can't create VOMS credential: "
					+ e.getLocalizedMessage(), e);
		}

	}

	@Override
	protected void initCred(Map<PROPERTY, Object> config) {

		// nothing to do here
		myLogger.debug("No init in GroupCred");
		// baseCred.init(config);

	}
	
	protected String getGroup() {
		return group;
	}

	@Override
	public boolean isRenewable() {
		return false;
	}

	public void setBaseCred(AbstractCred cred) {
		this.baseCred = cred;

		refresh();

	}

}
