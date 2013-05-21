package grith.jgrith.cred.details;

import grisu.jcommons.configuration.CommonGridProperties;
import grith.jgrith.certificate.CertificateHelper;

import java.util.List;

import org.apache.commons.lang.StringUtils;

import com.google.common.collect.Lists;

public class LoginTypeDetail extends StringDetail {

	public static List<String> getLoginChoices() {

		String idp = CommonGridProperties.getDefault().getLastShibIdp();


		List<String> choices = Lists.newLinkedList();
		choices.add("Institution login");
		if (StringUtils.isNotBlank(idp)) {
			choices.add("Institution login (using: '" + idp + "')");
		}
		if (CertificateHelper.userCertExists()) {
			choices.add("Certificate login");
		}
		choices.add("MyProxy login");
		return choices;
	}

	public LoginTypeDetail() {
		super("login_type", "Please choose your login type", true, getLoginChoices());
	}

	@Override
	public String getValue() {
		return value;
	}

}
