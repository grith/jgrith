package grith.jgrith.cred.callbacks;

import grisu.jcommons.view.cli.CliHelpers;
import grith.jgrith.cred.details.CredDetail;
import grith.jgrith.utils.CliLogin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class CliCallback extends AbstractCallback {

	static final Logger myLogger = LoggerFactory.getLogger(CliHelpers.class
			.getName());




	@Override
	public void displayError(String msg) {
		System.out.println(msg);
	}

	@Override
	public char[] getPasswordValue(CredDetail d) {
		return CliLogin.askPassword(d.getUserPrompt());
	}

	@Override
	public String getStringValue(CredDetail d) {

		String lastOne = d.getDefaultValue();
		String answer = CliLogin
				.ask(d.getUserPrompt(), lastOne, d.getChoices());

		return answer;
	}

}
