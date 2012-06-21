package grith.jgrith.utils

import grisu.jcommons.view.cli.CliHelpers;

class CliLogin {

	static char[] askPassword(String prompt) {
		def password
		password = CliHelpers.getConsoleReader().readLine(
				prompt+': ','*'.toCharArray()[0])

		return password.toCharArray();
	}

	static String ask(String prompt='Enter your choice', String default_answer=null, List answers=null, String msg='', boolean allowExit=true) {

		if ( msg ) {
			println msg
		}

		if (! answers) {
			def choice
			String promptTmp = prompt+': '
			if ( default_answer ) {
				promptTmp = prompt+' ['+default_answer+']: '
			}
			while (!choice) {
				choice = CliHelpers.getConsoleReader()
						.readLine(promptTmp)
				if (!choice) {
					choice = default_answer
				}
			}
			return choice
		}

		int i=1
		int defaultChoice=-1
		for ( def answer :  answers ) {
			println '['+i+'] '+answer
			if ( answer == default_answer) {
				defaultChoice = i
			}
			i++
		}

		if ( allowExit ) {
			println '[0] Exit'
		}

		int choice = -1;

		while ((choice < 0) || (choice > answers.size())) {

			String promptTmp = prompt+': '
			if ( defaultChoice > 0 ) {
				promptTmp = prompt+' ['+defaultChoice+']: '
			}
			String input = CliHelpers.getConsoleReader()
					.readLine(promptTmp);

			if ( ! input && defaultChoice > 0 ) {
				choice = defaultChoice
			} else {

				try {
					choice = input.toInteger()
				}catch (Exception e) {
				}
			}
		}

		if ( choice == 0 ) {
			return null
		}

		return answers.get(choice-1)
	}


	static void main(args) {

		println ask('what?', 'prompt', ['one', 'two', 'three'])
		println askPassword("Pw?")
		println ask('whatque', 'prompt2')
	}
}
