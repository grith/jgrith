package grith.jgrith.utils;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;

public class MobaXtermIniCreator {

	private final String templatePath;
	private final String mobaXtermPath;
	private final String panusername;

	public MobaXtermIniCreator(String templatePath, String mobaXtermPath,
			String panusername) {
		this.templatePath = templatePath;
		this.mobaXtermPath = mobaXtermPath;
		this.panusername = panusername;
		try {
			new File(mobaXtermPath).mkdirs();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void create() {

		String ini = createIni();

		try {
			FileUtils.write(new File(mobaXtermPath + File.separator
					+ "MobaXterm.ini"), ini);

			FileUtils.write(new File(mobaXtermPath + File.separator
					+ "MobaXterm.ini.auto"), ini);
		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}

	}

	private String createIni() {

		try {
			String iniFile = FileUtils.readFileToString(new File(templatePath));

			String replacement = iniFile
					.replaceAll("PAN_USERNAME", panusername);

			String homeDir = System.getProperty("user.home");

			replacement = replacement.replace("HOME_DIR", homeDir);

			return replacement;

		} catch(Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}

	}

}
